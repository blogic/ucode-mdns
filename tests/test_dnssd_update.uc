// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as announce from 'announce';
import * as main from 'main';
import * as c from 'const';

let checks = 0;

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

main.init({ hostname: 'router.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true },
	{ local_services: false, discovery: false });
registry.configure({ available: () => true });

function register(owner, kind, definition) {
	const result = { error: null };

	registry.registration_set(owner, 'lan', kind, definition, (error, name) => {
		result.error = error;
		result.name = name;
	});

	return result;
}

function asks(item, name) {
	return !item.packet.header.flags.response && item.packet.questions?.[0]?.name == name;
}

function named(name, from) {
	return filter(slice(mdns.sent, from), item => asks(item, name) ||
		length(filter(item.packet.answers ?? [], record => record.name == name)));
}

function probes(name, from) {
	return length(filter(slice(mdns.sent, from), item => asks(item, name)));
}

function goodbyes(name, from) {
	return filter(slice(mdns.sent, from), item => item.packet.header.flags.response &&
		length(filter(item.packet.answers, record => record.name == name && record.ttl === 0)));
}

function empty_host() {
	const before = length(mdns.sent);
	let result = register('one', 'host', { name: 'empty', addresses: [] });

	check(result.error === registry.ERROR_NONE, 'a host without addresses completes at once');
	uloop.advance(2000);
	check(!length(named('empty.local', before)), 'a host without records is neither probed nor announced');
	check(registry.reserved('empty.local'), 'a host without records still reserves its name');

	result = register('one', 'host', { name: 'empty', addresses: [ 'fd00::1' ] });
	check(result.error == null && !length(registry.records_query('lan', 'empty.local', 'AAAA')),
		'adding addresses to an empty host waits for probing');
	uloop.advance(1100);
	check(probes('empty.local', before) == 3 && result.error === registry.ERROR_NONE,
		'the first addresses of a host are probed before they are published');

	const keyless = length(mdns.sent);

	register('one', 'host', { name: 'bare', addresses: [] });
	result = register('one', 'key', { name: 'bare', key_hex: '0100030f00ff' });
	check(result.error == null, 'a KEY added to an empty host waits for probing');
	uloop.advance(1100);
	check(probes('bare.local', keyless) == 3 && result.error === registry.ERROR_NONE,
		'a KEY added to an empty host is probed');
	check(registry.records_query('lan', 'bare.local', 'KEY')[0].ttl == c.SERVICE_TTL_SEC,
		'a KEY at a host name uses the host name TTL');
}

function published_update() {
	register('one', 'host', { name: 'moving', addresses: [ 'fd00::1' ] });
	uloop.advance(3000);

	const before = length(mdns.sent);
	const result = register('one', 'host', { name: 'moving', addresses: [ 'fd00::2' ] });

	check(result.error === registry.ERROR_NONE, 'an update of a published host completes at once');
	uloop.advance(1100);
	check(!probes('moving.local', before), 'an update of a published name is not probed again');
	check(!length(goodbyes('moving.local', before)), 'replaced unique records rely on the cache-flush bit');

	const announced = filter(named('moving.local', before), item => item.packet.header.flags.response);

	check(length(announced) && announced[0].packet.answers[0].rdata.address == 'fd00::2' &&
		announced[0].packet.answers[0].flush_cache, 'the new address is announced with the cache-flush bit');
}

function shared_goodbye() {
	const result = register('one', 'service', { instance: 'subs', service_type: '_subs._tcp', port: 7,
		subtypes: [ '_a', '_b' ] });

	uloop.advance(3000);
	check(result.error === registry.ERROR_NONE, 'service with subtypes publishes');

	const before = length(mdns.sent);

	register('one', 'service', { instance: 'subs', service_type: '_subs._tcp', port: 7, subtypes: [ '_a' ] });

	const farewell = goodbyes('_b._sub._subs._tcp.local', before);

	check(length(farewell) == 1 && !farewell[0].immediate && !farewell[0].packet.answers[0].flush_cache,
		'a removed shared record gets a queued goodbye');
	check(!length(goodbyes('_a._sub._subs._tcp.local', before)), 'the kept subtype gets no goodbye');
}

function update_limit() {
	register('two', 'host', { name: 'busy', addresses: [ 'fd00::1' ] });
	uloop.advance(3000);

	for (let i = 2; i < 2 + c.UPDATE_RATE_LIMIT + 2; i++)
		check(register('two', 'host', { name: 'busy', addresses: [ `fd00::${i}` ] }).error === registry.ERROR_NONE,
			'updates of a published host are accepted');

	const link = announce.get_state('busy.local').links.lan;

	check(length(link.updates) == c.UPDATE_RATE_LIMIT && link.update_timer,
		'more than ten updates a minute wait for the limit');
	check(registry.registration_remove('two', 'lan', 'busy.local', 'host') === registry.ERROR_NONE,
		'the busy host can be removed');
	check(register('two', 'host', { name: 'busy', addresses: [ 'fd00::99' ] }).error === registry.ERROR_NO_BUFS,
		'removal and a new registration do not reset the update limit');
	uloop.advance(c.UPDATE_WINDOW_MS);

	const result = register('two', 'host', { name: 'busy', addresses: [ 'fd00::99' ] });

	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE, 'the name can be registered again once the minute passed');
	registry.owner_remove('two');
}

function primary_follow() {
	const result = register('three', 'service', { instance: 'local', service_type: '_follow._tcp', port: 8 });

	uloop.advance(3000);
	check(registry.records_query('lan', result.name, 'SRV')[0].rdata.target == 'router.local',
		'a service without a host targets the local host name');
	main.apply({ hostname: 'renamed.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true });
	uloop.advance(300);
	check(registry.records_get(result.name, null, 'lan')[1].rdata.target == 'renamed.local',
		'the service follows a new local host name');
	registry.owner_remove('three');
}

function last_part() {
	const result = register('four', 'service', { instance: 'gone', service_type: '_gone._tcp', port: 9 });

	uloop.advance(3000);
	check(result.error === registry.ERROR_NONE, 'the service publishes');

	const before = length(mdns.sent);

	check(registry.registration_remove('four', 'lan', result.name, 'service') === registry.ERROR_NONE,
		'the service is removed');

	const farewell = goodbyes(result.name, before);

	check(length(farewell) == 1 && length(farewell[0].packet.answers) == 3 && !farewell[0].immediate,
		'the last part sends a queued goodbye for every record');
	check(!registry.reserved(result.name), 'the name is released');
}

function owner_cleanup() {
	register('five', 'host', { name: 'leaving', addresses: [ 'fd00::5' ] });
	uloop.advance(3000);

	const before = length(mdns.sent);

	mdns.transport_fail('lan', 1, false);
	registry.owner_remove('five');
	check(!length(goodbyes('leaving.local', before)), 'a goodbye the link refuses is not lost');
	uloop.advance(100);
	check(length(goodbyes('leaving.local', before)) == 1, 'a refused goodbye goes out on a retry');
}

empty_host();
published_update();
shared_goodbye();
update_limit();
primary_follow();
last_part();
owner_cleanup();
printf('DNS-SD updates: %d checks passed\n', checks);
