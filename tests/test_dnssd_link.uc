// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as announce from 'announce';
import * as main from 'main';
import * as c from 'const';

let checks = 0;
const events = [];

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

main.init({ hostname: 'router.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true },
	{ local_services: false, discovery: false });
registry.configure({ available: () => true, event: (owner, data) => push(events, { owner, ...data }) });

function register(owner, iface_name, definition) {
	const result = { error: null };

	registry.registration_set(owner, iface_name, 'host', definition, (error, name) => {
		result.error = error;
		result.name = name;
	});

	return result;
}

function probes(name, from) {
	return length(filter(slice(mdns.sent, from), item => !item.packet.header.flags.response &&
		item.packet.questions?.[0]?.name == name));
}

function goodbyes(name, from) {
	return filter(slice(mdns.sent, from), item => item.packet.header.flags.response &&
		length(filter(item.packet.answers, record => record.name == name && record.ttl === 0)));
}

function deadline() {
	mdns.transport.fail.stuck = false;

	const result = register('one', 'stuck', { name: 'stuck', addresses: [ 'fd00::1' ] });

	uloop.advance(c.DNSSD_PUBLISH_TIMEOUT_MS - 100);
	check(result.error == null, 'a registration may wait while the link refuses packets');
	uloop.advance(200);
	check(result.error === registry.ERROR_FAILED, 'a registration that cannot publish in time fails');
	check(!registry.reserved('stuck.local') && !announce.get_state('stuck.local'),
		'the failed registration stops probing');
	delete mdns.transport.fail.stuck;
}

function never_sent() {
	mdns.transport.fail.dead = null;

	const result = register('one', 'dead', { name: 'dead', addresses: [ 'fd00::1' ] });

	uloop.advance(300);
	check(result.error === registry.ERROR_FAILED, 'a probe that can never be sent fails the registration at once');
	check(!announce.get_state('dead.local'), 'the claim ends with the failure');
	delete mdns.transport.fail.dead;
}

function link_up() {
	const result = register('two', 'lan', { name: 'flap', addresses: [ 'fd00::2' ] });

	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE, 'the host publishes');

	const before = length(mdns.sent);

	mdns.callbacks.interface_change({ name: 'lan', index: 1 }, 'up');
	check(registry.reserved('flap.local') && !length(registry.records_query('lan', 'flap.local', 'AAAA')),
		'a link change keeps the registration and probes it again');
	uloop.advance(1100);
	check(probes('flap.local', before) == 3 && length(registry.records_query('lan', 'flap.local', 'AAAA')) == 1,
		'the registration is published again after probing');
	check(!length(events), 'probing again after a link change reports nothing');
}

function link_down() {
	const before = length(mdns.sent);

	mdns.callbacks.interface_change({ name: 'lan', index: 1 }, 'down');
	check(!length(goodbyes('flap.local', before)), 'a link that went down gets no goodbye');
	check(!length(registry.records_query('lan', 'flap.local', 'AAAA')), 'a link that is down is not answered');
	mdns.callbacks.interface_change({ name: 'lan', index: 1 }, 'up');
	uloop.advance(1100);
	check(length(registry.records_query('lan', 'flap.local', 'AAAA')) == 1, 'the link coming up probes again');
}

function interface_removed() {
	const result = register('three', 'lan', { name: 'removed', addresses: [ 'fd00::3' ] });

	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE, 'the host publishes');

	const before = length(mdns.sent);

	main.apply({ hostname: 'router.local', interfaces: [], ipv4: true, ipv6: true });
	check(length(goodbyes('removed.local', before)) == 1, 'an interface that goes away while up sends goodbyes');
	check(!registry.reserved('removed.local') && !registry.reserved('flap.local'),
		'the registrations of a removed interface are withdrawn');
}

deadline();
never_sent();
link_up();
link_down();
interface_removed();
printf('DNS-SD links: %d checks passed\n', checks);
