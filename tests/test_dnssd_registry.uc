// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as announce from 'announce';
import * as packet from 'packet';
import * as response from 'response';
import * as host from 'host';
import * as c from 'const';

let checks = 0;

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

registry.configure({ available: (name) => name != 'offline' });
host.set_hostname('router.local');

function register(owner, iface, kind, definition) {
	const result = { error: null };

	registry.registration_set(owner, iface, kind, definition, (error, name) => {
		result.error = error;
		result.name = name;
	});

	return result;
}

function sent_on(iface, from) {
	return filter(slice(mdns.sent, from), item => item.iface == iface);
}

function probes(items, name) {
	return filter(items, item => !item.packet.header.flags.response &&
		item.packet.questions?.[0]?.name == name);
}

function publication() {
	const before = length(mdns.sent);
	const result = register('first', 'lan-a', 'host', { name: 'remote', addresses: [ 'fd00::1' ] });

	check(result.error == null, 'a registration does not complete before probing');
	check(!length(registry.records_query('lan-a', 'remote.local', 'AAAA')), 'an unprobed host is not answered');
	uloop.advance(300);
	check(packet.qu_pending('lan-a', 'remote.local', 'AAAA'), 'a probe asks for a unicast defence');
	check(!packet.qu_pending('lan-b', 'remote.local', 'AAAA'), 'the QU solicitation is scoped to its link');
	uloop.advance(800);
	check(result.error === registry.ERROR_NONE && result.name == 'remote.local', 'the host completes after probing');
	check(length(probes(sent_on('lan-a', before), 'remote.local')) == 3, 'three probes go out');
	check(probes(sent_on('lan-a', before), 'remote.local')[0].immediate, 'a probe needs a real transmission');
	check(length(registry.records_query('lan-a', 'remote.local', 'AAAA')) == 1, 'the published host is answered');
	check(!length(registry.records_query('lan-b', 'remote.local', 'AAAA')), 'publication is scoped to its link');
	check(response.multicast_wait('lan-a', registry.records_query('lan-a', 'remote.local', 'AAAA')) > 0,
		'announcements count against the multicast rate limit');
}

function ownership() {
	let result = register('other', 'lan-a', 'host', { name: 'remote', addresses: [ 'fd00::2' ] });

	check(result.error === registry.ERROR_DUPLICATED, 'another owner cannot take a host on the same link');
	result = register('other', 'lan-b', 'host', { name: 'Remote', addresses: [ 'fd00::2' ] });
	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE, 'another owner may register the name on another link');
	check(registry.records_query('lan-b', 'remote.local', 'AAAA')[0].rdata.address == 'fd00::2',
		'each link keeps its own records');
	check(registry.registration_remove('other', 'lan-a', 'remote.local', 'host') === registry.ERROR_DUPLICATED,
		'another owner cannot remove a registration');
	result = register('other', 'lan-a', 'service', { instance: 'dev', service_type: '_matter._tcp',
		host: 'remote', port: 5540 });
	check(result.error === registry.ERROR_INVALID_STATE, 'a service needs a host of its own owner');
	result = register('first', 'offline', 'host', { name: 'cut', addresses: [ 'fd00::3' ] });
	check(result.error === registry.ERROR_INVALID_STATE, 'an unavailable interface is refused');
}

function service_records() {
	const result = register('first', 'lan-a', 'service', { instance: 'A.B', service_type: '_matter._tcp',
		host: 'remote', port: 5540, priority: 7, weight: 8, txt_hex: '0569643d00ff', subtypes: [ '_I1', '_i1' ] });

	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE && result.name == 'A\\.B._matter._tcp.local',
		'a service completes with an escaped instance label');

	const srv = registry.records_query('lan-a', result.name, 'SRV')[0];
	const txt = registry.records_query('lan-a', result.name, 'TXT')[0];
	const browse = registry.records_query('lan-a', '_matter._tcp.local', 'PTR')[0];

	check(srv.rdata.priority == 7 && srv.rdata.weight == 8 && srv.rdata.target == 'remote.local', 'SRV fields');
	check(txt.rdata.strings[0] == 'id=\x00\xff', 'binary TXT data is kept');
	check(length(registry.records_query('lan-a', '_I1._sub._matter._tcp.local', 'PTR')) == 1,
		'subtypes are deduplicated without regard to case');
	check(srv.ttl == c.SERVICE_TTL_SEC && txt.ttl == c.RECORD_TTL_SEC && browse.ttl == c.RECORD_TTL_SEC,
		'records with a host name use 120 s, the others 4500 s');
	check(!browse.flush_cache && srv.flush_cache && txt.flush_cache, 'only the PTR records are shared');
	check(index(registry.service_types('lan-a'), '_matter._tcp.local') >= 0, 'the type is enumerated');
}

function ttl_caps() {
	const capped = register('ttl', 'lan-a', 'service', { instance: 'long', service_type: '_cap._udp',
		port: 1, ttl: 99999 });
	const short = register('ttl', 'lan-a', 'host', { name: 'short', addresses: [ 'fd00::5' ], ttl: 30 });

	uloop.advance(1100);
	check(capped.error === registry.ERROR_NONE && short.error === registry.ERROR_NONE, 'TTL registrations');
	check(registry.records_query('lan-a', capped.name, 'SRV')[0].ttl == c.SERVICE_TTL_SEC &&
		registry.records_query('lan-a', capped.name, 'TXT')[0].ttl == c.RECORD_TTL_SEC,
		'a client TTL is capped at the RFC 6762 Section 10 value');
	check(registry.records_query('lan-a', 'short.local', 'AAAA')[0].ttl == 30, 'a shorter client TTL is kept');
	registry.owner_remove('ttl');
}

function validation() {
	const bad = [
		[ 'host', { name: 'remote', addresses: [ '192.0.2.1' ] } ],
		[ 'host', { name: 'remote', addresses: [ 'fd00::1\x00tail' ] } ],
		[ 'host', { name: '', addresses: [] } ],
		[ 'host', { name: 'xn--mnchen-3ya', addresses: [] } ],
		[ 'service', { instance: 'x', service_type: '_matter._bad', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_a--b._tcp', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_-ab._tcp', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_123._tcp', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_abcdefghijklmnop._tcp', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_matter._tcp.local', port: 1 } ],
		[ 'service', { instance: 'x', service_type: '_matter._tcp', port: 0 } ],
		[ 'service', { instance: 'x', service_type: '_matter._tcp', port: 65536 } ],
		[ 'service', { instance: 'x', service_type: '_matter._tcp', port: 1, txt_hex: '05abcd' } ],
		[ 'service', { instance: 'x', service_type: '_matter._tcp', port: 1, txt_hex: 'zz' } ],
		[ 'key', { name: 'remote', key_hex: '0' } ],
		[ 'key', { name: 'remote', key_hex: '00ff', class: 3 } ],
		[ 'other', { name: 'remote' } ]
	];
	let big = '';

	for (let i = 0; i < 6; i++)
		big += 'ff' + substr(sprintf('%0510d', 0), 0, 510);
	push(bad, [ 'service', { instance: 'x', service_type: '_matter._tcp', port: 1, txt_hex: big } ]);

	for (let item in bad)
		check(register('first', 'lan-a', item[0], item[1]).error === registry.ERROR_INVALID_ARGS,
			`invalid ${item[0]} registration ${sprintf('%J', item[1])} is refused`);
}

function limits() {
	let result;

	for (let i = 0; i < c.DNSSD_OWNER_REGISTRATIONS_MAX; i++) {
		result = register('greedy', 'lan-c', 'host', { name: `empty${i}`, addresses: [] });
		check(result.error === registry.ERROR_NONE, 'a host without addresses completes at once');
	}

	result = register('greedy', 'lan-c', 'host', { name: 'one-more', addresses: [] });
	check(result.error === registry.ERROR_NO_BUFS, 'an owner is limited in its registrations');
	result = register('modest', 'lan-c', 'host', { name: 'one-more', addresses: [] });
	check(result.error === registry.ERROR_NONE, 'the limit of one owner does not hold back another');
	registry.owner_remove('greedy');
	registry.owner_remove('modest');
	check(!registry.reserved('empty0.local'), 'owner removal releases the names');
}

function qm_probe() {
	mdns.state.first_binder = false;

	const before = length(mdns.sent);

	register('qm', 'lan-a', 'host', { name: 'second', addresses: [ 'fd00::7' ] });
	uloop.advance(300);
	check(!probes(sent_on('lan-a', before), 'second.local')[0].packet.questions[0].unicast_response,
		'a responder that is not the first binder probes with QM questions');
	check(!packet.qu_pending('lan-a', 'second.local', 'AAAA'), 'a QM probe solicits no unicast reply');
	registry.owner_remove('qm');
	mdns.state.first_binder = true;
}

publication();
ownership();
service_records();
ttl_caps();
validation();
limits();
qm_probe();
printf('DNS-SD registry: %d checks passed\n', checks);
