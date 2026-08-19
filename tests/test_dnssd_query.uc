// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as service from 'service';
import * as announce from 'announce';
import * as query from 'query';
import * as nsec from 'nsec';
import * as main from 'main';
import * as c from 'const';

let checks = 0;
const iface = { name: 'lan', index: 1 };
const peer = { address: '192.0.2.100', port: 5353, family: 'inet', local: true };
const ANNOUNCEMENTS_MS = 200000;

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

main.init({ hostname: 'router.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true },
	{ local_services: false, discovery: false });
registry.configure({ available: () => true });
uloop.advance(3000);

function register(kind, definition) {
	const result = { error: null };

	registry.registration_set('one', 'lan', kind, definition, (error, name) => {
		result.error = error;
		result.name = name;
	});

	return result;
}

function ask(name, record_type) {
	const before = length(mdns.sent);

	query.handle({ header: { flags: {} }, questions: [ { name, type: record_type, class: 'IN',
		unicast_response: true } ], answers: [], authority: [] }, peer, iface, true, false);
	uloop.advance(1500);

	return filter(slice(mdns.sent, before), item => item.packet.header.flags.response)[-1]?.packet;
}

function types_of(records, name) {
	return sort(map(filter(records ?? [], record => record.name == name), record => record.type));
}

register('host', { name: 'remote', addresses: [ 'fd00::1' ] });
register('key', { name: 'remote', key_hex: '00ff' });
register('service', { instance: 'dev', service_type: '_query._tcp', host: 'remote', port: 1, subtypes: [ '_s' ] });
register('service', { instance: 'own', service_type: '_query._tcp', port: 2 });
uloop.advance(ANNOUNCEMENTS_MS);

function srv_targets() {
	let reply = ask('own._query._tcp.local', 'SRV');

	check(reply && length(filter(reply.additional, record => record.type == 'A' && record.name == 'router.local')) &&
		length(filter(reply.additional, record => record.type == 'AAAA' && record.name == 'router.local')),
		'the SRV target of a service gets both address families in the additional section');
	reply = ask('dev._query._tcp.local', 'SRV');
	check(reply && length(filter(reply.additional, record => record.type == 'AAAA' && record.name == 'remote.local')),
		'the SRV target of a registered host gets its addresses');
}

function lists_owned(record) {
	return record?.type == 'NSEC' && nsec.denies(record, 'A') && nsec.denies(record, 'TXT') &&
		!nsec.denies(record, 'AAAA') && !nsec.denies(record, 'KEY');
}

function denials() {
	let reply = ask('remote.local', 'AAAA');

	check(lists_owned(filter(reply?.additional ?? [], record => record.type == 'NSEC')[0]),
		'an AAAA answer without A records carries an NSEC of the unique types at the name');
	reply = ask('remote.local', 'A');
	check(reply && length(reply.answers) == 1 && lists_owned(reply.answers[0]),
		'an A question at a registered host gets an NSEC');
	check(!ask('_query._tcp.local', 'TXT'), 'a shared service type name is never denied');
}

function enumeration() {
	const local = service.register({ instance: 'Mixed', service: '_query._tcp.local', port: 3 });

	announce.start_probe(local, 'lan', { records: service.build_records, state: service.set_state });
	uloop.advance(ANNOUNCEMENTS_MS);

	const reply = ask(c.SERVICE_ENUM_NAME, 'PTR');

	check(reply && length(filter(reply.answers, record => record.rdata.ptr == '_query._tcp.local')) == 1,
		'a type that local and registered services share is enumerated once');
}

function browse() {
	const reply = ask('_query._tcp.local', 'PTR');
	const answers = map(reply?.answers ?? [], record => record.rdata.ptr);

	check(index(answers, 'dev._query._tcp.local') >= 0 && index(answers, 'own._query._tcp.local') >= 0,
		'a browse answers with the registered instances');
	check(length(filter(reply.additional, record => record.type == 'SRV')) >= 2 &&
		length(filter(reply.additional, record => record.type == 'TXT')) >= 2,
		'a browse carries SRV and TXT records in the additional section');
	check(length(ask('_s._sub._query._tcp.local', 'PTR')?.answers ?? []) == 1, 'a subtype browse is answered');
}

srv_targets();
denials();
enumeration();
browse();
printf('DNS-SD queries: %d checks passed\n', checks);
