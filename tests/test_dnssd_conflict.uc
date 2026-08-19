// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as main from 'main';
import * as c from 'const';

let checks = 0;
const events = [];
const iface = { name: 'lan', index: 1 };
const peer = { address: '192.0.2.100', port: 5353, family: 'inet', local: true };

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

main.init({ hostname: 'router.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true },
	{ local_services: false, discovery: false });
registry.configure({ available: () => true, event: (owner, data) => push(events, { owner, ...data }) });

function register(owner, kind, definition) {
	const result = { error: null };

	registry.registration_set(owner, 'lan', kind, definition, (error, name) => {
		result.error = error;
		result.name = name;
	});

	return result;
}

function answer(record) {
	mdns.callbacks.packet({ header: { flags: { response: true } }, questions: [], answers: [ record ],
		authority: [], additional: [] }, peer, iface, true, false);
}

function address(name, value) {
	return { name, type: 'AAAA', class: 'IN', ttl: 120, flush_cache: true, rdata: { address: value } };
}

function probes_since(name, from) {
	return length(filter(slice(mdns.sent, from), item => !item.packet.header.flags.response &&
		item.packet.questions?.[0]?.name == name));
}

function goodbyes_since(name, from) {
	return filter(slice(mdns.sent, from), item => item.packet.header.flags.response &&
		length(filter(item.packet.answers, record => record.name == name && record.ttl === 0)));
}

function any_type_while_probing() {
	const result = register('one', 'host', { name: 'clash', addresses: [ 'fd00::1' ] });

	uloop.advance(300);
	answer({ name: 'clash.local', type: 'TXT', class: 'IN', ttl: 120, rdata: { strings: [ 'other' ] } });
	check(result.error === registry.ERROR_DUPLICATED, 'while probing, a record of any type at the name is a conflict');
	check(!registry.reserved('clash.local'), 'the failed registration releases its name');
	check(!length(events), 'a failure the callback reports needs no event');
}

function conflict_after_publication() {
	const result = register('one', 'host', { name: 'later', addresses: [ 'fd00::1' ] });

	uloop.advance(1100);
	check(result.error === registry.ERROR_NONE, 'publication before the conflict');
	answer({ name: 'later.local', type: 'TXT', class: 'IN', ttl: 120, rdata: { strings: [ 'other' ] } });
	check(length(registry.records_query('lan', 'later.local', 'AAAA')) == 1,
		'once announced, a record of a type we do not hold is no conflict');
	answer(address('later.local', 'fd00::99'));
	check(registry.reserved('later.local') && !length(registry.records_query('lan', 'later.local', 'AAAA')),
		'a conflict on a published name probes again instead of failing at once');
	uloop.advance(300);
	answer(address('later.local', 'fd00::99'));
	check(!registry.reserved('later.local'), 'a conflict seen while probing again fails the registration');
	check(length(events) == 1 && events[0].owner == 'one' && events[0].name == 'later.local' &&
		events[0].error === registry.ERROR_DUPLICATED, 'the owner gets the conflict as an event');
	splice(events, 0);
}

function cascade() {
	const base = register('two', 'host', { name: 'base', addresses: [ 'fd00::2' ] });

	uloop.advance(1100);

	const svc = register('two', 'service', { instance: 'svc', service_type: '_cascade._tcp', host: 'base', port: 9 });

	uloop.advance(1100);
	check(base.error === registry.ERROR_NONE && svc.error === registry.ERROR_NONE, 'host and service publish');
	answer(address('base.local', 'fd00::98'));
	uloop.advance(300);

	const before = length(mdns.sent);

	answer(address('base.local', 'fd00::98'));
	check(!registry.reserved('svc._cascade._tcp.local'), 'a host lost to a conflict takes its services with it');
	check(length(goodbyes_since('svc._cascade._tcp.local', before)) == 1 &&
		!goodbyes_since('svc._cascade._tcp.local', before)[0].immediate,
		'the withdrawn service sends a queued goodbye');
	check(length(filter(events, event => event.name == 'svc._cascade._tcp.local')) == 1,
		'the owner learns that the service went too');
	splice(events, 0);
}

function lost_tiebreak() {
	const result = register('three', 'host', { name: 'tie', addresses: [ 'fd00::1' ] });

	uloop.advance(300);

	const before = length(mdns.sent);

	mdns.callbacks.packet({ header: { flags: {} }, questions: [ { name: 'tie.local', type: 'ANY', class: 'IN' } ],
		answers: [], authority: [ address('tie.local', 'fd00::ffff') ] }, peer, iface, true, false);
	uloop.advance(950);
	check(!probes_since('tie.local', before), 'the loser of a tiebreak waits a second before it probes again');
	check(result.error == null, 'a lost tiebreak does not fail the registration');
	uloop.advance(2000);
	check(result.error === registry.ERROR_NONE, 'the deferred registration publishes afterwards');
	registry.owner_remove('three');
}

function budget_across_registrations() {
	for (let i = 0; i < c.CONFLICT_RATE_LIMIT; i++) {
		const result = register('four', 'host', { name: 'budget', addresses: [ 'fd00::1' ] });

		uloop.advance(300);
		answer(address('budget.local', 'fd00::97'));
		check(result.error === registry.ERROR_DUPLICATED, 'each conflict fails its registration');
	}

	const before = length(mdns.sent);

	register('four', 'host', { name: 'budget', addresses: [ 'fd00::1' ] });
	uloop.advance(c.CONFLICT_BACKOFF_MS - 100);
	check(!probes_since('budget.local', before), 'the conflict budget holds back a new registration of the name');
	uloop.advance(500);
	check(probes_since('budget.local', before) > 0, 'probing resumes after the backoff');
	registry.owner_remove('four');
}

any_type_while_probing();
conflict_after_publication();
cascade();
lost_tiebreak();
budget_across_registrations();
printf('DNS-SD conflicts: %d checks passed\n', checks);
