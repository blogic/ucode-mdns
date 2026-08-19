// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as ubus from 'ubus';
import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as cache from 'cache';
import * as tracker from 'tracker';
import * as registry from 'dnssd_registry';
import * as dnssd_api from 'dnssd_ubus';
import * as c from 'const';

let checks = 0;
const published = { 'owner.a': true, 'owner.b': true };
const removals = {};
const calls = [];
let methods;

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

const connection = {
	publish: (name, table) => {
		methods = table;
		return { remove: () => true };
	},
	subscriber: (notify, remove) => ({
		subscribe: (owner) => {
			if (!published[owner])
				return null;
			removals[owner] = remove;
			return true;
		},
		remove: () => true
	}),
	defer: (request) => {
		push(calls, request);
		return { request };
	}
};

mdns.interfaces[0].enabled = true;
check(dnssd_api.init(connection), 'the provider publishes its object');

function call(method, args) {
	const req = { args, info: { acl: { user: 'root' } } };

	req.error = (code) => { req.status = code; };
	req.defer = () => true;
	req.reply = (data) => { req.deferred_reply = data; };
	req.result = methods[method].call(req);

	return req;
}

function events_to(owner, event_type) {
	return filter(calls, request => request.object == owner && (event_type == null || request.method == event_type));
}

function txt(name, ttl, value) {
	return { name, type: 'TXT', class: 'IN', ttl, flush_cache: true, rdata: { strings: [ value ] } };
}

function sessions() {
	check(call('open', { owner: 'owner.missing' }).status === ubus.STATUS_NOT_FOUND,
		'a session needs a published owner object');
	check(call('open', { owner: 'bad owner' }).status === ubus.STATUS_INVALID_ARGUMENT, 'owner names are checked');

	const first = call('open', { owner: 'owner.a' }).result;

	check(length(first?.session) == 32 && first.version == c.DNSSD_API_VERSION, 'a session opens');
	check(call('open', { owner: 'owner.a' }).status === ubus.STATUS_PERMISSION_DENIED,
		'a second session for the same owner is refused');

	return first.session;
}

function watch_ids(token) {
	const invalid = call('watch', { session: token, interface: 'lan', name: 'x.local', type: 'MX' });

	check(invalid.status === ubus.STATUS_INVALID_ARGUMENT, 'an unsupported watch type is refused');

	const first = call('watch', { session: token, interface: 'lan', name: 'Seen.local', type: 'TXT' }).result;

	check(first.watch == 1 && !length(first.records), 'a refused watch does not use up an id');
	check(tracker.has_interest('lan', 'seen.local', 'TXT'), 'a watch starts a continuous query');

	return first.watch;
}

function watch_events(token, id, other) {
	cache.insert(txt('seen.local', 2, 'one'), 'lan');
	uloop.advance(0);
	check(length(events_to('owner.a', 'records')) == 1 && !length(events_to('owner.b')),
		'a cache change reaches the owner of the watch and nobody else');

	const event = events_to('owner.a', 'records')[0].data;

	check(event.owner == 'owner.a' && event.watch == id && event.records[0].rdata_hex == '036f6e65' &&
		event.records[0].ttl == 2, 'the event carries the records with their remaining TTL');
	uloop.advance(500);
	cache.insert(txt('seen.local', 2, 'one'), 'lan');
	uloop.advance(0);
	check(length(events_to('owner.a', 'records')) == 1, 'a refresh with the same TTL is no change');
	uloop.advance(1000);
	check(length(events_to('owner.a', 'records')) == 1, 'nothing is polled while the records stay');
	uloop.advance(1100);
	check(length(events_to('owner.a', 'records')) == 2 && !length(events_to('owner.a', 'records')[1].data.records),
		'the expiry of a record is reported');
	cache.insert(txt('seen.local', 120, 'two'), 'lan');
	uloop.advance(0);
	cache.insert(txt('seen.local', 0, 'two'), 'lan');
	uloop.advance(0);
	check(length(events_to('owner.a', 'records')) == 4 && !length(events_to('owner.a', 'records')[3].data.records),
		'a goodbye is reported at once');
	cache.insert(txt('seen.local', 120, 'three'), 'other');
	uloop.advance(0);
	check(length(events_to('owner.a', 'records')) == 4, 'a record on another link is no change');
}

function watch_limit(token) {
	let result;

	for (let i = 1; i < c.DNSSD_OWNER_WATCHES_MAX; i++) {
		result = call('watch', { session: token, interface: 'lan', name: `w${i}.local`, type: 'SRV' });
		check(result.result?.watch, 'watches up to the limit are accepted');
	}

	result = call('watch', { session: token, interface: 'lan', name: 'over.local', type: 'SRV' });
	check(result.status != null && !result.result, 'an owner is limited in its watches');
}

function interface_events(token, other) {
	splice(calls, 0);
	dnssd_api.interface_changed('lan', false);
	check(length(events_to('owner.a', 'interface')) == 1 && length(events_to('owner.b', 'interface')) == 1 &&
		length(calls) == 2, 'an interface change goes once to each owner');
	splice(calls, 0);
}

function owner_gone(token) {
	const reply = call('register', { session: token, interface: 'lan', kind: 'host',
		definition: { name: 'leaving', addresses: [ 'fd00::1' ] } });

	uloop.advance(3000);
	check(reply.deferred_reply?.error === registry.ERROR_NONE, 'a registration through ubus completes');
	check(call('register', { session: '0000', interface: 'lan', kind: 'host', definition: {} }).status ===
		ubus.STATUS_PERMISSION_DENIED, 'an unknown session is refused');

	const before = length(mdns.sent);

	removals['owner.a']();
	check(!registry.reserved('leaving.local'), 'the removal of the owner object withdraws its registrations');
	check(length(filter(slice(mdns.sent, before), item => item.packet.header.flags.response &&
		item.packet.answers[0]?.name == 'leaving.local' && item.packet.answers[0].ttl === 0)) == 1,
		'the owner cleanup sends a goodbye');
	check(!tracker.has_interest('lan', 'seen.local', 'TXT'), 'the owner cleanup stops its watches');
	check(call('watch', { session: token, interface: 'lan', name: 'x.local', type: 'TXT' }).status ===
		ubus.STATUS_PERMISSION_DENIED, 'the session is gone');
	check(call('open', { owner: 'owner.a' }).result?.session, 'the owner can open a new session afterwards');
}

const token = sessions();
const other = call('open', { owner: 'owner.b' }).result.session;
const id = watch_ids(token);

watch_events(token, id, other);
watch_limit(token);
interface_events(token, other);
owner_gone(token);
dnssd_api.shutdown();
printf('DNS-SD ubus: %d checks passed\n', checks);
