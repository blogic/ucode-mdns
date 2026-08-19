/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

import * as ubus from 'ubus';
import * as uloop from 'uloop';
import * as fs from 'fs';
import * as mdns from 'mdns';
import * as cache from 'cache';
import * as tracker from 'tracker';
import * as utils from 'utils';
import * as registry from 'dnssd_registry';
import * as log from 'log';
import * as c from 'const';

const WATCH_TYPES = [ 'PTR', 'SRV', 'TXT', 'AAAA', 'A', 'KEY' ];
const REGISTRATION_KINDS = [ 'host', 'service', 'key' ];
const TRACKER_SCOPE = 'dnssd';
const SESSION_TOKEN_LEN = 32;

const sessions = {};
const owners = {};
const watches = {};
const watch_keys = {};
let connection;
let object;
let next_watch = 0;

function interface_available(name) {
	for (let iface in mdns.interface_list()) {
		if (iface.name == name && iface.enabled)
			return true;
	}

	return false;
}

function event_send(token, event_type, data) {
	const session = sessions[token];

	if (!session || !connection)
		return;

	let call;

	call = connection.defer({
		object: session.owner,
		method: event_type,
		data: { owner: session.owner, ...data },
		cb: () => { session.calls = filter(session.calls, pending => pending !== call); }
	});

	if (call)
		push(session.calls, call);
	else
		log.WARN(`dnssd: Cannot deliver ${event_type} to ${session.owner}: ${ubus.error()}\n`);
}

function snapshot_get(watch) {
	const now = utils.now_ms();
	const records = [];
	const fingerprint = [];
	let next;

	if (!interface_available(watch.interface))
		return { records, fingerprint: '', next };

	for (let record in cache.lookup(watch.name, watch.type, 'IN', watch.interface)) {
		if (record.valid_until > now)
			next = min(next ?? record.valid_until, record.valid_until);

		const bytes = record.is_goodbye ? null : mdns.rdata_encode(record);

		if (bytes == null)
			continue;

		const raw = hexenc(bytes);

		push(records, { name: record.name, type: record.type,
			ttl: max(0, int((record.expires_at - now + 999) / 1000)), rdata_hex: raw });
		push(fingerprint, `${raw}:${record.ttl}`);
	}

	return { records, fingerprint: join('|', sort(fingerprint)), next };
}

let watch_check;

function watch_schedule(id, delay) {
	const watch = watches[id];

	watch.timer?.cancel();
	watch.timer = uloop.timer(delay, () => watch_check(id));
}

watch_check = function(id) {
	const watch = watches[id];

	if (!watch)
		return;

	const snapshot = snapshot_get(watch);

	watch.timer = null;

	if (snapshot.next != null)
		watch_schedule(id, max(0, snapshot.next - utils.now_ms()));

	if (snapshot.fingerprint === watch.fingerprint)
		return;

	watch.fingerprint = snapshot.fingerprint;
	event_send(watch.session, 'records', { watch: watch.id, interface: watch.interface,
		name: watch.name, type: watch.type, records: snapshot.records });
};

function watch_key(iface_name, canonical, record_type) {
	return `${iface_name}\t${canonical}\t${record_type}`;
}

function cache_changed(canonical, record_type, iface_name) {
	for (let id in watch_keys[watch_key(iface_name, canonical, record_type)] ?? {})
		watch_schedule(id, 0);
}

function watch_remove(id) {
	const watch = watches[id];

	if (!watch)
		return;

	watch.timer?.cancel();
	delete watches[id];
	delete watch_keys[watch.key][id];

	if (sessions[watch.session])
		delete sessions[watch.session].watches[id];

	if (length(watch_keys[watch.key]))
		return;

	delete watch_keys[watch.key];
	tracker.stop_continuous(watch.interface, watch.name, watch.type, TRACKER_SCOPE);
}

function session_remove(token) {
	const session = sessions[token];

	if (!session)
		return;

	registry.owner_remove(token);

	for (let id in keys(session.watches))
		watch_remove(id);

	delete sessions[token];
	delete owners[session.owner];
	session.subscriber?.remove();
}

function session_get(req) {
	const session = sessions[req.args.session];

	if (!session || session.user != (req.info?.acl?.user ?? '')) {
		req.error(ubus.STATUS_PERMISSION_DENIED);
		return null;
	}

	return session;
}

function owner_valid(owner) {
	return type(owner) == 'string' && length(owner) > 0 && length(owner) <= c.DNSSD_OWNER_NAME_MAX &&
		!match(owner, /[^a-zA-Z0-9_.-]/);
}

function session_open(req) {
	const owner = req.args.owner;
	const user = req.info?.acl?.user ?? '';

	if (!owner_valid(owner)) {
		req.error(ubus.STATUS_INVALID_ARGUMENT);
		return;
	}

	if (owners[owner]) {
		req.error(ubus.STATUS_PERMISSION_DENIED);
		return;
	}

	if (length(sessions) >= c.DNSSD_SESSIONS_MAX) {
		req.error(ubus.STATUS_NO_MEMORY ?? ubus.STATUS_UNKNOWN_ERROR);
		return;
	}

	const token = replace(trim(fs.readfile('/proc/sys/kernel/random/uuid') ?? ''), '-', '');

	if (length(token) != SESSION_TOKEN_LEN || sessions[token]) {
		req.error(ubus.STATUS_UNKNOWN_ERROR);
		return;
	}

	const subscriber = connection.subscriber(null, () => session_remove(token));

	if (!subscriber || !subscriber.subscribe(owner)) {
		subscriber?.remove();
		req.error(ubus.STATUS_NOT_FOUND);
		return;
	}

	sessions[token] = { owner, user, subscriber, watches: {}, calls: [] };
	owners[owner] = token;

	return { session: token, version: c.DNSSD_API_VERSION };
}

function session_close(req) {
	if (!session_get(req))
		return;

	session_remove(req.args.session);

	return { error: registry.ERROR_NONE };
}

function registration_set(req) {
	if (!session_get(req))
		return;

	req.defer();
	registry.registration_set(req.args.session, req.args.interface, req.args.kind, req.args.definition,
		(error, name) => req.reply({ error, name: name ?? '' }));

	return req;
}

function registration_remove(req) {
	if (!session_get(req))
		return;

	if (index(REGISTRATION_KINDS, req.args.kind) < 0 || type(req.args.name) != 'string') {
		req.error(ubus.STATUS_INVALID_ARGUMENT);
		return;
	}

	return { error: registry.registration_remove(req.args.session, req.args.interface, req.args.name,
		req.args.kind) };
}

function watch_args_valid(args) {
	return interface_available(args.interface) && type(args.name) == 'string' && length(args.name) > 0 &&
		length(args.name) <= c.DNSSD_WATCH_NAME_MAX && index(args.name, '\x00') < 0 &&
		index(WATCH_TYPES, args.type) >= 0 && utils.name_normalise(args.name) != null;
}

function watch_start(req) {
	const session = session_get(req);

	if (!session)
		return;

	if (!watch_args_valid(req.args)) {
		req.error(ubus.STATUS_INVALID_ARGUMENT);
		return;
	}

	if (length(watches) >= c.DNSSD_WATCHES_MAX || length(session.watches) >= c.DNSSD_OWNER_WATCHES_MAX) {
		req.error(ubus.STATUS_NO_MEMORY ?? ubus.STATUS_UNKNOWN_ERROR);
		return;
	}

	const id = ++next_watch;
	const watch = { id, session: req.args.session, interface: req.args.interface,
		name: req.args.name, type: req.args.type };

	watch.key = watch_key(watch.interface, utils.name_normalise(watch.name), watch.type);

	if (!watch_keys[watch.key])
		tracker.start_continuous(watch.interface, { name: watch.name, type: watch.type, class: 'IN' },
			TRACKER_SCOPE);

	watch_keys[watch.key] ??= {};
	watch_keys[watch.key][id] = true;
	session.watches[id] = true;
	watches[id] = watch;

	const snapshot = snapshot_get(watch);

	watch.fingerprint = snapshot.fingerprint;

	if (snapshot.next != null)
		watch_schedule(id, max(0, snapshot.next - utils.now_ms()));

	return { watch: id, records: snapshot.records };
}

function watch_stop(req) {
	const session = session_get(req);

	if (!session)
		return;

	if (!session.watches[req.args.watch]) {
		req.error(ubus.STATUS_NOT_FOUND);
		return;
	}

	watch_remove(req.args.watch);

	return { error: registry.ERROR_NONE };
}

/**
 * init - publish the dynamic DNS-SD provider on an existing ubus connection
 * @conn: connection owned by the mDNS daemon
 *
 * Return: true if the mdns.dnssd object is published
 */
export function init(conn) {
	connection = conn;
	registry.configure({
		available: interface_available,
		event: (token, data) => event_send(token, 'registration', data)
	});
	cache.observer_set(cache_changed);

	object = connection.publish('mdns.dnssd', {
		status: {
			call: () => ({ version: c.DNSSD_API_VERSION, interfaces: mdns.interface_list() }),
			args: {}
		},
		open: { call: session_open, args: { owner: '' } },
		close: { call: session_close, args: { session: '' } },
		register: { call: registration_set, args: { session: '', interface: '', kind: '', definition: {} } },
		unregister: { call: registration_remove, args: { session: '', interface: '', kind: '', name: '' } },
		watch: { call: watch_start, args: { session: '', interface: '', name: '', type: '' } },
		unwatch: { call: watch_stop, args: { session: '', watch: 0 } }
	});

	return object != null;
};

/**
 * shutdown - withdraw the records of every session and stop its watches
 *
 * Return: nothing; the connection stays with its owner
 */
export function shutdown() {
	for (let token in keys(sessions))
		session_remove(token);

	cache.observer_set(null);
	object?.remove();
	object = null;
	connection = null;
};

/**
 * interface_changed - tell every session that an interface changed
 * @name: interface name
 * @ready: true if the interface can carry registrations and watches
 *
 * Return: nothing
 */
export function interface_changed(name, ready) {
	for (let token in sessions)
		event_send(token, 'interface', { interface: name, ready });

	for (let id, watch in watches) {
		if (watch.interface == name)
			watch_schedule(id, 0);
	}
};
