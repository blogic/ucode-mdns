/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * publish.uc - Records published at run time by other daemons
 *
 * A client publishes services, hosts with their own addresses, and KEY
 * records through ubus. Each entry belongs
 * to the owner string the client passed, so the client can withdraw all of
 * its entries in one call when it starts or stops.
 *
 * A publish request is answered once probing for the name is done. A lost
 * conflict is reported back to the owner rather than renamed, because the
 * owner decides on the replacement name.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as service from 'service';
import * as host from 'host';
import * as key from 'key';
import * as announce from 'announce';
import * as response from 'response';
import * as subscribe from 'subscribe';
import * as utils from 'utils';
import * as uloop from 'uloop';
import * as mdns from 'mdns';
import * as log from 'log';
import * as c from 'const';

/* Claimed name -> owner, for the services and hosts published here */
const owners = {
	service: {},
	host: {}
};

/* Claimed name -> requests waiting for the probe of that name */
const pending = {};

/* Sends a notification to the ubus subscribers, set by mdns_ubus.uc */
let notifier;

/**
 * Set the function that delivers notifications
 * @param {function} fn - Called with (type, data)
 */
export function set_notifier(fn) {
	notifier = fn;
};

function notify(type, data) {
	if (notifier)
		notifier(type, data);
}

/**
 * Answer every request waiting for a name
 * @param {string} name - Claimed name
 * @param {string} result - Result reported to the caller
 */
function pending_resolve(name, result) {
	const waiting = pending[name];

	if (!waiting)
		return;

	delete pending[name];

	for (let entry in waiting) {
		entry.timer.cancel();
		entry.reply(result);
	}
}

/**
 * Hold a request until probing for a name is done
 *
 * A name that cannot be probed yet, for example on an interface without an
 * address, is answered as published once the timeout runs out; the probe
 * goes on and a later conflict is reported as a notification.
 *
 * @param {string} name - Claimed name
 * @param {function} reply - Called once with the result
 */
function pending_add(name, reply) {
	const entry = { reply: reply };

	entry.timer = uloop.timer(c.PUBLISH_REPLY_TIMEOUT_MS, function() {
		const idx = index(pending[name] ?? [], entry);

		if (idx < 0)
			return;

		splice(pending[name], idx, 1);
		if (!length(pending[name]))
			delete pending[name];

		reply('ok');
	});

	pending[name] ??= [];
	push(pending[name], entry);
}

/**
 * Start claiming a new name on every interface
 * @param {string} name - Claimed name
 * @param {object} ops - Entry operations
 * @param {function} reply - Called once with the result
 * @returns {string|null} Result, or null when the reply comes later
 */
function claim(name, ops, reply) {
	const ifaces = mdns.interface_list();

	for (let iface in ifaces)
		announce.start_probe(name, iface.name, ops);

	if (!length(ifaces))
		return 'ok';

	pending_add(name, reply);

	return null;
}

/**
 * Answer a request for a name that is already claimed
 *
 * The records changed, so an announced name announces them again. A name that
 * is still probing answers once probing is done.
 *
 * @param {string} name - Claimed name
 * @param {object} ops - Entry operations
 * @param {function} reply - Called once with the result
 * @returns {string|null} Result, or null when the reply comes later
 */
function settle(name, ops, reply) {
	const state = announce.get_state(name);

	if (!state)
		return claim(name, ops, reply);

	if (state.state === 'probing') {
		pending_add(name, reply);
		return null;
	}

	for (let iface_name in state.ifaces)
		announce.refresh(name, iface_name);

	return 'ok';
}

/**
 * RFC 6762 Section 10.1: send goodbyes for records that went away
 * @param {string} name - Claimed name the records belong to
 * @param {array} records - Records that are no longer published
 */
function goodbye_records(name, records) {
	const state = announce.get_state(name);

	if (!length(records) || !announce.owned(name))
		return;

	const goodbyes = map(records, (record) => ({ ...record, ttl: 0, flush_cache: false }));

	for (let iface_name in state.ifaces)
		announce.goodbye(name, iface_name, () => goodbyes);
}

/**
 * Stop claiming a name
 *
 * RFC 6762 Section 10.1: an announced name gets a goodbye first.
 *
 * @param {string} name - Claimed name
 * @param {function} records_fn - Record source of the name
 */
function withdraw(name, records_fn) {
	const state = announce.get_state(name);

	if (announce.owned(name)) {
		for (let iface_name in state.ifaces)
			announce.goodbye(name, iface_name, records_fn);
	}

	announce.cancel(name);
	pending_resolve(name, 'aborted');
}

function service_state(name, state) {
	service.set_state(name, state);

	if (state !== 'announcing')
		return;

	pending_resolve(name, 'ok');
	subscribe.schedule();
}

/**
 * RFC 6762 Section 9: another host owns the name of a published service
 *
 * announce.uc stopped claiming the name before calling this.
 *
 * @param {string} name - Instance name that lost
 */
function service_conflict(name) {
	const owner = owners.service[name];

	service.unregister(name);
	delete owners.service[name];

	log.NOTE(`publish: ${name} of ${owner} is taken by another host\n`);

	pending_resolve(name, 'duplicated');
	notify('conflict', { owner: owner, kind: 'service', name: name });
}

const service_ops = {
	records: service.build_records,
	conflict: service_conflict,
	state: service_state
};

function host_state(name, state) {
	if (state === 'announcing')
		pending_resolve(name, 'ok');
}

/**
 * RFC 6762 Section 9: another host owns a host name published here
 * @param {string} name - Host name that lost
 */
function host_conflict(name) {
	const owner = owners.host[name];

	host.foreign_del(name);
	delete owners.host[name];

	log.NOTE(`publish: ${name} of ${owner} is taken by another host\n`);

	pending_resolve(name, 'duplicated');
	notify('conflict', { owner: owner, kind: 'host', name: name });
}

const host_ops = {
	records: host.build_records,
	conflict: host_conflict,
	state: host_state
};

function owner_valid(owner) {
	return type(owner) === 'string' && length(owner) > 0;
}

/**
 * A single DNS label: no dot, at most 63 bytes
 * @param {*} label - Value to test
 * @returns {boolean} True if usable as one label
 */
function label_valid(label) {
	return type(label) === 'string' && length(label) > 0 && length(label) <= 63 &&
	       index(label, '.') < 0;
}

/**
 * Append .local to a name given with or without it
 * @param {string} name - Name like "node" or "node.local"
 * @returns {string} Name like "node.local"
 */
function local_name(name) {
	const bare = rtrim(name, '.');

	if (match(bare, /\.local$/i))
		return bare;

	return `${bare}.local`;
}

/**
 * Parse a service type given as "_srv._udp" or "_srv._udp.local"
 * @param {*} value - Service type
 * @returns {string|null} Type like "_srv._udp.local", or null if malformed
 */
function service_type_parse(value) {
	if (type(value) !== 'string')
		return null;

	const service_type = local_name(value);
	const parsed = utils.parse_service_type(service_type);

	if (!parsed || lc(parsed.domain) !== 'local')
		return null;

	return service_type;
}

/**
 * RFC 6763 Section 6: split encoded TXT data into its strings
 * @param {string} hex - TXT RDATA as a hex string
 * @returns {array|null} TXT strings, or null if malformed
 */
function txt_decode(hex) {
	if (!match(hex, /^([0-9a-fA-F][0-9a-fA-F])*$/))
		return null;

	const raw = hexdec(hex);
	const strings = [];
	let pos = 0;

	while (pos < length(raw)) {
		const len = ord(raw, pos);

		if (pos + 1 + len > length(raw))
			return null;

		push(strings, substr(raw, pos + 1, len));
		pos += 1 + len;
	}

	return strings;
}

/**
 * The TXT strings of a publish request
 * @param {object} args - Request with txt_hex or txt
 * @returns {array|null} TXT strings, or null if malformed
 */
function txt_parse(args) {
	if (args.txt_hex != null)
		return type(args.txt_hex) === 'string' ? txt_decode(args.txt_hex) : null;

	const strings = args.txt ?? [];

	if (type(strings) !== 'array')
		return null;

	for (let str in strings) {
		if (type(str) !== 'string' || length(str) > 255)
			return null;
	}

	return strings;
}

/**
 * RFC 6763 Section 4.1.1: the default instance label is the host label
 * @returns {string} Label of our primary host name
 */
function host_label() {
	return replace(host.hostname() ?? '', /\.local$/, '');
}

/**
 * Validate and normalise a service publish request
 * @param {object} args - ubus arguments
 * @returns {object|null} Request, or null if malformed
 */
function service_request(args) {
	const service_type = service_type_parse(args.service);
	const txt_strings = txt_parse(args);
	const subtypes = args.subtypes ?? [];
	const instance = args.instance || host_label();

	if (!owner_valid(args.owner) || !service_type || txt_strings == null)
		return null;

	if (!label_valid(instance) || (args.host && !label_valid(args.host)))
		return null;

	if (type(subtypes) !== 'array')
		return null;

	for (let subtype in subtypes) {
		if (type(subtype) !== 'string' || !match(subtype, /^_[^.]+$/))
			return null;
	}

	return {
		owner: args.owner,
		instance: instance,
		service: service_type,
		port: args.port,
		txt_strings: txt_strings,
		subtypes: subtypes,
		hostname: args.host ? local_name(args.host) : null
	};
}

/**
 * Change a service this owner already published
 * @param {string} name - Instance name
 * @param {object} req - Normalised request
 * @param {function} reply - Called once with the result
 * @returns {string|null} Result, or null when the reply comes later
 */
function service_change(name, req, reply) {
	const before = service.build_records(name);

	if (!service.update(name, req))
		return 'invalid';

	goodbye_records(name, response.records_missing(before, service.build_records(name)));
	subscribe.schedule();

	return settle(name, service_ops, reply);
}

/**
 * Publish or update a service
 * @param {object} args - ubus arguments
 * @param {function} reply - Called once with the result when it comes later
 * @returns {string|null} Result, or null when the reply comes later
 */
export function service_add(args, reply) {
	const req = service_request(args);

	if (!req)
		return 'invalid';

	const name = utils.build_instance_name(req.instance, req.service);

	if (service.get(name) && owners.service[name] !== req.owner)
		return 'duplicated';

	if (service.get(name))
		return service_change(name, req, reply);

	const registered = service.register({ ...req, ops: service_ops });

	if (!registered)
		return 'invalid';

	owners.service[registered] = req.owner;
	mdns.info(`publish: ${req.owner} publishes ${registered}\n`);

	return claim(registered, service_ops, reply);
};

/**
 * Withdraw a published service
 * @param {object} args - ubus arguments with owner, instance, service
 * @returns {string} Result
 */
export function service_del(args) {
	const service_type = service_type_parse(args.service);
	const instance = args.instance || host_label();

	if (!owner_valid(args.owner) || !service_type || !label_valid(instance))
		return 'invalid';

	const name = utils.build_instance_name(instance, service_type);

	if (owners.service[name] !== args.owner)
		return 'not_found';

	withdraw(name, service.build_records);
	service.unregister(name);
	delete owners.service[name];
	subscribe.schedule();

	return 'ok';
};

/**
 * Validate a list of addresses
 * @param {*} addresses - Value to test
 * @returns {boolean} True if a non-empty list of IPv4 and IPv6 addresses
 */
function addresses_valid(addresses) {
	if (type(addresses) !== 'array' || !length(addresses))
		return false;

	for (let address in addresses) {
		if (type(address) !== 'string' || !iptoarr(address))
			return false;
	}

	return true;
}

/**
 * Publish or update a host with its own addresses
 * @param {object} args - ubus arguments with owner, host, addresses
 * @param {function} reply - Called once with the result when it comes later
 * @returns {string|null} Result, or null when the reply comes later
 */
export function host_add(args, reply) {
	if (!owner_valid(args.owner) || !label_valid(args.host) || !addresses_valid(args.addresses))
		return 'invalid';

	const existing = host.foreign_get(local_name(args.host));

	if (existing && owners.host[existing.name] !== args.owner)
		return 'duplicated';

	if (!existing && host.owns(local_name(args.host)))
		return 'duplicated';

	if (existing) {
		const before = host.build_records(existing.name);

		host.foreign_set(existing.name, args.addresses, host_ops);
		goodbye_records(existing.name,
		                response.records_missing(before, host.build_records(existing.name)));
		subscribe.schedule();

		return settle(existing.name, host_ops, reply);
	}

	if (length(owners.host) >= c.MAX_PUBLISHED_HOSTS)
		return 'invalid';

	const name = host.foreign_set(local_name(args.host), args.addresses, host_ops);

	owners.host[name] = args.owner;
	mdns.info(`publish: ${args.owner} publishes host ${name}\n`);

	return claim(name, host_ops, reply);
};

/**
 * Withdraw a published host
 * @param {object} args - ubus arguments with owner, host
 * @returns {string} Result
 */
export function host_del(args) {
	if (!owner_valid(args.owner) || !label_valid(args.host))
		return 'invalid';

	const name = host.foreign_get(local_name(args.host))?.name;

	if (!name || owners.host[name] !== args.owner)
		return 'not_found';

	withdraw(name, host.build_records);
	host.foreign_del(name);
	delete owners.host[name];
	subscribe.schedule();

	return 'ok';
};

/**
 * The claimed name a KEY record travels with
 * @param {string} name - Owner name of the KEY record
 * @returns {string|null} Claimed host or instance name, or null
 */
function key_holder(name) {
	return host.canonical(name) ?? service.find_by_name(name);
}

/**
 * Publish or replace the KEY record of a name
 * @param {object} args - ubus arguments with owner, name, key
 * @returns {string} Result
 */
export function key_add(args) {
	if (!owner_valid(args.owner) || type(args.name) !== 'string' || !length(args.name))
		return 'invalid';

	if (type(args.key) !== 'string' || !match(args.key, /^([0-9a-fA-F][0-9a-fA-F])+$/))
		return 'invalid';

	const name = local_name(args.name);
	const existing = key.get(name);

	if (existing && existing.owner !== args.owner)
		return 'duplicated';

	key.set(name, args.key, args.owner);

	const holder = key_holder(name);
	const state = holder ? announce.get_state(holder) : null;

	for (let iface_name in state?.ifaces ?? [])
		announce.refresh(holder, iface_name);

	return 'ok';
};

/**
 * Withdraw the KEY record of a name
 * @param {object} args - ubus arguments with owner, name
 * @returns {string} Result
 */
export function key_del(args) {
	if (!owner_valid(args.owner) || type(args.name) !== 'string' || !length(args.name))
		return 'invalid';

	const name = local_name(args.name);

	if (key.get(name)?.owner !== args.owner)
		return 'not_found';

	const holder = key_holder(name);

	if (holder)
		goodbye_records(holder, key.records(name));

	key.del(name);

	return 'ok';
};

/**
 * Withdraw everything an owner published
 * @param {string} owner - Owner string
 * @returns {number} Number of entries withdrawn
 */
export function owner_flush(owner) {
	let count = 0;

	for (let entry in key.list()) {
		if (entry.owner === owner && key_del({ owner: owner, name: entry.name }) === 'ok')
			count++;
	}

	for (let name, name_owner in { ...owners.service }) {
		if (name_owner !== owner)
			continue;

		const svc = service.get(name);

		if (service_del({ owner: owner, instance: svc.instance, service: svc.service_type }) === 'ok')
			count++;
	}

	for (let name, name_owner in { ...owners.host }) {
		if (name_owner !== owner)
			continue;

		if (host_del({ owner: owner, host: replace(name, /\.local$/i, '') }) === 'ok')
			count++;
	}

	return count;
};

/**
 * Announce again the services that point at our own host name
 *
 * Their SRV target follows the primary host name, which changed after a lost
 * conflict.
 */
export function local_refresh() {
	for (let name in owners.service) {
		if (service.get(name)?.hostname)
			continue;

		const state = announce.get_state(name);

		for (let iface_name in state?.ifaces ?? [])
			announce.refresh(name, iface_name);
	}
};
