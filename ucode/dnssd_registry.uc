/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

import * as announce from 'announce';
import * as service from 'service';
import * as host from 'host';
import * as utils from 'utils';
import * as uloop from 'uloop';
import * as log from 'log';
import * as c from 'const';

export const ERROR_NONE = 0;
export const ERROR_FAILED = 1;
export const ERROR_NO_BUFS = 3;
export const ERROR_INVALID_ARGS = 7;
export const ERROR_ABORT = 11;
export const ERROR_INVALID_STATE = 13;
export const ERROR_DUPLICATED = 29;

const PART_KINDS = [ 'host', 'service', 'key' ];

const entries = {};
const names = {};
const record_index = {};
const owner_counts = {};
let hooks = { available: () => false };

function entry_key(iface_name, name) {
	return `${iface_name}\t${utils.name_normalise(name)}`;
}

function records_ttl(records, ttl) {
	if (ttl == null)
		return records;

	return map(records, record => ({ ...record, ttl, flush_cache: record.flush_cache && ttl > 0 }));
}

/**
 * records_get - get the records registered under a claimed name
 * @name: claimed name
 * @ttl: TTL for every record, null for the registered TTLs, 0 for a goodbye
 * @iface_name: interface name
 *
 * Return: the records of the registration of @name on @iface_name
 */
export function records_get(name, ttl, iface_name) {
	return records_ttl(entries[entry_key(iface_name, name)]?.records ?? [], ttl);
};

/**
 * reserved - check whether a DNS-SD client registered a name
 * @name: DNS name
 *
 * Return: true if a registration on any interface holds @name
 */
export function reserved(name) {
	const claim = utils.name_normalise(name);

	return claim != null && names[claim] != null;
};

host.reservation_set(reserved);
service.reservation_set(reserved);

function index_add(entry) {
	for (let record in entry.records) {
		const key = entry_key(entry.iface, record.name);

		record_index[key] ??= {};
		record_index[key][entry.key] = true;
	}
}

function index_drop(entry) {
	for (let record in entry.records) {
		const key = entry_key(entry.iface, record.name);

		if (!record_index[key])
			continue;

		delete record_index[key][entry.key];

		if (!length(record_index[key]))
			delete record_index[key];
	}
}

function records_assign(entry, records) {
	index_drop(entry);
	entry.records = records;
	index_add(entry);
}

function entry_create(key, name, iface_name, owner) {
	const entry = { key, name, claim: utils.name_normalise(name), iface: iface_name, owner,
		parts: {}, records: [], pending: {}, claimed: false };

	entries[key] = entry;
	names[entry.claim] ??= {};
	names[entry.claim][key] = true;
	owner_counts[owner] = (owner_counts[owner] ?? 0) + 1;

	return entry;
}

function entry_drop(entry) {
	entry.timer?.cancel();
	entry.timer = null;
	index_drop(entry);
	delete entries[entry.key];
	delete names[entry.claim][entry.key];

	if (!length(names[entry.claim]))
		delete names[entry.claim];

	owner_counts[entry.owner]--;

	if (owner_counts[entry.owner] <= 0)
		delete owner_counts[entry.owner];
}

function callbacks_run(callbacks, error, name) {
	for (let done in callbacks ?? [])
		done(error, name);
}

function entry_complete(entry, error) {
	const pending = entry.pending;

	entry.timer?.cancel();
	entry.timer = null;
	entry.pending = {};

	for (let kind, callbacks in pending)
		callbacks_run(callbacks, error, entry.name);
}

function entry_reported(entry) {
	for (let kind in entry.parts) {
		if (!length(entry.pending[kind]))
			return true;
	}

	return false;
}

function claim_release(entry, goodbye) {
	if (!entry.claimed)
		return;

	if (goodbye)
		announce.goodbye(entry.claim, entry.iface, records_get);

	announce.iface_remove(entry.claim, entry.iface);
	entry.claimed = false;
}

function entry_withdraw(entry, error) {
	claim_release(entry, true);
	entry_drop(entry);
	entry_complete(entry, error);
}

function dependants(entry) {
	return filter(values(entries), other => other.owner === entry.owner && other.iface === entry.iface &&
		other.parts.service?.host_target != null &&
		utils.name_equal(other.parts.service.host_target, entry.name));
}

function entry_fail(entry, error) {
	if (entries[entry.key] !== entry)
		return;

	const reported = entry_reported(entry);

	log.NOTE(`dnssd: Withdrawing ${entry.name} on ${entry.iface}, error ${error}\n`);

	entry_withdraw(entry, error);

	if (reported)
		hooks.event?.(entry.owner, { name: entry.name, interface: entry.iface, error });

	if (!entry.parts.host)
		return;

	for (let other in dependants(entry))
		entry_fail(other, error);
}

function claim_link(name, iface_name, state) {
	const entry = entries[entry_key(iface_name, name)];

	if (entry && state !== 'probing')
		entry_complete(entry, ERROR_NONE);
}

function claim_fail(name, iface_name, reason) {
	const entry = entries[entry_key(iface_name, name)];

	if (!entry)
		return;

	entry.claimed = false;
	entry_fail(entry, reason === announce.FAIL_CONFLICT ? ERROR_DUPLICATED : ERROR_FAILED);
}

const ops = {
	records: records_get,
	link: claim_link,
	fail: claim_fail
};

function claim_start(entry) {
	announce.start_probe(entry.claim, entry.iface, ops);
	entry.claimed = true;
}

function pending_add(entry, kind, done) {
	entry.pending[kind] ??= [];
	push(entry.pending[kind], done);
	entry.timer ??= uloop.timer(c.DNSSD_PUBLISH_TIMEOUT_MS, () => entry_fail(entry, ERROR_FAILED));
}

function pending_abort(entry, kind) {
	const callbacks = entry.pending[kind];

	delete entry.pending[kind];

	if (!length(entry.pending)) {
		entry.timer?.cancel();
		entry.timer = null;
	}

	callbacks_run(callbacks, ERROR_ABORT, entry.name);
}

function parts_records(parts) {
	const result = [];

	for (let kind in PART_KINDS) {
		if (parts[kind])
			push(result, ...parts[kind].records);
	}

	return result;
}

function records_same(existing, built) {
	if (length(existing) !== length(built))
		return false;

	for (let record in existing) {
		if (!length(filter(built, other => utils.records_equal(record, other) && record.ttl === other.ttl)))
			return false;
	}

	return true;
}

function record_replaced(old, records) {
	for (let record in records) {
		if (utils.records_equal(old, record))
			return true;
		if (old.flush_cache && record.flush_cache && utils.name_equal(old.name, record.name) &&
		    old.type === record.type && old.class === record.class)
			return true;
	}

	return false;
}

function records_goodbye(entry, removed) {
	if (length(removed))
		announce.goodbye(entry.claim, entry.iface, () => records_ttl(removed, 0));
}

function entry_change(entry, kind, part, done) {
	const parts = { ...entry.parts };

	if (part)
		parts[kind] = part;
	else
		delete parts[kind];

	const records = parts_records(parts);
	const published = entry.claimed && announce.is_announced(entry.claim, entry.iface);

	if (!entry.claimed && length(records) && announce.update_wait(entry.claim, entry.iface) > 0)
		return ERROR_NO_BUFS;

	if (published)
		records_goodbye(entry, filter(entry.records, old => !record_replaced(old, records)));

	entry.parts = parts;
	records_assign(entry, records);

	if (published && length(records)) {
		announce.refresh(entry.claim, entry.iface);
		return ERROR_NONE;
	}

	claim_release(entry, false);

	if (!length(records)) {
		entry_complete(entry, ERROR_NONE);
		return ERROR_NONE;
	}

	claim_start(entry);

	if (done)
		pending_add(entry, kind, done);

	return null;
}

function name_claimable(name) {
	if (utils.name_is_punycode(name))
		die('punycode name');

	return name;
}

function ttl_cap(value, ceiling) {
	if (value == null || value === 0)
		return ceiling;

	if (type(value) != 'int' || value < 0)
		die('invalid TTL');

	return min(value, ceiling);
}

function field_check(value) {
	if (type(value) != 'int' || value < 0 || value > c.SRV_FIELD_MAX)
		die('invalid SRV field');

	return value;
}

function hex_check(value) {
	if (type(value) != 'string' || length(value) % 2 || match(value, /[^0-9a-fA-F]/))
		die('invalid hexadecimal data');

	return value;
}

function type_local(service_type) {
	const parsed = type(service_type) == 'string' ? service.type_parse(`${service_type}.local`) : null;

	if (parsed?.domain != 'local')
		die('invalid service type');

	return parsed.name;
}

function address_canonical(address) {
	const bytes = type(address) == 'string' && index(address, '\x00') < 0 ? iptoarr(address) : null;

	if (length(bytes) != 16)
		die('invalid IPv6 address');

	return arrtoip(bytes);
}

function txt_decode(encoded) {
	const raw = hexdec(hex_check(encoded));
	const strings = [];

	for (let offset = 0; offset < length(raw);) {
		const size = ord(raw, offset++);

		if (offset + size > length(raw))
			die('truncated TXT data');

		push(strings, substr(raw, offset, size));
		offset += size;
	}

	if (!length(strings))
		push(strings, '');

	if (utils.txt_size(strings) > c.MAX_TXT_SIZE)
		die('TXT data too large');

	return strings;
}

function subtypes_build(subtypes, service_type) {
	if (type(subtypes) != 'array' || length(subtypes) > c.DNSSD_SUBTYPES_MAX)
		die('invalid subtype list');

	const result = [];

	for (let label in subtypes) {
		const name = `${utils.label_encode(label)}._sub.${service_type}`;

		if (!length(filter(result, other => utils.name_equal(other, name))))
			push(result, name);
	}

	return result;
}

function host_part(definition) {
	const name = name_claimable(`${utils.label_encode(definition.name)}.local`);
	const ttl = ttl_cap(definition.ttl, c.SERVICE_TTL_SEC);
	const addresses = definition.addresses;

	if (type(addresses) != 'array' || length(addresses) > c.DNSSD_ADDRESSES_MAX)
		die('invalid IPv6 address list');

	const records = [];

	for (let address in addresses) {
		const record = host.address_record(name, 'AAAA', address_canonical(address), ttl);

		if (!length(filter(records, other => utils.records_equal(other, record))))
			push(records, record);
	}

	return { name, records, definition };
}

function service_part(definition) {
	const service_type = type_local(definition.service_type);
	const name = name_claimable(utils.build_instance_name(definition.instance, service_type));
	const host_target = definition.host != null ? `${utils.label_encode(definition.host)}.local` : null;
	const target = host_target ?? host.hostname();

	if (type(target) != 'string' || !length(target))
		die('missing service host');

	if (!service.port_valid(definition.port))
		die('invalid port');

	const records = service.records_make(name, {
		service_type,
		target,
		port: definition.port,
		priority: field_check(definition.priority ?? 0),
		weight: field_check(definition.weight ?? 0),
		strings: txt_decode(definition.txt_hex ?? ''),
		subtypes: subtypes_build(definition.subtypes ?? [], service_type),
		ttl_host: ttl_cap(definition.ttl, c.SERVICE_TTL_SEC),
		ttl_service: ttl_cap(definition.ttl, c.RECORD_TTL_SEC)
	}, null);

	return { name, records, definition, service_type, host_target };
}

function key_part(definition) {
	const service_type = definition.service_type != null ? type_local(definition.service_type) : null;
	const name = name_claimable(`${utils.label_encode(definition.name)}.${service_type ?? 'local'}`);
	const raw = hex_check(definition.key_hex);

	if (!length(raw) || length(raw) > c.DNSSD_KEY_HEX_MAX)
		die('invalid KEY data');

	if ((definition.class ?? c.CLASS_NUMBERS.IN) != c.CLASS_NUMBERS.IN)
		die('unsupported KEY class');

	const ttl = ttl_cap(definition.ttl, service_type ? c.RECORD_TTL_SEC : c.SERVICE_TTL_SEC);

	return { name, definition, records: [
		{ name, type: 'KEY', class: 'IN', ttl, flush_cache: true, rdata: { raw: lc(raw) } }
	] };
}

function part_build(kind, definition) {
	if (type(definition) != 'object')
		die('invalid registration');

	switch (kind) {
	case 'host':
		return host_part(definition);
	case 'service':
		return service_part(definition);
	case 'key':
		return key_part(definition);
	}

	die('invalid registration kind');
}

function host_owned(owner, iface_name, name) {
	const target = entries[entry_key(iface_name, name)];

	return target?.owner === owner && target.parts.host != null;
}

function registration_check(owner, iface_name, part, existing) {
	if (existing && existing.owner !== owner)
		return ERROR_DUPLICATED;

	if (!existing && (host.owns(part.name) || service.find_by_name(part.name) != null))
		return ERROR_DUPLICATED;

	if (part.host_target != null && !host_owned(owner, iface_name, part.host_target))
		return ERROR_INVALID_STATE;

	if (existing)
		return null;

	if (length(entries) >= c.DNSSD_REGISTRATIONS_MAX ||
	    (owner_counts[owner] ?? 0) >= c.DNSSD_OWNER_REGISTRATIONS_MAX)
		return ERROR_NO_BUFS;

	return null;
}

/**
 * configure - set the interface check and the event sink
 * @options: { available, event }; available(iface_name) tells whether an
 *           interface can carry registrations, event(owner, data) reports a
 *           registration lost after it was confirmed
 *
 * Return: nothing
 */
export function configure(options) {
	hooks = { available: () => false, ...options };
};

/**
 * registration_set - publish a host, service or KEY registration on one link
 * @owner: session identifier
 * @iface_name: interface name
 * @kind: "host", "service" or "key"
 * @definition: registration fields
 * @done: callback taking an OpenThread error code and the registered name
 *
 * Return: nothing; @done runs once the name is probed, or at once for an
 *         update of a published name, a registration without records or an
 *         error
 */
export function registration_set(owner, iface_name, kind, definition, done) {
	let part;

	try {
		part = part_build(kind, definition);
	} catch (e) {
		done(ERROR_INVALID_ARGS);
		return;
	}

	if (!hooks.available(iface_name)) {
		done(ERROR_INVALID_STATE);
		return;
	}

	const key = entry_key(iface_name, part.name);
	const existing = entries[key];
	const error = registration_check(owner, iface_name, part, existing);

	if (error != null) {
		done(error);
		return;
	}

	const entry = existing ?? entry_create(key, part.name, iface_name, owner);
	const current = entry.parts[kind];

	if (current && records_same(current.records, part.records)) {
		if (entry.claimed && !announce.is_announced(entry.claim, iface_name))
			pending_add(entry, kind, done);
		else
			done(ERROR_NONE, entry.name);
		return;
	}

	const result = entry_change(entry, kind, part, done);

	if (result === ERROR_NO_BUFS && !length(entry.parts))
		entry_drop(entry);

	if (result != null)
		done(result, entry.name);
};

/**
 * registration_remove - withdraw one part of a registration
 * @owner: session identifier
 * @iface_name: interface name
 * @name: full DNS name of the registration
 * @kind: "host", "service" or "key"
 *
 * Return: OpenThread error code; a part that does not exist counts as removed
 */
export function registration_remove(owner, iface_name, name, kind) {
	const entry = entries[entry_key(iface_name, name)];

	if (!entry)
		return ERROR_NONE;

	if (entry.owner !== owner)
		return ERROR_DUPLICATED;

	if (!entry.parts[kind])
		return ERROR_NONE;

	pending_abort(entry, kind);

	if (length(entry.parts) == 1)
		entry_withdraw(entry, ERROR_ABORT);
	else
		entry_change(entry, kind, null, null);

	if (kind != 'host')
		return ERROR_NONE;

	for (let other in dependants(entry))
		entry_withdraw(other, ERROR_ABORT);

	return ERROR_NONE;
};

/**
 * owner_remove - withdraw every registration of a session
 * @owner: session identifier
 *
 * Return: nothing
 */
export function owner_remove(owner) {
	for (let entry in values(entries)) {
		if (entry.owner === owner)
			entry_withdraw(entry, ERROR_ABORT);
	}
};

function iface_entries(iface_name) {
	return filter(values(entries), entry => entry.iface === iface_name);
}

/**
 * interface_up - probe the registrations of a link again after a link change
 * @iface_name: interface name
 *
 * Return: nothing
 */
export function interface_up(iface_name) {
	for (let entry in iface_entries(iface_name)) {
		if (!length(entry.records))
			continue;

		claim_release(entry, false);
		claim_start(entry);
	}
};

/**
 * interface_down - stop claiming the registrations of a link that went down
 * @iface_name: interface name
 *
 * Return: nothing
 */
export function interface_down(iface_name) {
	for (let entry in iface_entries(iface_name))
		claim_release(entry, false);
};

/**
 * interface_stop - withdraw the registrations of an interface being removed
 * @iface_name: interface name
 *
 * Return: nothing
 */
export function interface_stop(iface_name) {
	for (let entry in iface_entries(iface_name))
		entry_withdraw(entry, ERROR_INVALID_STATE);
};

/**
 * primary_changed - follow a new local host name in services without a host
 *
 * Return: nothing
 */
export function primary_changed() {
	for (let entry in values(entries)) {
		const part = entry.parts.service;

		if (!part || part.host_target != null)
			continue;

		try {
			entry_change(entry, 'service', service_part(part.definition), null);
		} catch (e) {
			entry_fail(entry, ERROR_FAILED);
		}
	}
};

/**
 * claim_find - find the claimed name of a registration
 * @name: DNS name
 *
 * Return: the name under which announce.uc claims @name, or null
 */
export function claim_find(name) {
	const claim = utils.name_normalise(name);

	return claim != null && names[claim] != null ? claim : null;
};

/**
 * records_query - find the published records at a name on one link
 * @iface_name: interface name
 * @name: DNS name
 * @record_type: DNS type, or "ANY"
 *
 * Return: records of registrations that finished probing on @iface_name
 */
export function records_query(iface_name, name, record_type) {
	const result = [];

	for (let key in record_index[entry_key(iface_name, name)] ?? {}) {
		const entry = entries[key];

		if (!announce.is_announced(entry.claim, iface_name))
			continue;

		push(result, ...filter(entry.records, record => utils.name_equal(record.name, name) &&
			(record_type == 'ANY' || record.type == record_type)));
	}

	return result;
};

/**
 * service_types - list the service types published on one link
 * @iface_name: interface name
 *
 * Return: service type names of the local services and of the service
 *         registrations published on @iface_name, each name once
 */
export function service_types(iface_name) {
	const found = {};

	for (let service_type in service.types())
		found[utils.name_normalise(service_type)] ??= service_type;

	for (let key, entry in entries) {
		const part = entry.parts.service;

		if (entry.iface !== iface_name || !part || !announce.is_announced(entry.claim, iface_name))
			continue;

		found[utils.name_normalise(part.service_type)] ??= part.service_type;
	}

	return values(found);
};
