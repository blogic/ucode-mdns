/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * host.uc - Host name registry and address records
 *
 * Owns the names this host claims for itself and builds the A and AAAA
 * records that answer them. The primary name comes from the configuration or
 * from the system host name; extra names come from the hostname field of a
 * service definition, which is what the OpenWrt umdns daemon does too.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as mdns from 'mdns';
import * as log from 'log';
import * as utils from 'utils';
import * as c from 'const';

/* Claimed names, normalised key -> canonical name. Wire-parsed names carry no
 * trailing root dot while claimed names always do, and DNS names compare
 * case-insensitively (RFC 6762 Section 16) */
const claimed = {};

/* Names from service definitions, tracked apart from the primary so a reload
 * can withdraw the ones that went away */
const extra = {};

/* Original name -> the name we took after losing a conflict on it. A reload
 * recomputes the wanted set from the unchanged service definitions, so without
 * this the conflicting name would be claimed again on every reload. */
const renamed = {};

let primary;
let reserved_check;

function claim_key(name) {
	return utils.name_normalise(name);
}

/**
 * reservation_set - install the check for names another publisher holds
 * @check: function taking a name and returning true if it is taken, or null
 *
 * Return: nothing
 */
export function reservation_set(check) {
	reserved_check = check;
};

/**
 * address_record - build the A or AAAA record of a host name
 * @name: host name
 * @record_type: "A" or "AAAA"
 * @address: address in text form
 * @ttl: TTL in seconds, 0 for a goodbye
 *
 * Return: the record, with the cache-flush bit unless it is a goodbye
 */
export function address_record(name, record_type, address, ttl) {
	return {
		name: name,
		type: record_type,
		class: 'IN',
		ttl: ttl,
		/* RFC 6762 Section 10.2: address records are unique to this host */
		flush_cache: (ttl > 0),
		rdata: {
			address: address
		}
	};
};

function name_next(name) {
	const label = utils.label_first(name);
	const rest = substr(name, length(utils.label_encode(label)) + 1);
	const numbered = match(label, /-([0-9]+)$/);
	const suffix = numbered ? `-${int(numbered[1]) + 1}` : '-2';
	const base = numbered ? replace(label, /-[0-9]+$/, '') : label;

	return `${utils.label_encode(utils.label_suffix(base, suffix))}.${rest}`;
}

function name_taken(name) {
	return !!reserved_check?.(name);
}

/**
 * free_name - find the first name another publisher does not hold
 * @name: wanted host name
 *
 * Return: @name, or the first numbered form of it that is free
 */
export function free_name(name) {
	let current = name;

	for (let tries = 0; current && name_taken(current) && tries < c.SERVICE_RENAME_MAX; tries++)
		current = name_next(current);

	return current;
};

/**
 * Canonical form of a claimed name
 * @param {string} name - Name in any case, with or without the trailing dot
 * @returns {string|null} Claimed name or null if we do not own it
 */
export function canonical(name) {
	return claimed[claim_key(name)] || null;
};

/**
 * Check whether this host claims a name
 * @param {string} name - Name to test
 * @returns {boolean} True if claimed
 */
export function owns(name) {
	return canonical(name) !== null;
};

/**
 * All claimed names
 * @returns {array} Canonical names
 */
export function list() {
	return values(claimed);
};

/**
 * Set the primary host name
 * @param {string} name - Host name like "router.local", as returned by
 *   mdns.name_prepare()
 * @returns {string|null} Previous primary name
 */
export function set_hostname(name) {
	const previous = primary;

	/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
	 * ASCII-compatible encoding of it */
	if (utils.name_is_punycode(name)) {
		log.WARN(`host: Refusing ${name}: punycode is not a legal mDNS encoding\n`);
		return previous;
	}

	/* A name held only because it was also the primary goes when the primary
	 * does. extra_stale() skips the primary key, so leaving it in extra would
	 * keep it claimed and re-announce it after its own goodbye. */
	if (previous && claim_key(previous) !== claim_key(name ?? '')) {
		delete claimed[claim_key(previous)];
		delete extra[claim_key(previous)];
	}

	primary = name;

	if (primary)
		claimed[claim_key(primary)] = primary;

	return previous;
};

/**
 * Get the primary host name
 * @returns {string|null} Primary name
 */
export function hostname() {
	return primary;
};

/**
 * Names that a following extra_set() would withdraw
 *
 * Reported before the change so the caller can still build goodbye records
 * for them.
 *
 * @param {array} names - Wanted extra names
 * @returns {array} Canonical names about to go away
 */
export function extra_stale(names) {
	const wanted = {};
	for (let name in names) {
		const key = claim_key(name);

		wanted[key] = true;

		/* A name we renamed away from stays wanted under its new spelling,
		 * or the next reload would claim the conflicting one again */
		if (renamed[key])
			wanted[claim_key(renamed[key])] = true;
	}

	const stale = [];
	for (let key, name in extra) {
		if (wanted[key])
			continue;
		if (primary && key === claim_key(primary))
			continue;
		push(stale, name);
	}

	return stale;
};

/**
 * Replace the set of extra names
 * @param {array} names - Wanted extra names
 * @returns {array} Names replaced because another publisher holds them,
 *   as { from, to } pairs
 */
export function extra_set(names) {
	const replaced = [];

	for (let name in extra_stale(names)) {
		delete extra[claim_key(name)];
		delete claimed[claim_key(name)];
	}

	for (let raw in names) {
		let name = mdns.name_prepare(raw);

		if (!name)
			continue;

		/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
		 * ASCII-compatible encoding of it */
		if (utils.name_is_punycode(name)) {
			log.WARN(`host: Refusing ${name}: punycode is not a legal mDNS encoding\n`);
			continue;
		}

		/* Honour an earlier rename rather than re-claiming the name that
		 * lost the conflict */
		const wanted = name;

		if (renamed[claim_key(name)])
			name = renamed[claim_key(name)];

		if (name_taken(name)) {
			const free = free_name(name);

			renamed[claim_key(wanted)] = free;
			push(replaced, { from: name, to: free });
			name = free;
		}

		extra[claim_key(name)] = name;
		if (!claimed[claim_key(name)])
			claimed[claim_key(name)] = name;
	}

	return replaced;
};

/**
 * Build the address records for a claimed name
 *
 * RFC 6762 Section 10: records carrying a host name use a 120 second TTL.
 *
 * @param {string} name - Claimed name
 * @param {number} ttl - Override TTL, null for the default, 0 for a goodbye
 * @param {string} iface_name - Interface to take the addresses from, null for all
 * @returns {array} A and AAAA records
 */
export function build_records(name, ttl, iface_name) {
	const records = [];
	const host_name = canonical(name);

	if (!host_name)
		return records;

	const record_ttl = ttl != null ? ttl : c.SERVICE_TTL_SEC;

	for (let iface in mdns.interface_list()) {
		if (iface_name && iface.name !== iface_name)
			continue;

		for (let address in iface.ipv4_addresses)
			push(records, address_record(host_name, 'A', address, record_ttl));

		for (let address in iface.ipv6_addresses)
			push(records, address_record(host_name, 'AAAA', address, record_ttl));
	}

	return records;
};

/**
 * Record types that exist for a claimed name, for NSEC generation
 *
 * RFC 6762 Section 6.1: an NSEC record states which types the name has.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface the question arrived on
 * @returns {array} Type names
 */
export function types_for(name, iface_name) {
	const types = [];

	for (let record in build_records(name, null, iface_name)) {
		if (index(types, record.type) < 0)
			push(types, record.type);
	}

	return types;
};

function reverse_address(name) {
	const canonical_name = utils.name_normalise(name) ?? '';
	const v4 = match(canonical_name, /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.in-addr\.arpa$/);

	if (v4) {
		const bytes = map([ v4[4], v4[3], v4[2], v4[1] ], value => int(value));

		return length(filter(bytes, byte => byte > 255)) ? null : bytes;
	}

	const v6 = match(canonical_name, /^(([0-9a-f]\.){32})ip6\.arpa$/);

	if (!v6)
		return null;

	const nibbles = reverse(split(rtrim(v6[1], '.'), '.'));
	const bytes = [];

	for (let i = 0; i < 32; i += 2)
		push(bytes, hex(nibbles[i] + nibbles[i + 1]));

	return bytes;
}

/**
 * RFC 6762 Section 4: reverse-mapping PTR records for our own addresses
 *
 * A name under in-addr.arpa or ip6.arpa that maps an address of an interface
 * points to the primary host name. Section 8.1 lets these records skip
 * probing, as the address is known to be ours.
 *
 * @param {string} name - Queried name
 * @param {string} iface_name - Interface the question arrived on
 * @returns {array} The PTR record, or an empty array
 */
export function reverse_records(name, iface_name) {
	const address = reverse_address(name);

	if (!address || !primary)
		return [];

	const wanted = { address: arrtoip(address) };

	for (let record in build_records(primary, null, iface_name)) {
		if (!utils.rdata_equal(record.type, record.rdata, wanted))
			continue;

		return [ {
			name: name,
			type: 'PTR',
			class: 'IN',
			ttl: c.SERVICE_TTL_SEC,
			flush_cache: true,
			rdata: { ptr: primary }
		} ];
	}

	return [];
};

/**
 * RFC 6762 Section 9: claim a different name after losing a probe tiebreak
 *
 * Appends "-2" to the label, or increments an existing number.
 *
 * @param {string} name - Claimed name that lost
 * @returns {string|null} New name, or null if we did not own the old one
 */
export function rename(name) {
	const host_name = canonical(name);

	if (!host_name)
		return null;

	const new_name = free_name(name_next(host_name));
	const key = claim_key(host_name);

	delete claimed[key];

	if (extra[key]) {
		delete extra[key];
		extra[claim_key(new_name)] = new_name;
	}

	if (primary === host_name)
		primary = new_name;

	claimed[claim_key(new_name)] = new_name;

	/* Follow a chain: renaming router-2 to router-3 must still map router */
	for (let original, current in renamed) {
		if (claim_key(current) === key)
			renamed[original] = new_name;
	}

	renamed[key] ??= new_name;

	return new_name;
};

/**
 * Map a host name to the name it was renamed to after a conflict
 *
 * @param {string} name - Host name as configured
 * @returns {string} Current name of that host
 */
export function resolved(name) {
	return name ? (renamed[claim_key(name)] ?? name) : name;
};
