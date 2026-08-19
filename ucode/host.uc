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

function claim_key(name) {
	return utils.name_normalise(name);
}

function address_record(name, record_type, address, ttl) {
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
}

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
 * @param {string} name - Host name like "router.local."
 * @returns {string|null} Previous primary name
 */
export function set_hostname(name) {
	const previous = primary;
	const wanted = name ? rtrim(name, '.') : name;

	/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
	 * ASCII-compatible encoding of it */
	if (utils.name_is_punycode(wanted)) {
		log.WARN(`host: Refusing ${wanted}: punycode is not a legal mDNS encoding\n`);
		return previous;
	}

	/* A name held only because it was also the primary goes when the primary
	 * does. extra_stale() skips the primary key, so leaving it in extra would
	 * keep it claimed and re-announce it after its own goodbye. */
	if (previous && claim_key(previous) !== claim_key(wanted ?? '')) {
		delete claimed[claim_key(previous)];
		delete extra[claim_key(previous)];
	}

	primary = wanted;

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
 * @returns {void}
 */
export function extra_set(names) {
	for (let name in extra_stale(names)) {
		delete extra[claim_key(name)];
		delete claimed[claim_key(name)];
	}

	for (let raw in names) {
		let name = rtrim(raw, '.');

		/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
		 * ASCII-compatible encoding of it */
		if (utils.name_is_punycode(name)) {
			log.WARN(`host: Refusing ${name}: punycode is not a legal mDNS encoding\n`);
			continue;
		}

		/* Honour an earlier rename rather than re-claiming the name that
		 * lost the conflict */
		if (renamed[claim_key(name)])
			name = renamed[claim_key(name)];

		extra[claim_key(name)] = name;
		if (!claimed[claim_key(name)])
			claimed[claim_key(name)] = name;
	}
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

	const label = replace(host_name, /\.local\.?$/, '');
	const numbered = match(label, /-([0-9]+)$/);
	const next = numbered ? replace(label, /-[0-9]+$/, `-${int(numbered[1]) + 1}`)
	                      : `${label}-2`;
	const new_name = `${next}.local`;

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
