/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * key.uc - KEY records published for a name
 *
 * An SRP registrar (RFC 9665) advertises the KEY record (RFC 2535) of each
 * host and service instance it proxies, so a second registrar on the link
 * sees who owns the name. The records travel with the host or service entry
 * of the same name; a key without such an entry is only answered, never
 * probed.
 */

import * as utils from 'utils';
import * as c from 'const';

/* Normalised name -> { name, key, owner } */
const entries = {};

/**
 * Store the key for a name, replacing an earlier one
 * @param {string} name - Owner name of the KEY record, e.g. "host.local"
 * @param {string} key - KEY rdata as a hex string
 * @param {string} owner - Client that published it
 */
export function set(name, key, owner) {
	entries[utils.name_normalise(name)] = {
		name: rtrim(name, '.'),
		key: lc(key),
		owner: owner
	};
};

/**
 * Remove the key of a name
 * @param {string} name - Owner name of the KEY record
 * @returns {boolean} True if a key was removed
 */
export function del(name) {
	const key = utils.name_normalise(name);

	if (!entries[key])
		return false;

	delete entries[key];

	return true;
};

/**
 * The stored entry of a name
 * @param {string} name - Owner name of the KEY record
 * @returns {object|null} { name, key, owner } or null
 */
export function get(name) {
	return entries[utils.name_normalise(name)] ?? null;
};

/**
 * Every stored entry
 * @returns {array} Entries { name, key, owner }
 */
export function list() {
	return values(entries);
};

/**
 * The KEY record of a name, as a list so callers can append it
 *
 * RFC 6762 Section 10: the record names a host or an instance, so it takes
 * the 120 second TTL of host records. It is unique to its owner.
 *
 * @param {string} name - Owner name of the KEY record
 * @param {number} ttl - Override TTL, null for the default, 0 for a goodbye
 * @returns {array} Zero or one KEY record
 */
export function records(name, ttl) {
	const entry = get(name);

	if (!entry)
		return [];

	const record_ttl = ttl ?? c.SERVICE_TTL_SEC;

	return [{
		name: entry.name,
		type: 'KEY',
		class: 'IN',
		ttl: record_ttl,
		flush_cache: (record_ttl > 0),
		rdata: {
			raw: entry.key
		}
	}];
};
