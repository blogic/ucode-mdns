/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * utils.uc - Helper functions for mDNS operations
 *
 * Provides name normalisation, parsing, and common utilities.
 */

import * as math from 'math';
import * as c from 'const';

/**
 * Normalise DNS name (lowercase, ensure trailing dot for absolute names)
 * @param {string} name - DNS name to normalise
 * @returns {string|null} Normalised name or null
 */
export function name_normalise(name) {
	if (!name)
		return null;

	/* The wire form has no root dot, so that is the canonical one here.
	 * RFC 6762 Section 16: names compare case-insensitively. */
	return rtrim(lc(name), '.');
};

/**
 * Compare two DNS names
 *
 * @param {string} a - First name
 * @param {string} b - Second name
 * @returns {boolean} True if the names are the same
 */
export function name_equal(a, b) {
	if (a === b)
		return true;

	if (!a || !b)
		return false;

	return name_normalise(a) === name_normalise(b);
};

/**
 * Escape the bytes of a string that are not printable UTF-8
 *
 * RFC 6763 Section 6.5 makes a TXT value opaque binary data, so it may hold
 * anything. Consumers read it out of JSON, which has to be valid UTF-8, and a
 * control character in it would also reach syslog unfiltered.
 *
 * @param {string} str - Arbitrary byte string
 * @returns {string} The same text with invalid bytes shown as \xNN
 */
export function utf8_escape(str) {
	if (!str)
		return str;

	const len = length(str);
	let out = '';
	let i = 0;

	while (i < len) {
		const ch = ord(str, i);
		let extra = 0;

		if (ch >= 0x20 && ch < 0x7f) {
			out += substr(str, i, 1);
			i++;
			continue;
		}

		if ((ch & 0xe0) === 0xc0)
			extra = 1;
		else if ((ch & 0xf0) === 0xe0)
			extra = 2;
		else if ((ch & 0xf8) === 0xf0)
			extra = 3;

		let valid = extra > 0 && i + extra < len;

		for (let j = 1; valid && j <= extra; j++) {
			if ((ord(str, i + j) & 0xc0) !== 0x80)
				valid = false;
		}

		if (!valid) {
			out += sprintf('\\x%02x', ch);
			i++;
			continue;
		}

		out += substr(str, i, extra + 1);
		i += extra + 1;
	}

	return out;
};


/**
 * Extract service type from PTR record name
 * @param {string} name - Service type name like "_http._tcp.local"
 * @returns {object|null} Object with { service, proto, domain } or null
 */
export function parse_service_type(name) {
	const m = match(name, /^(_[^.]+)\.(_[^.]+)\.(.+)$/);
	if (!m)
		return null;

	return {
		service: m[1],
		proto: m[2],
		domain: m[3]
	};
};

/**
 * Build service type name
 * @param {string} service - Service like "_http"
 * @param {string} proto - Protocol like "_tcp" or "_udp"
 * @param {string} domain - Domain (defaults to "local.")
 * @returns {string} Service type name like "_http._tcp.local."
 */
export function build_service_type(service, proto, domain) {
	domain = rtrim(domain || 'local', '.');

	return `${service}.${proto}.${domain}`;
};

/**
 * Build service instance name
 * @param {string} instance - Instance name like "My Printer"
 * @param {string} service_type - Service type like "_http._tcp.local"
 * @returns {string} Full instance name like "My Printer._http._tcp.local"
 */
export function build_instance_name(instance, service_type) {
	return `${instance}.${service_type}`;
};


/**
 * Get monotonic time in milliseconds
 * @returns {number} Milliseconds from a monotonic clock
 */
export function now_ms() {
	const t = clock(true);
	return t[0] * 1000 + t[1] / 1000000;
};

/**
 * Test whether a name carries a punycode label
 *
 * RFC 6762 Section 16: every name is precomposed UTF-8, and no other encoding
 * may be used. Appendix F names punycode and the other ASCII-compatible
 * encodings of unicast DNS as the ones excluded.
 *
 * A punycoded label gives one name two byte forms, so a host claiming
 * "xn--mnchen-3ya.local" never sees its conflict with a host claiming the same
 * name as UTF-8. Uniqueness is decided by comparing bytes, so the two forms
 * must never both be in use.
 *
 * The test is only applied to a name this host proposes to claim. A label may
 * legitimately begin with those four characters, and a name received from the
 * link is another implementation's choice to make.
 *
 * @param {string} name - Name to test
 * @returns {boolean} True if any label carries the punycode prefix
 */
export function name_is_punycode(name) {
	if (!name)
		return false;

	for (let label in split(name, '.')) {
		if (lc(substr(label, 0, 4)) === 'xn--')
			return true;
	}

	return false;
};

/**
 * Count one event against a budget for the current second
 *
 * The caller owns the state object, so one budget can cover a whole module
 * or a table of them can cover each peer.
 *
 * @param {object} state - Counter state, empty on the first call
 * @param {number} limit - Events allowed within one second
 * @returns {boolean} True if the event fits the budget
 */
export function rate_allow(state, limit) {
	const now = time();

	if (state.second !== now) {
		state.second = now;
		state.count = 0;
	}

	if (state.count >= limit)
		return false;

	state.count++;

	return true;
};

/**
 * Generate random delay for multicast response (RFC 6762 Section 6)
 * @returns {number} Milliseconds in range [20, 120] for shared records
 */
export function random_delay() {
	return c.RESPONSE_DELAY_MIN_MS + (math.rand() % (c.RESPONSE_DELAY_MAX_MS - c.RESPONSE_DELAY_MIN_MS + 1));
};

/**
 * Generate TC bit response delay (RFC 6762 Section 6, 7.2)
 * @returns {number} Milliseconds in range [400, 500]
 */
export function tc_delay() {
	return c.TC_DELAY_MIN_MS + (math.rand() % (c.TC_DELAY_MAX_MS - c.TC_DELAY_MIN_MS + 1));
};

/**
 * Generate probe delay (RFC 6762 Section 8.1)
 * @returns {number} Milliseconds in range [0, 250]
 */
export function probe_delay() {
	return math.rand() % (c.PROBE_INTERVAL_MS + 1);
};

/**
 * Calculate next announcement time with exponential backoff
 *
 * RFC 6762 Section 8.3: 1 second between first two, then double.
 *
 * @param {number} announcement_num - 0-based announcement number
 * @returns {number} Milliseconds delay
 */
export function announcement_delay(announcement_num) {
	if (announcement_num === 0)
		return 0;

	/* RFC 6762 Section 8.3: 1 second between first two, then double */
	if (announcement_num === 1)
		return 1000;

	return 1000 * (1 << (announcement_num - 1));  /* 2^(n-1) seconds */
};




/**
 * Parse TXT record strings into key=value object
 * @param {array} strings - Array of TXT strings
 * @returns {object} Object with key-value pairs (boolean true for flags without values)
 */
export function txt_parse(strings) {
	const result = {};

	for (let str in strings) {
		const eq_pos = index(str, '=');
		if (eq_pos >= 0) {
			const key = substr(str, 0, eq_pos);
			const value = substr(str, eq_pos + 1);
			result[key] = value;
		} else {
			/* Boolean flag (no value) */
			result[str] = true;
		}
	}

	return result;
};

/**
 * Build TXT record strings from key=value object
 * @param {object} obj - Object with key-value pairs
 * @returns {array} Array of TXT strings
 */
export function txt_build(obj) {
	const strings = [];

	for (let key in obj) {
		const value = obj[key];
		if (value === true || value === null)
			push(strings, key);
		else
			push(strings, `${key}=${value}`);
	}

	return strings;
};



/**
 * Compare TXT record strings for equality
 * @param {array} strings1 - First array of TXT strings
 * @param {array} strings2 - Second array of TXT strings
 * @returns {boolean} True if arrays contain identical strings in same order
 */
export function txt_strings_equal(strings1, strings2) {
	const s1 = strings1 || [];
	const s2 = strings2 || [];

	if (length(s1) !== length(s2))
		return false;

	for (let i = 0; i < length(s1); i++) {
		if (s1[i] !== s2[i])
			return false;
	}

	return true;
};

/**
 * Calculate total wire size of TXT record strings
 * @param {array} strings - Array of TXT strings
 * @returns {number} Total size in bytes (including length prefixes)
 */
export function txt_size(strings) {
	let total_size = 0;
	for (let str in strings)
		total_size += length(str) + 1;  /* +1 for length byte */
	return total_size;
};


/**
 * Compare DNS record rdata for equality
 *
 * Type-specific comparison of record data. Used for conflict detection,
 * known-answer suppression, and cache management.
 *
 * @param {string} type - DNS record type (A, AAAA, PTR, SRV, TXT, etc.)
 * @param {object} rdata1 - First rdata object
 * @param {object} rdata2 - Second rdata object
 * @returns {boolean} True if rdata is equal, false otherwise
 */
export function rdata_equal(type, rdata1, rdata2) {
	switch (type) {
	case 'A':
	case 'AAAA':
		return rdata1?.address === rdata2?.address;

	case 'PTR':
		return rdata1?.ptr === rdata2?.ptr;

	case 'CNAME':
		return rdata1?.name === rdata2?.name;

	case 'SRV':
		return rdata1?.priority === rdata2?.priority &&
		       rdata1?.weight === rdata2?.weight &&
		       rdata1?.port === rdata2?.port &&
		       rdata1?.target === rdata2?.target;

	case 'TXT':
		return txt_strings_equal(rdata1?.strings, rdata2?.strings);

	case 'NSEC':
		return rdata1?.raw === rdata2?.raw;

	default:
		/* For unknown types, compare serialised form */
		return sprintf('%J', rdata1) === sprintf('%J', rdata2);
	}
};

/**
 * Compare two DNS records for equality
 *
 * Compares name, type, class, and rdata. Ignores TTL and timestamps.
 * Used for cache management, conflict detection, and deduplication.
 *
 * @param {object} r1 - First DNS record
 * @param {object} r2 - Second DNS record
 * @returns {boolean} True if records are equal, false otherwise
 */
export function records_equal(r1, r2) {
	if (!name_equal(r1.name, r2.name) || r1.type !== r2.type || r1.class !== r2.class)
		return false;

	return rdata_equal(r1.type, r1.rdata, r2.rdata);
};
