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
import * as mdns from 'mdns';
import * as c from 'const';

/**
 * Normalise DNS name for comparison and as a lookup key
 *
 * RFC 6762 Section 16: ASCII letters compare case-insensitively, every other
 * byte compares as it is. The result has no trailing dot, and only "." and
 * "\" inside a label are escaped.
 *
 * @param {string} name - DNS name to normalise
 * @returns {string|null} Normalised name, or null if the name is invalid
 */
export function name_normalise(name) {
	if (!name)
		return null;

	return mdns.name_canonical(name);
};

/**
 * Compare two DNS names
 *
 * @param {string} a - First name
 * @param {string} b - Second name
 * @returns {boolean} True if the strings are identical and not empty, or
 *   if both names are valid and the same
 */
export function name_equal(a, b) {
	if (a === b)
		return !!a;

	const first = name_normalise(a);

	return first != null && first === name_normalise(b);
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
 * Encode one DNS label for use in a name
 *
 * A dot or a backslash inside the label is escaped, so the label stays one
 * label. RFC 6762 Section 16: the label must be well-formed UTF-8 without C1
 * controls. mdns.name_prepare() checks this and the length, and keeps the
 * bytes as they are. An invalid label raises an exception.
 *
 * @param {string} label - Label text, 1 to 63 bytes, without control characters
 * @returns {string} Escaped label
 */
export function label_encode(label) {
	if (type(label) != 'string' || !length(label) ||
	    index(label, '\x00') >= 0 || match(label, /[\x01-\x1f\x7f]/))
		die('invalid DNS label');

	const prepared = mdns.name_prepare(replace(label, /([.\\])/g, '\\$1'));

	if (prepared == null)
		die('invalid DNS label');

	return prepared;
};

/**
 * Get the first label of a name, without its escapes
 *
 * @param {string} name - Name as produced by label_encode() or the codec
 * @returns {string} First label, e.g. "My Printer" for "My Printer._ipp._tcp.local"
 */
export function label_first(name) {
	let label = '';

	for (let i = 0; i < length(name); i++) {
		let ch = substr(name, i, 1);

		if (ch == '.')
			break;
		if (ch == '\\')
			ch = substr(name, ++i, 1);

		label += ch;
	}

	return label;
};

/**
 * Get the number of a type or class name
 *
 * @param {object} table - c.TYPE_NUMBERS or c.CLASS_NUMBERS
 * @param {string} name - Name such as "AAAA", or "UNKNOWN_<n>" from the codec
 * @returns {number} The number
 */
export function code_number(table, name) {
	return table[name] ?? int(replace(name, /^UNKNOWN_/, ''));
};

/**
 * Build service instance name
 * @param {string} instance - Instance name like "My Printer"
 * @param {string} service_type - Service type like "_http._tcp.local"
 * @returns {string} Full instance name like "My Printer._http._tcp.local"
 */
export function build_instance_name(instance, service_type) {
	return `${label_encode(instance)}.${service_type}`;
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
 * RFC 6762 Section 16: names are UTF-8, and no other encoding may be used.
 * Appendix F names punycode and the other ASCII-compatible encodings of
 * unicast DNS as the ones excluded. This test does not check the Unicode
 * normalisation form of a name.
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
	const now = int(now_ms() / 1000);

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

function address_equal(a, b) {
	if (a === b)
		return iptoarr(a) != null;

	const first = iptoarr(a);
	const second = iptoarr(b);

	if (first == null || second == null || length(first) !== length(second))
		return false;

	for (let i = 0; i < length(first); i++) {
		if (first[i] !== second[i])
			return false;
	}

	return true;
}

/**
 * Compare DNS record rdata for equality
 *
 * Type-specific comparison of record data. Used for conflict detection,
 * known-answer suppression, and cache management. Other types compare by
 * their wire encoding, with embedded names in lower case. Data that cannot
 * be encoded never compares equal.
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
		return address_equal(rdata1?.address, rdata2?.address);

	case 'PTR':
		return name_equal(rdata1?.ptr, rdata2?.ptr);

	case 'CNAME':
		return name_equal(rdata1?.cname, rdata2?.cname);

	case 'SRV':
		return rdata1?.priority === rdata2?.priority &&
		       rdata1?.weight === rdata2?.weight &&
		       rdata1?.port === rdata2?.port &&
		       name_equal(rdata1?.target, rdata2?.target);

	case 'TXT':
		return txt_strings_equal(rdata1?.strings, rdata2?.strings);

	default:
		const encoded1 = mdns.rdata_canonical({ type, rdata: rdata1 });
		const encoded2 = mdns.rdata_canonical({ type, rdata: rdata2 });
		return encoded1 != null && encoded2 != null && encoded1 === encoded2;
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

/**
 * Append a suffix to a label, shortening the label to stay within 63 bytes
 *
 * The label is cut at a UTF-8 character boundary.
 *
 * @param {string} label - Unescaped label text
 * @param {string} suffix - Suffix such as " (2)" or "-2"
 * @returns {string} Label with the suffix
 */
export function label_suffix(label, suffix) {
	let end = min(length(label), 63 - length(suffix));

	while (end > 0 && end < length(label) && (ord(label, end) & 0xc0) === 0x80)
		end--;

	return substr(label, 0, end) + suffix;
};
