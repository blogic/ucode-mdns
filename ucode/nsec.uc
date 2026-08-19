/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * nsec.uc - NSEC record generation for negative responses
 *
 * RFC 6762 Section 6.1: NSEC records indicate which record types exist
 * for a name, allowing negative responses.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as c from 'const';

/**
 * Encode DNS name to hex wire format
 * @param {string} name - DNS name (e.g., "host.local.")
 * @returns {string} Hex string of wire format
 */
function encode_name_hex(name) {
	let hex = "";
	const labels = split(name, ".");

	for (let label in labels) {
		/* Skip empty labels (from trailing dot) */
		if (length(label) == 0)
			continue;

		/* Label length */
		hex += sprintf("%02x", length(label));

		/* Label characters */
		for (let i = 0; i < length(label); i++)
			hex += sprintf("%02x", ord(label, i));
	}

	/* Root label (zero length) */
	hex += "00";

	return hex;
}

/**
 * Build type bitmap in RFC 4034 format
 *
 * RFC 4034 Section 4.1.2: Type Bit Maps.
 *
 * @param {array} type_numbers - Sorted array of type numbers
 * @returns {object} Window blocks object { window_num: bitmap_array }
 */
function build_type_bitmap(type_numbers) {
	const windows = {};

	for (let type_num in type_numbers) {
		const window = type_num >> 8;  /* Window number (upper byte) */
		const bit = type_num & 0xff;  /* Bit number (lower byte) */

		if (!windows[window])
			windows[window] = [];

		const byte_idx = bit >> 3;  /* Which byte in the bitmap */
		const bit_idx = 7 - (bit & 7);  /* Which bit in the byte (big-endian) */

		/* Ensure array is large enough */
		while (length(windows[window]) <= byte_idx)
			push(windows[window], 0);

		windows[window][byte_idx] |= (1 << bit_idx);
	}

	return windows;
}

/**
 * Encode NSEC rdata as hex string
 * @param {string} next_name - Next Domain Name (same as owner in mDNS)
 * @param {object} windows - Type bitmap windows
 * @returns {string} Hex string of encoded rdata
 */
function encode_nsec_rdata(next_name, windows) {
	let hex = "";

	/* Encode Next Domain Name in DNS wire format */
	hex += encode_name_hex(next_name);

	/* Encode Type Bit Maps */
	for (let window_num in windows) {
		const bitmap = windows[window_num];

		/* Window Block: window number (1 byte) + bitmap length (1 byte) + bitmap */
		hex += sprintf("%02x", int(window_num));
		hex += sprintf("%02x", length(bitmap));

		for (let byte in bitmap)
			hex += sprintf("%02x", byte);
	}

	return hex;
}

/**
 * RFC 6762 Section 6.1: Generate NSEC record for negative response
 *
 * NSEC record format:
 * - Next Domain Name: Same as owner name (forms a loop)
 * - Type Bit Map: Bitmap showing which types exist
 * - MUST NOT set the NSEC bit itself
 *
 * @param {string} name - The owner name (same as Next Domain Name in mDNS)
 * @param {array} existing_types - Array of DNS type strings that DO exist for this name
 * @returns {object} NSEC record object
 */
export function build(name, existing_types) {
	/* RFC 6762 Section 6.1: NSEC record format
	 * - Next Domain Name: Same as owner name (forms a loop)
	 * - Type Bit Map: Bitmap showing which types exist
	 * MUST NOT set the NSEC bit itself */

	/* Collect type numbers. RFC 6762 Section 6.1 leaves the NSEC bit clear;
	 * ANY and OPT are not types that exist at a name. */
	const excluded = [ c.TYPE_NUMBERS.NSEC, c.TYPE_NUMBERS.OPT, c.TYPE_NUMBERS.ANY ];
	const type_numbers = [];

	for (let type_str in existing_types) {
		const number = c.TYPE_NUMBERS[type_str];

		if (number && !(number in excluded))
			push(type_numbers, number);
	}

	/* Sort type numbers */
	sort(type_numbers, function(a, b) { return a - b; });

	/* Build bitmap in window format
	 * RFC 4034 Section 4.1.2: Type Bit Maps */
	const bitmap = build_type_bitmap(type_numbers);

	/* Encode Next Domain Name + Type Bit Map as hex */
	const rdata_hex = encode_nsec_rdata(name, bitmap);

	return {
		name: name,
		type: 'NSEC',
		class: 'IN',
		ttl: 120,  /* Same as host records */
		flush_cache: true,  /* Unique record */
		rdata: {
			raw: rdata_hex
		}
	};
};
