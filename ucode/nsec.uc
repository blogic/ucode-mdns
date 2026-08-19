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
import * as mdns from 'mdns';
import * as utils from 'utils';

/**
 * Encode DNS name to hex wire format
 * @param {string} name - DNS name (e.g., "host.local.")
 * @returns {string} Hex string of wire format
 */
function encode_name_hex(name) {
	return hexenc(mdns.rdata_encode({ type: 'PTR', rdata: { ptr: name } }));
}

/**
 * Build the window 0 type bitmap in RFC 4034 format
 *
 * RFC 4034 Section 4.1.2: Type Bit Maps.
 *
 * @param {array} type_numbers - Sorted array of type numbers below 256
 * @returns {array} Bitmap bytes
 */
function build_type_bitmap(type_numbers) {
	const bitmap = [];

	for (let type_num in type_numbers) {
		const byte_idx = type_num >> 3;  /* Which byte in the bitmap */

		/* Ensure array is large enough */
		while (length(bitmap) <= byte_idx)
			push(bitmap, 0);

		bitmap[byte_idx] |= 0x80 >> (type_num & 7);
	}

	return bitmap;
}

/**
 * Encode NSEC rdata as hex string
 * @param {string} next_name - Next Domain Name (same as owner in mDNS)
 * @param {array} bitmap - Window 0 type bitmap
 * @returns {string} Hex string of encoded rdata
 */
function encode_nsec_rdata(next_name, bitmap) {
	let hex = "";

	/* Encode Next Domain Name in DNS wire format */
	hex += encode_name_hex(next_name);

	/* Window Block: window number (1 byte) + bitmap length (1 byte) + bitmap */
	hex += sprintf("%02x%02x", 0, length(bitmap));

	for (let byte in bitmap)
		hex += sprintf("%02x", byte);

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
 * @returns {object|null} NSEC record object, or null if no type is left to
 *   list or a type is above 255, which the restricted block 0 form of
 *   Section 6.1 cannot list
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
		const number = utils.code_number(c.TYPE_NUMBERS, type_str);

		if (number > 255)
			return null;
		if (number && index(excluded, number) < 0)
			push(type_numbers, number);
	}

	if (!length(type_numbers))
		return null;

	/* Sort type numbers */
	sort(type_numbers, function(a, b) { return a - b; });

	/* Build bitmap in window 0 format
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

/**
 * RFC 6762 Section 6.1: check whether a received NSEC denies a type
 *
 * @param {object} record - Cached NSEC record, rdata.raw holding its rdata
 *   with the next domain name uncompressed
 * @param {string} type - Record type
 * @returns {boolean} True if the NSEC is well formed and does not list the type
 */
export function denies(record, type) {
	const data = hexdec(record?.rdata?.raw ?? '');
	const number = utils.code_number(c.TYPE_NUMBERS, type);
	let pos = 0;

	if (data == null || !number || type === 'ANY')
		return false;

	while (pos < length(data) && ord(data, pos))
		pos += ord(data, pos) + 1;

	if (++pos + 2 > length(data))
		return false;

	while (pos + 2 <= length(data)) {
		const block = ord(data, pos);
		const size = ord(data, pos + 1);
		const byte = (number & 0xff) >> 3;

		if (size < 1 || size > 32 || pos + 2 + size > length(data))
			return false;

		if (block == number >> 8)
			return byte >= size || !(ord(data, pos + 2 + byte) & (0x80 >> (number & 7)));

		pos += 2 + size;
	}

	return pos == length(data);
};
