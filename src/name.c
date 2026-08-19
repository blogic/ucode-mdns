/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <string.h>

#include "mdns.h"

static int label_byte(const char **pos)
{
	const char *p = *pos;

	if (*p != '\\') {
		*pos = p + 1;
		return (unsigned char)*p;
	}

	p++;
	if (p[0] >= '0' && p[0] <= '9' && p[1] >= '0' && p[1] <= '9' &&
	    p[2] >= '0' && p[2] <= '9') {
		int value = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');

		if (value > 255)
			return -1;

		*pos = p + 3;
		return value;
	}

	if (!*p)
		return -1;

	*pos = p + 1;
	return (unsigned char)*p;
}

static int name_parse(const char *name, uint8_t *out, size_t size)
{
	const char *p = name;
	size_t used = 0;

	if (!strcmp(p, "."))
		p++;

	while (*p) {
		size_t label = used++;

		if (*p == '.')
			return -1;

		while (*p && *p != '.') {
			int byte = label_byte(&p);

			if (byte <= 0 || used - label > MAX_LABEL_LEN || used + 1 >= size ||
			    used + 2 > MAX_NAME_LEN + 1)
				return -1;

			out[used++] = byte;
		}

		out[label] = used - label - 1;

		if (*p == '.')
			p++;
	}

	if (used >= size)
		return -1;

	out[used++] = 0;
	return used;
}

/**
 * mdns_name_wire() - encode a presentation-format name in wire format
 * @name: name with labels separated by dots, "\." and "\\" escaped
 * @out: output buffer
 * @size: output buffer size
 *
 * Accepts the escapes "\X" and "\DDD". A trailing dot is optional, and an
 * empty name or "." is the root. RFC 6762 Section 17 and Appendix C allow
 * 255 bytes of name plus the root label.
 *
 * Return: wire length including the root label, or -1 if the name is invalid
 */
int mdns_name_wire(const char *name, uint8_t *out, size_t size)
{
	return name_parse(name, out, size);
}

/**
 * mdns_name_expand() - decode a wire-format name to presentation format
 * @base: start of the message
 * @size: message length
 * @offset: offset of the name in the message
 * @out: output buffer, at least MAX_NAME_TEXT bytes
 * @capacity: output buffer size
 *
 * Follows compression pointers. Label bytes are copied as they are; only
 * "." and "\" inside a label are escaped, so the result encodes back to the
 * same wire name.
 *
 * Return: wire length of the name at @offset, or -1 if it is malformed or
 * holds a control character
 */
int mdns_name_expand(const uint8_t *base, size_t size, size_t offset,
		     char *out, size_t capacity)
{
	size_t pos = offset, used = 0, wire = 1, consumed = 0;
	unsigned int jumps = 0;

	while (pos < size) {
		unsigned int n = base[pos++];

		if (!n) {
			if (!consumed)
				consumed = pos - offset;
			out[used] = 0;
			return consumed;
		}

		if ((n & 0xc0) == 0xc0) {
			if (pos >= size || ++jumps > MAX_NAME_LEN)
				return -1;
			if (!consumed)
				consumed = pos + 1 - offset;
			pos = ((n & 0x3f) << 8) | base[pos];
			continue;
		}

		if (n > MAX_LABEL_LEN || pos + n > size)
			return -1;

		wire += n + 1;
		if (wire > MAX_NAME_LEN + 1)
			return -1;

		if (used)
			out[used++] = '.';

		for (unsigned int i = 0; i < n; i++) {
			unsigned char ch = base[pos++];

			if (used + 3 > capacity || ch < 0x20 || ch == 0x7f)
				return -1;
			if (ch == '.' || ch == '\\')
				out[used++] = '\\';
			out[used++] = ch;
		}
	}

	return -1;
}

static int utf8_next(const uint8_t *input, size_t length, size_t *pos, uint32_t *code)
{
	unsigned int lead = input[(*pos)++], extra;
	uint32_t minimum;

	if (lead < 0x80) {
		*code = lead;
		return 0;
	}

	if (lead >= 0xc2 && lead <= 0xdf) {
		*code = lead & 0x1f;
		extra = 1;
		minimum = 0x80;
	} else if (lead >= 0xe0 && lead <= 0xef) {
		*code = lead & 0xf;
		extra = 2;
		minimum = 0x800;
	} else if (lead >= 0xf0 && lead <= 0xf4) {
		*code = lead & 7;
		extra = 3;
		minimum = 0x10000;
	} else {
		return -1;
	}

	if (*pos + extra > length)
		return -1;

	while (extra--) {
		if ((input[*pos] & 0xc0) != 0x80)
			return -1;

		*code = (*code << 6) | (input[(*pos)++] & 0x3f);
	}

	if (*code < minimum || *code > 0x10ffff || (*code >= 0xd800 && *code <= 0xdfff))
		return -1;

	return 0;
}

/**
 * mdns_utf8_valid() - check that bytes are well-formed UTF-8 text
 * @input: bytes to check
 * @length: number of bytes
 *
 * Rejects overlong forms, surrogates, scalar values above U+10FFFF and the
 * C1 control characters U+0080 to U+009F.
 *
 * Return: true if @input is well-formed UTF-8 without C1 controls
 */
bool mdns_utf8_valid(const uint8_t *input, size_t length)
{
	uint32_t code;

	for (size_t pos = 0; pos < length;) {
		if (utf8_next(input, length, &pos, &code) < 0 ||
		    (code >= 0x80 && code <= 0x9f))
			return false;
	}

	return true;
}

/**
 * mdns_name_encode() - encode a name for transmission in wire format
 * @name: presentation-format name
 * @out: output buffer
 * @size: output buffer size
 *
 * RFC 6762 Section 16: names are sent as UTF-8. Like mdns_name_wire(), but
 * every label must also be well-formed UTF-8 without C1 controls.
 *
 * Return: wire length including the root label, or -1 if the name is invalid
 */
int mdns_name_encode(const char *name, uint8_t *out, size_t size)
{
	int len = name_parse(name, out, size);

	if (len < 0)
		return -1;

	for (int pos = 0; out[pos]; pos += out[pos] + 1) {
		if (!mdns_utf8_valid(out + pos + 1, out[pos]))
			return -1;
	}

	return len;
}

/**
 * mdns_name_prepare() - check a name for transmission
 * @name: presentation-format name
 * @out: output buffer, at least MAX_NAME_TEXT bytes
 * @capacity: output buffer size
 *
 * The name must pass mdns_name_encode(). The result has the minimal escaping
 * of mdns_name_expand(); letter case is kept.
 *
 * Return: 0 on success, -1 if the name is not valid UTF-8 or too long
 */
int mdns_name_prepare(const char *name, char *out, size_t capacity)
{
	uint8_t wire[MAX_NAME_LEN + 1];
	int len = mdns_name_encode(name, wire, sizeof(wire));

	if (len < 0)
		return -1;

	return mdns_name_expand(wire, len, 0, out, capacity) < 0 ? -1 : 0;
}

/**
 * mdns_name_canonical() - reduce a name to its canonical comparison form
 * @name: presentation-format name
 * @out: output buffer, at least MAX_NAME_TEXT bytes
 * @capacity: output buffer size
 *
 * RFC 6762 Section 16: names compare case-insensitively for ASCII letters and
 * byte by byte otherwise. The result has ASCII letters in lower case, no
 * trailing dot and the minimal escaping of mdns_name_expand().
 *
 * Return: 0 on success, -1 if the name is invalid
 */
int mdns_name_canonical(const char *name, char *out, size_t capacity)
{
	uint8_t wire[MAX_NAME_LEN + 1];
	int len = mdns_name_encode(name, wire, sizeof(wire));

	if (len < 0)
		return -1;

	for (int pos = 0; wire[pos]; pos += wire[pos] + 1) {
		for (int i = 1; i <= wire[pos]; i++)
			wire[pos + i] = mdns_ascii_lower(wire[pos + i]);
	}

	return mdns_name_expand(wire, len, 0, out, capacity) < 0 ? -1 : 0;
}

/**
 * mdns_name_suffix_equal() - compare a name in a message with a wire name
 * @base: start of the message
 * @size: bytes of the message written so far
 * @offset: offset of the name in the message
 * @wire: uncompressed wire name
 *
 * Return: true if both names are equal, ignoring ASCII case
 */
bool mdns_name_suffix_equal(const uint8_t *base, size_t size, size_t offset,
			    const uint8_t *wire)
{
	unsigned int jumps = 0;

	while (offset < size) {
		unsigned int n = base[offset];

		if ((n & 0xc0) == 0xc0) {
			if (offset + 1 >= size || ++jumps > MAX_NAME_LEN)
				return false;
			offset = ((n & 0x3f) << 8) | base[offset + 1];
			continue;
		}

		if (n != *wire)
			return false;
		if (!n)
			return true;
		if (offset + n >= size)
			return false;

		for (unsigned int i = 1; i <= n; i++) {
			if (mdns_ascii_lower(base[offset + i]) != mdns_ascii_lower(wire[i]))
				return false;
		}

		offset += n + 1;
		wire += n + 1;
	}

	return false;
}
