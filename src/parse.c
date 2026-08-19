/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>

#include "mdns.h"

/**
 * expand_name() - decode a name and check that it is UTF-8 text
 * @base: start of packet data
 * @base_len: total packet length
 * @start: position of the name in the packet
 * @out: output buffer, at least MAX_NAME_TEXT bytes
 * @capacity: output buffer size
 *
 * RFC 6763 Section 4.1.1 requires the names this daemon handles to be UTF-8.
 *
 * Return: wire length of the name, or -1 if it is malformed or not UTF-8
 */
static int expand_name(const uint8_t *base, size_t base_len, const uint8_t *start,
		       char *out, size_t capacity)
{
	int len = mdns_name_expand(base, base_len, start - base, out, capacity);

	if (len < 0 || !mdns_utf8_valid((const uint8_t *)out, strlen(out)))
		return -1;

	return len;
}

/**
 * parse_name() - parse and expand DNS name from wire format
 * @base: start of packet data
 * @base_len: total packet length
 * @ptr: pointer to current parse position (updated)
 * @remaining: bytes remaining in packet (updated)
 *
 * Advances parse position past name in wire format.
 *
 * Return: allocated string with expanded name, or NULL on error
 */
static char *parse_name(const uint8_t *base, size_t base_len, const uint8_t **ptr, size_t *remaining)
{
	char name_buf[MAX_NAME_TEXT];
	int wire_len = expand_name(base, base_len, *ptr, name_buf, sizeof(name_buf));
	char *result;

	if (wire_len < 0 || (size_t)wire_len > *remaining) {
		mdns_set_error("Invalid or truncated DNS name");
		return NULL;
	}

	*ptr += wire_len;
	*remaining -= wire_len;

	result = strdup(name_buf);
	if (!result)
		mdns_set_error("Out of memory duplicating DNS name");

	return result;
}

/**
 * parse_question() - parse DNS question from wire format
 * @base: start of packet data
 * @base_len: total packet length
 * @ptr: pointer to current parse position (updated)
 * @remaining: bytes remaining in packet (updated)
 * @q: output question structure
 *
 * Parses question name, type, class, and unicast-response flag.
 *
 * Return: 0 on success, -1 on error
 */
int parse_question(const uint8_t *base, size_t base_len, const uint8_t **ptr,
		   size_t *remaining, struct mdns_question *q)
{
	struct dns_question *dq;

	memset(q, 0, sizeof(*q));

	q->name = parse_name(base, base_len, ptr, remaining);
	if (!q->name)
		return -1;

	if (*remaining < sizeof(*dq)) {
		mdns_set_error("Truncated question");
		goto error;
	}

	dq = (struct dns_question *)*ptr;
	q->type = ntohs(dq->type);
	q->class = ntohs(dq->class) & ~DNS_CLASS_UNICAST;
	q->unicast_response = !!(ntohs(dq->class) & DNS_CLASS_UNICAST);

	*ptr += sizeof(*dq);
	*remaining -= sizeof(*dq);

	return 0;

error:
	free(q->name);
	q->name = NULL;
	return -1;
}

/**
 * parse_rdata_a() - parse A record rdata (IPv4 address)
 * @rec: record structure to populate
 * @rdata: rdata bytes
 * @rdlen: rdata length
 *
 * Return: 0 on success, -1 on error
 */
static int parse_rdata_a(struct mdns_record *rec, const uint8_t *rdata, uint16_t rdlen)
{
	if (rdlen != 4) {
		mdns_set_error("Invalid A record length");
		return -1;
	}

	memcpy(&rec->rdata.a.addr, rdata, 4);
	return 0;
}

/**
 * parse_rdata_aaaa() - parse AAAA record rdata (IPv6 address)
 * @rec: record structure to populate
 * @rdata: rdata bytes
 * @rdlen: rdata length
 *
 * Return: 0 on success, -1 on error
 */
static int parse_rdata_aaaa(struct mdns_record *rec, const uint8_t *rdata, uint16_t rdlen)
{
	if (rdlen != 16) {
		mdns_set_error("Invalid AAAA record length");
		return -1;
	}

	memcpy(&rec->rdata.aaaa.addr, rdata, 16);
	return 0;
}

/**
 * parse_rdata_name() - parse PTR/CNAME/NS record rdata (domain name)
 * @base: start of packet data
 * @base_len: total packet length
 * @rdata: rdata bytes
 * @rdlen: rdata length
 * @name_out: output pointer to allocated name string
 *
 * Return: 0 on success, -1 on error
 */
static int parse_rdata_name(const uint8_t *base, size_t base_len, const uint8_t *rdata,
			    uint16_t rdlen, char **name_out)
{
	char name_buf[MAX_NAME_TEXT];
	int name_len = expand_name(base, base_len, rdata, name_buf, sizeof(name_buf));
	if (name_len < 0 || name_len != rdlen) {
		mdns_set_error("Invalid name in rdata");
		return -1;
	}

	*name_out = strdup(name_buf);
	if (!*name_out) {
		mdns_set_error("Out of memory duplicating name in rdata");
		return -1;
	}

	return 0;
}

/**
 * parse_rdata_srv() - parse SRV record rdata (service location)
 * @base: start of packet data
 * @base_len: total packet length
 * @rdata: rdata bytes
 * @rdlen: rdata length
 * @rec: record structure to populate
 *
 * Parses priority, weight, port, and target hostname.
 *
 * Return: 0 on success, -1 on error
 */
static int parse_rdata_srv(const uint8_t *base, size_t base_len, const uint8_t *rdata,
			   uint16_t rdlen, struct mdns_record *rec)
{
	struct dns_srv_data *srv;
	char target_buf[MAX_NAME_TEXT];
	int name_len;

	if (rdlen < sizeof(*srv)) {
		mdns_set_error("Truncated SRV record");
		return -1;
	}

	srv = (struct dns_srv_data *)rdata;
	rec->rdata.srv.priority = ntohs(srv->priority);
	rec->rdata.srv.weight = ntohs(srv->weight);
	rec->rdata.srv.port = ntohs(srv->port);

	name_len = expand_name(base, base_len, rdata + sizeof(*srv), target_buf, sizeof(target_buf));
	if (name_len < 0 || (size_t)name_len + sizeof(*srv) != rdlen) {
		mdns_set_error("Invalid SRV target");
		return -1;
	}

	rec->rdata.srv.target = strdup(target_buf);
	if (!rec->rdata.srv.target) {
		mdns_set_error("Out of memory duplicating SRV target");
		return -1;
	}

	return 0;
}

/**
 * parse_rdata_txt() - parse TXT record rdata (text strings)
 * @rdata: rdata bytes
 * @rdlen: rdata length
 * @rec: record structure to populate
 *
 * Parses length-prefixed text strings into array.
 *
 * Return: 0 on success, -1 on error
 */
static int parse_rdata_txt(const uint8_t *rdata, uint16_t rdlen, struct mdns_record *rec)
{
	const uint8_t *ptr = rdata;
	const uint8_t *end = rdata + rdlen;
	int count = 0;
	int capacity = 16;
	char **strings = NULL;
	uint8_t *lengths = NULL;

	/* Preallocate initial capacity to avoid O(n²) realloc pattern */
	strings = malloc(capacity * sizeof(char *));
	if (!strings) {
		mdns_set_error("Out of memory allocating TXT strings array");
		return -1;
	}
	lengths = malloc(MAX_TXT_STRINGS * sizeof(*lengths));
	if (!lengths) {
		free(strings);
		mdns_set_error("Out of memory allocating TXT lengths");
		return -1;
	}

	while (ptr < end) {
		uint8_t len = *ptr++;
		if (ptr + len > end) {
			mdns_set_error("Invalid TXT record");
			goto error;
		}

		/* DoS prevention: limit number of TXT strings */
		if (count >= MAX_TXT_STRINGS) {
			mdns_set_error("Too many TXT strings (max %d)", MAX_TXT_STRINGS);
			goto error;
		}

		/* Grow array exponentially when full (O(n log n) instead of O(n²)) */
		if (count >= capacity) {
			capacity *= 2;
			char **tmp = realloc(strings, capacity * sizeof(char *));
			if (!tmp) {
				mdns_set_error("Out of memory growing TXT strings array");
				goto error;
			}
			strings = tmp;
		}

		strings[count] = malloc(len + 1);
		if (!strings[count])
			goto error;

		memcpy(strings[count], ptr, len);
		strings[count][len] = '\0';
		lengths[count] = len;
		count++;
		ptr += len;
	}

	rec->rdata.txt.strings = strings;
	rec->rdata.txt.lengths = lengths;
	rec->rdata.txt.count = count;
	return 0;

error:
	for (int i = 0; i < count; i++)
		free(strings[i]);
	free(strings);
	free(lengths);
	return -1;
}

static void rdata_layout(uint16_t type, unsigned int *prefix, unsigned int *names,
			 unsigned int *suffix)
{
	*prefix = 0;
	*names = 1;
	*suffix = 0;

	switch (type) {
	case DNS_TYPE_SOA:
		*names = 2;
		*suffix = SOA_FIELDS_LEN;
		break;
	case DNS_TYPE_MX:
	case DNS_TYPE_AFSDB:
	case DNS_TYPE_RT:
	case DNS_TYPE_KX:
		*prefix = 2;
		break;
	case DNS_TYPE_RP:
		*names = 2;
		break;
	case DNS_TYPE_PX:
		*prefix = 2;
		*names = 2;
		break;
	}
}

static bool rdata_has_names(uint16_t type)
{
	switch (type) {
	case DNS_TYPE_NS:
	case DNS_TYPE_CNAME:
	case DNS_TYPE_SOA:
	case DNS_TYPE_PTR:
	case DNS_TYPE_MX:
	case DNS_TYPE_RP:
	case DNS_TYPE_AFSDB:
	case DNS_TYPE_RT:
	case DNS_TYPE_PX:
	case DNS_TYPE_KX:
	case DNS_TYPE_DNAME:
	case DNS_TYPE_NSEC:
		return true;
	}

	return false;
}

/**
 * mdns_rdata_fold() - lower-case the names embedded in uncompressed rdata
 * @type: record type
 * @data: rdata with every name uncompressed
 * @len: rdata length
 *
 * RFC 6762 Section 16: names compare case-insensitively for ASCII letters.
 * Names in the rdata of the Section 18.14 types are folded so that two
 * records differing only in that case compare equal. Other types are left
 * as they are.
 *
 * Return: 0 on success, -1 if the rdata does not match its layout
 */
int mdns_rdata_fold(uint16_t type, uint8_t *data, size_t len)
{
	unsigned int prefix, names, suffix;
	size_t pos;

	if (!rdata_has_names(type))
		return 0;

	rdata_layout(type, &prefix, &names, &suffix);
	pos = prefix;

	for (unsigned int i = 0; i < names; i++) {
		while (pos < len && data[pos]) {
			size_t label = data[pos];

			if (label > MAX_LABEL_LEN || pos + 1 + label > len)
				return -1;

			for (size_t j = pos + 1; j <= pos + label; j++)
				data[j] = mdns_ascii_lower(data[j]);

			pos += label + 1;
		}

		if (pos >= len)
			return -1;

		pos++;
	}

	return 0;
}

/**
 * parse_rdata_names() - decode rdata that embeds compressed names
 * @base: start of packet data
 * @base_len: total packet length
 * @rdata: rdata bytes
 * @rdlen: rdata length
 * @rec: record structure to populate
 *
 * RFC 6762 Section 18.14 allows compression in the rdata of these types. The
 * names are stored uncompressed, so the rdata no longer depends on the packet
 * it came in; every other field is kept as it is.
 *
 * Return: 0 on success, -1 if the rdata does not match its layout
 */
static int parse_rdata_names(const uint8_t *base, size_t base_len, const uint8_t *rdata,
			     uint16_t rdlen, struct mdns_record *rec)
{
	unsigned int prefix, names, suffix;
	uint8_t output[MAX_PACKET_SIZE];
	size_t used, remaining = rdlen;

	rdata_layout(rec->type, &prefix, &names, &suffix);

	if (remaining < prefix) {
		mdns_set_error("Truncated rdata");
		return -1;
	}

	memcpy(output, rdata, prefix);
	used = prefix;
	rdata += prefix;
	remaining -= prefix;

	for (unsigned int i = 0; i < names; i++) {
		char name[MAX_NAME_TEXT];
		int consumed = expand_name(base, base_len, rdata, name, sizeof(name));
		int encoded;

		if (consumed < 0 || (size_t)consumed > remaining) {
			mdns_set_error("Invalid name in rdata");
			return -1;
		}

		encoded = mdns_name_wire(name, output + used, sizeof(output) - used);
		if (encoded < 0) {
			mdns_set_error("Name in rdata does not fit");
			return -1;
		}

		used += encoded;
		rdata += consumed;
		remaining -= consumed;
	}

	if ((rec->type != DNS_TYPE_NSEC && remaining != suffix) ||
	    used + remaining > sizeof(output)) {
		mdns_set_error("Invalid rdata length");
		return -1;
	}

	memcpy(output + used, rdata, remaining);
	used += remaining;

	rec->rdata.raw.data = malloc(used);
	if (!rec->rdata.raw.data) {
		mdns_set_error("Out of memory copying rdata");
		return -1;
	}

	memcpy(rec->rdata.raw.data, output, used);
	rec->rdata.raw.len = used;
	return 0;
}

/**
 * parse_record() - parse DNS resource record from wire format
 * @base: start of packet data
 * @base_len: total packet length
 * @ptr: pointer to current parse position (updated)
 * @remaining: bytes remaining in packet (updated)
 * @rec: output record structure
 *
 * Parses record name, type, class, TTL, flush-cache flag, and type-specific rdata.
 *
 * Return: 0 on success, 1 if the record was consumed but its rdata is invalid,
 * -1 if the parse position is lost
 */
int parse_record(const uint8_t *base, size_t base_len, const uint8_t **ptr,
		 size_t *remaining, struct mdns_record *rec)
{
	struct dns_answer *ans;
	const uint8_t *rdata;
	uint16_t rdlen;

	memset(rec, 0, sizeof(*rec));

	rec->name = parse_name(base, base_len, ptr, remaining);
	if (!rec->name)
		return -1;

	if (*remaining < sizeof(*ans)) {
		mdns_set_error("Truncated answer");
		goto error;
	}

	ans = (struct dns_answer *)*ptr;
	rec->type = ntohs(ans->type);
	rec->class = ntohs(ans->class) & ~DNS_CLASS_FLUSH;
	rec->flush_cache = !!(ntohs(ans->class) & DNS_CLASS_FLUSH);
	rec->ttl = ntohl(ans->ttl);
	rdlen = ntohs(ans->rdlength);

	*ptr += sizeof(*ans);
	*remaining -= sizeof(*ans);

	if (*remaining < rdlen) {
		mdns_set_error("Truncated rdata");
		goto error;
	}

	rdata = *ptr;
	*ptr += rdlen;
	*remaining -= rdlen;

	/* Parse type-specific rdata */
	switch (rec->type) {
	case DNS_TYPE_A:
		if (parse_rdata_a(rec, rdata, rdlen) < 0)
			goto skip;
		break;

	case DNS_TYPE_AAAA:
		if (parse_rdata_aaaa(rec, rdata, rdlen) < 0)
			goto skip;
		break;

	case DNS_TYPE_PTR:
		if (parse_rdata_name(base, base_len, rdata, rdlen, &rec->rdata.ptr.name) < 0)
			goto skip;
		break;

	case DNS_TYPE_CNAME:
		if (parse_rdata_name(base, base_len, rdata, rdlen, &rec->rdata.cname.name) < 0)
			goto skip;
		break;

	case DNS_TYPE_SRV:
		if (parse_rdata_srv(base, base_len, rdata, rdlen, rec) < 0)
			goto skip;
		break;

	case DNS_TYPE_TXT:
		if (parse_rdata_txt(rdata, rdlen, rec) < 0)
			goto skip;
		break;

	default:
		if (rdata_has_names(rec->type)) {
			if (parse_rdata_names(base, base_len, rdata, rdlen, rec) < 0)
				goto skip;
			break;
		}

		rec->rdata.raw.data = malloc(rdlen);
		if (!rec->rdata.raw.data)
			goto skip;
		memcpy(rec->rdata.raw.data, rdata, rdlen);
		rec->rdata.raw.len = rdlen;
		break;
	}

	return 0;

skip:
	mdns_debug("Skipping record %s type %u: %s\n", rec->name, rec->type, ctx.error);
	free(rec->name);
	rec->name = NULL;
	return 1;

error:
	free(rec->name);
	rec->name = NULL;
	return -1;
}
