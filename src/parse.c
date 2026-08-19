/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "mdns.h"

/**
 * scan_name_length() - calculate length of DNS name in wire format
 * @data: packet data
 * @len: packet length
 * @offset: offset to name start
 *
 * Scans DNS name to determine wire format length, handling compression pointers.
 * Does not follow compression pointers, only determines encoded length.
 *
 * Return: length in bytes, or -1 if malformed
 */
static int scan_name_length(const uint8_t *data, size_t len, size_t offset)
{
	size_t pos = offset;

	while (pos < len) {
		uint8_t label_len = data[pos];

		if (label_len == 0)
			return pos - offset + 1;

		/* Compression pointer - name ends here (2 bytes) */
		if ((label_len & 0xc0) == 0xc0) {
			if (pos + 1 >= len)
				return -1;
			return pos - offset + 2;
		}

		if (label_len > MAX_LABEL_LEN)
			return -1;

		pos += label_len + 1;
		if (pos > len)
			return -1;
	}

	return -1;
}

/**
 * parse_name() - parse and expand DNS name from wire format
 * @base: start of packet data
 * @base_len: total packet length
 * @ptr: pointer to current parse position (updated)
 * @remaining: bytes remaining in packet (updated)
 *
 * Parses DNS name using dn_expand() for compression handling.
 * Advances parse position past name in wire format.
 *
 * Return: allocated string with expanded name, or NULL on error
 */
/**
 * name_is_valid() - reject a name that cannot be represented or compared
 * @name: presentation-format name from dn_expand()
 *
 * musl copies label bytes verbatim, with no escaping. A NUL truncates the name
 * at strdup(), a control character reaches the log and the ubus output as-is,
 * and a byte sequence that is not UTF-8 corrupts the JSON a consumer parses.
 * RFC 6763 Section 4.1.1 requires the names this daemon handles to be UTF-8.
 *
 * Return: true if the name is usable
 */
static bool name_is_valid(const char *name, size_t len)
{
	size_t i = 0;

	while (i < len) {
		uint8_t ch = (uint8_t)name[i];
		int extra;

		if (ch < 0x20 || ch == 0x7f)
			return false;

		if (ch < 0x80) {
			i++;
			continue;
		}

		if ((ch & 0xe0) == 0xc0)
			extra = 1;
		else if ((ch & 0xf0) == 0xe0)
			extra = 2;
		else if ((ch & 0xf8) == 0xf0)
			extra = 3;
		else
			return false;

		if (i + extra >= len)
			return false;

		for (int j = 1; j <= extra; j++) {
			if (((uint8_t)name[i + j] & 0xc0) != 0x80)
				return false;
		}

		i += extra + 1;
	}

	return true;
}

static char *parse_name(const uint8_t *base, size_t base_len, const uint8_t **ptr, size_t *remaining)
{
	char name_buf[MAX_NAME_LEN + 1];
	int name_len;
	int wire_len;

	wire_len = scan_name_length(base, base_len, *ptr - base);
	if (wire_len < 0) {
		mdns_set_error("Invalid DNS name");
		return NULL;
	}

	if ((size_t)wire_len > *remaining) {
		mdns_set_error("Name exceeds packet bounds");
		return NULL;
	}

	name_len = dn_expand(base, base + base_len, *ptr, name_buf, sizeof(name_buf));
	if (name_len < 0) {
		mdns_set_error("Failed to expand DNS name");
		return NULL;
	}

	if (!name_is_valid(name_buf, strlen(name_buf))) {
		mdns_set_error("DNS name is not printable UTF-8");
		return NULL;
	}

	*ptr += wire_len;
	*remaining -= wire_len;

	char *result = strdup(name_buf);
	if (!result) {
		mdns_set_error("Out of memory duplicating DNS name");
		return NULL;
	}

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
	char name_buf[MAX_NAME_LEN + 1];
	int name_len;

	name_len = dn_expand(base, base + base_len, rdata, name_buf, sizeof(name_buf));
	if (name_len < 0) {
		mdns_set_error("Failed to expand name in rdata");
		return -1;
	}

	/* The name has to fit the rdata it was declared in, or the record was
	 * assembled from bytes belonging to the record after it */
	if ((uint16_t)name_len > rdlen) {
		mdns_set_error("Name overruns its rdata");
		return -1;
	}

	if (!name_is_valid(name_buf, strlen(name_buf))) {
		mdns_set_error("Name in rdata is not printable UTF-8");
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
	char target_buf[MAX_NAME_LEN + 1];
	int name_len;

	if (rdlen < sizeof(*srv)) {
		mdns_set_error("Truncated SRV record");
		return -1;
	}

	srv = (struct dns_srv_data *)rdata;
	rec->rdata.srv.priority = ntohs(srv->priority);
	rec->rdata.srv.weight = ntohs(srv->weight);
	rec->rdata.srv.port = ntohs(srv->port);

	name_len = dn_expand(base, base + base_len, rdata + sizeof(*srv),
			     target_buf, sizeof(target_buf));
	if (name_len < 0) {
		mdns_set_error("Failed to expand SRV target");
		return -1;
	}

	if ((size_t)name_len + sizeof(*srv) > rdlen) {
		mdns_set_error("SRV target overruns its rdata");
		return -1;
	}

	if (!name_is_valid(target_buf, strlen(target_buf))) {
		mdns_set_error("SRV target is not printable UTF-8");
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

	/* Preallocate initial capacity to avoid O(n²) realloc pattern */
	strings = malloc(capacity * sizeof(char *));
	if (!strings) {
		mdns_set_error("Out of memory allocating TXT strings array");
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
		count++;
		ptr += len;
	}

	rec->rdata.txt.strings = strings;
	rec->rdata.txt.count = count;
	return 0;

error:
	for (int i = 0; i < count; i++)
		free(strings[i]);
	free(strings);
	return -1;
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
 * Return: 0 on success, -1 on error
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
			goto error;
		break;

	case DNS_TYPE_AAAA:
		if (parse_rdata_aaaa(rec, rdata, rdlen) < 0)
			goto error;
		break;

	case DNS_TYPE_PTR:
		if (parse_rdata_name(base, base_len, rdata, rdlen, &rec->rdata.ptr.name) < 0)
			goto error;
		break;

	case DNS_TYPE_CNAME:
		if (parse_rdata_name(base, base_len, rdata, rdlen, &rec->rdata.cname.name) < 0)
			goto error;
		break;

	case DNS_TYPE_SRV:
		if (parse_rdata_srv(base, base_len, rdata, rdlen, rec) < 0)
			goto error;
		break;

	case DNS_TYPE_TXT:
		if (parse_rdata_txt(rdata, rdlen, rec) < 0)
			goto error;
		break;

	default:
		rec->rdata.raw.data = malloc(rdlen);
		if (!rec->rdata.raw.data)
			goto error;
		memcpy(rec->rdata.raw.data, rdata, rdlen);
		rec->rdata.raw.len = rdlen;
		break;
	}

	return 0;

error:
	free(rec->name);
	rec->name = NULL;
	return -1;
}
