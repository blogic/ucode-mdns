/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <libubox/ulog.h>

#include "mdns.h"

/**
 * struct packet_builder - context for assembling DNS packet
 * @data: output buffer
 * @size: buffer size
 * @limit: write ceiling, normally the soft size but raised for a lone record
 * @overflow: the last failure was want of space, not a malformed item
 * @pos: current write position
 * @ptrs: dn_comp() name pointer list; first entry is the message base,
 *        further entries are maintained by dn_comp() itself
 */
struct packet_builder {
	uint8_t *data;
	size_t size;
	size_t limit;
	size_t pos;
	bool legacy;
	bool overflow;
	uint8_t *ptrs[256];
};

/**
 * builder_init() - initialise packet builder
 * @pb: builder context
 * @buffer: output buffer
 * @size: buffer size
 * @limit: initial write ceiling
 */
static void builder_init(struct packet_builder *pb, uint8_t *buffer, size_t size, size_t limit)
{
	memset(pb, 0, sizeof(*pb));
	pb->data = buffer;
	pb->size = size;
	pb->limit = limit;
	pb->ptrs[0] = buffer;
}

/**
 * builder_ptrs_used() - count the name pointers dn_comp() recorded
 * @pb: builder context
 *
 * Return: number of entries in use
 */
static size_t builder_ptrs_used(struct packet_builder *pb)
{
	size_t n = 0;

	while (n < ARRAY_SIZE(pb->ptrs) && pb->ptrs[n])
		n++;

	return n;
}

/**
 * builder_rollback() - undo a partly written item
 * @pb: builder context
 * @pos: write position to return to
 * @ptrs: name pointer count to return to
 *
 * Drops the name pointers dn_comp() recorded for the discarded bytes, so a
 * later name never compresses against a part of the packet that is gone.
 */
static void builder_rollback(struct packet_builder *pb, size_t pos, size_t ptrs)
{
	pb->pos = pos;

	if (ptrs < ARRAY_SIZE(pb->ptrs))
		pb->ptrs[ptrs] = NULL;
}

/**
 * builder_append() - append raw data to packet
 * @pb: builder context
 * @data: data to append
 * @len: data length
 *
 * Return: 0 on success, -1 if buffer full
 */
static int builder_append(struct packet_builder *pb, const void *data, size_t len)
{
	if (pb->pos + len > pb->limit) {
		pb->overflow = true;
		mdns_set_error("Packet buffer exhausted");
		return -1;
	}

	memcpy(pb->data + pb->pos, data, len);
	pb->pos += len;
	return 0;
}

/**
 * builder_append_name() - append DNS name with compression
 * @pb: builder context
 * @name: domain name to encode
 *
 * Uses dn_comp() for name compression against previously encoded names.
 *
 * Return: 0 on success, -1 on error
 */
static int builder_append_name(struct packet_builder *pb, const char *name)
{
	int len;

	/* Encode directly into the packet so dn_comp() records name
	 * locations relative to the message base in pb->ptrs[0] */
	len = dn_comp(name, pb->data + pb->pos, pb->limit - pb->pos,
		      (unsigned char **)pb->ptrs,
		      (unsigned char **)(pb->ptrs + ARRAY_SIZE(pb->ptrs)));
	if (len < 0) {
		uint8_t scratch[MAX_NAME_LEN + 1];

		/* dn_comp() reports a name it cannot encode and a buffer with
		 * no room the same way. Encode into a full sized scratch to
		 * tell them apart, so a packet that is merely full splits
		 * instead of rejecting a valid record. */
		if (dn_comp(name, scratch, sizeof(scratch), NULL, NULL) >= 0)
			pb->overflow = true;
		else
			mdns_set_error("Failed to encode name: %s", name);

		return -1;
	}

	pb->pos += len;

	return 0;
}

/**
 * builder_append_name_raw() - append DNS name without compression
 * @pb: builder context
 * @name: domain name to encode
 *
 * RFC 6762 Section 18.14 forbids compressing the SRV target in a legacy
 * unicast response, because resolvers predating RFC 2782 mis-parse it.
 *
 * Return: 0 on success, -1 on error
 */
static int builder_append_name_raw(struct packet_builder *pb, const char *name)
{
	uint8_t encoded[MAX_NAME_LEN + 1];
	int len;

	len = dn_comp(name, encoded, sizeof(encoded), NULL, NULL);
	if (len < 0) {
		mdns_set_error("Failed to encode name: %s", name);
		return -1;
	}

	return builder_append(pb, encoded, len);
}

/**
 * builder_append_u16() - append 16-bit value in network byte order
 * @pb: builder context
 * @val: value to append
 *
 * Return: 0 on success, -1 if buffer full
 */
static int builder_append_u16(struct packet_builder *pb, uint16_t val)
{
	uint16_t nval = htons(val);
	return builder_append(pb, &nval, sizeof(nval));
}

/**
 * builder_append_u32() - append 32-bit value in network byte order
 * @pb: builder context
 * @val: value to append
 *
 * Return: 0 on success, -1 if buffer full
 */
static int builder_append_u32(struct packet_builder *pb, uint32_t val)
{
	uint32_t nval = htonl(val);
	return builder_append(pb, &nval, sizeof(nval));
}

/**
 * build_question() - build DNS question from ucode object
 * @pb: builder context
 * @q: ucode question object
 *
 * Encodes question name, type, class, and unicast-response flag.
 *
 * Return: 0 on success, -1 on error
 */
/**
 * resolve_type() - resolve a ucode type value to a DNS type
 * @val: ucode value, a type name or a numeric type, may be NULL
 * @out: resolved type
 *
 * Return: 0 on success, -1 on error
 */
static int resolve_type(uc_value_t *val, uint16_t *out)
{
	int type_val;

	if (!val) {
		*out = DNS_TYPE_A;
		return 0;
	}

	if (ucv_type(val) == UC_INTEGER) {
		int64_t n = ucv_int64_get(val);

		if (n < 0 || n > 0xffff) {
			mdns_set_error("Type out of range: %" PRId64, n);
			return -1;
		}

		*out = (uint16_t)n;
		return 0;
	}

	if (ucv_type(val) != UC_STRING) {
		mdns_set_error("Type must be a string or an integer");
		return -1;
	}

	type_val = mdns_string_to_type(ucv_string_get(val));
	if (type_val < 0) {
		mdns_set_error("Invalid type: %s", ucv_string_get(val));
		return -1;
	}

	*out = (uint16_t)type_val;

	return 0;
}

/**
 * resolve_class() - resolve a ucode class value to a DNS class
 * @val: ucode value, a class name or a numeric class, may be NULL
 * @out: resolved class
 *
 * Return: 0 on success, -1 on error
 */
static int resolve_class(uc_value_t *val, uint16_t *out)
{
	const char *str;

	if (!val) {
		*out = DNS_CLASS_IN;
		return 0;
	}

	if (ucv_type(val) == UC_INTEGER) {
		int64_t n = ucv_int64_get(val);

		if (n != DNS_CLASS_IN && n != DNS_CLASS_ANY) {
			mdns_set_error("Invalid class: %" PRId64, n);
			return -1;
		}

		*out = (uint16_t)n;
		return 0;
	}

	if (ucv_type(val) != UC_STRING) {
		mdns_set_error("Class must be a string or an integer");
		return -1;
	}

	str = ucv_string_get(val);

	if (strcasecmp(str, "IN") == 0)
		*out = DNS_CLASS_IN;
	else if (strcasecmp(str, "ANY") == 0)
		*out = DNS_CLASS_ANY;
	else {
		mdns_set_error("Invalid class: %s", str);
		return -1;
	}

	return 0;
}

static int build_question(struct packet_builder *pb, uc_value_t *q)
{
	uc_value_t *name, *type, *class, *unicast;
	uint16_t type_val, class_val;

	name = ucv_object_get(q, "name", NULL);
	type = ucv_object_get(q, "type", NULL);
	class = ucv_object_get(q, "class", NULL);
	unicast = ucv_object_get(q, "unicast_response", NULL);

	if (!name || ucv_type(name) != UC_STRING) {
		mdns_set_error("Question missing name");
		return -1;
	}

	if (builder_append_name(pb, ucv_string_get(name)) < 0)
		return -1;

	if (resolve_type(type, &type_val) < 0)
		return -1;

	if (resolve_class(class, &class_val) < 0)
		return -1;

	if (unicast && ucv_is_truish(unicast))
		class_val |= DNS_CLASS_UNICAST;

	if (builder_append_u16(pb, type_val) < 0)
		return -1;
	if (builder_append_u16(pb, class_val) < 0)
		return -1;

	return 0;
}

/**
 * build_rdata_a() - build A record rdata from ucode object
 * @pb: builder context
 * @rdata: ucode rdata object with "address" field
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_a(struct packet_builder *pb, uc_value_t *rdata)
{
	uc_value_t *addr_obj;
	const char *addr_str;
	struct in_addr addr;

	addr_obj = ucv_object_get(rdata, "address", NULL);
	if (!addr_obj || ucv_type(addr_obj) != UC_STRING) {
		mdns_set_error("A record missing address");
		return -1;
	}

	addr_str = ucv_string_get(addr_obj);
	if (inet_pton(AF_INET, addr_str, &addr) != 1) {
		mdns_set_error("Invalid IPv4 address: %s", addr_str);
		return -1;
	}

	return builder_append(pb, &addr, 4);
}

/**
 * build_rdata_aaaa() - build AAAA record rdata from ucode object
 * @pb: builder context
 * @rdata: ucode rdata object with "address" field
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_aaaa(struct packet_builder *pb, uc_value_t *rdata)
{
	uc_value_t *addr_obj;
	const char *addr_str;
	struct in6_addr addr;

	addr_obj = ucv_object_get(rdata, "address", NULL);
	if (!addr_obj || ucv_type(addr_obj) != UC_STRING) {
		mdns_set_error("AAAA record missing address");
		return -1;
	}

	addr_str = ucv_string_get(addr_obj);
	if (inet_pton(AF_INET6, addr_str, &addr) != 1) {
		mdns_set_error("Invalid IPv6 address: %s", addr_str);
		return -1;
	}

	return builder_append(pb, &addr, 16);
}

/**
 * build_rdata_name() - build PTR/CNAME record rdata from ucode object
 * @pb: builder context
 * @rdata: ucode rdata object
 * @field: field name to extract ("ptr" or "cname")
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_name(struct packet_builder *pb, uc_value_t *rdata, const char *field)
{
	uc_value_t *name_obj;
	const char *name;

	name_obj = ucv_object_get(rdata, field, NULL);
	if (!name_obj || ucv_type(name_obj) != UC_STRING) {
		mdns_set_error("%s record missing %s", field, field);
		return -1;
	}

	name = ucv_string_get(name_obj);
	return builder_append_name(pb, name);
}

/**
 * build_rdata_srv() - build SRV record rdata from ucode object
 * @pb: builder context
 * @rdata: ucode rdata object with priority, weight, port, target fields
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_srv(struct packet_builder *pb, uc_value_t *rdata)
{
	uc_value_t *priority, *weight, *port, *target;
	struct dns_srv_data srv;

	priority = ucv_object_get(rdata, "priority", NULL);
	weight = ucv_object_get(rdata, "weight", NULL);
	port = ucv_object_get(rdata, "port", NULL);
	target = ucv_object_get(rdata, "target", NULL);

	if (!priority || !weight || !port || !target) {
		mdns_set_error("SRV record missing fields");
		return -1;
	}

	if (ucv_type(target) != UC_STRING) {
		mdns_set_error("SRV target must be a string");
		return -1;
	}

	srv.priority = htons(ucv_int64_get(priority));
	srv.weight = htons(ucv_int64_get(weight));
	srv.port = htons(ucv_int64_get(port));

	if (builder_append(pb, &srv, sizeof(srv)) < 0)
		return -1;

	if (pb->legacy)
		return builder_append_name_raw(pb, ucv_string_get(target));

	return builder_append_name(pb, ucv_string_get(target));
}

/**
 * build_rdata_txt() - build TXT record rdata from ucode object
 * @pb: builder context
 * @rdata: ucode rdata object with "strings" array field
 *
 * Encodes length-prefixed text strings.
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_txt(struct packet_builder *pb, uc_value_t *rdata)
{
	uc_value_t *txt_obj, *str;
	size_t i, len;

	txt_obj = ucv_object_get(rdata, "strings", NULL);
	if (!txt_obj || ucv_type(txt_obj) != UC_ARRAY) {
		mdns_set_error("TXT record missing strings array");
		return -1;
	}

	for (i = 0; i < ucv_array_length(txt_obj); i++) {
		str = ucv_array_get(txt_obj, i);
		if (!str || ucv_type(str) != UC_STRING) {
			mdns_set_error("TXT record contains non-string");
			return -1;
		}

		len = ucv_string_length(str);
		if (len > 255) {
			mdns_set_error("TXT string too long: %zu", len);
			return -1;
		}

		uint8_t len_byte = len;
		if (builder_append(pb, &len_byte, 1) < 0)
			return -1;
		if (builder_append(pb, ucv_string_get(str), len) < 0)
			return -1;
	}

	return 0;
}

/**
 * build_rdata_raw() - build raw rdata from hex string
 * @pb: builder context
 * @rdata: ucode rdata object with "raw" hex string field
 *
 * Decodes hex string and appends raw bytes.
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata_raw(struct packet_builder *pb, uc_value_t *rdata)
{
	uc_value_t *raw_obj;
	const char *hex;
	size_t hex_len, i;
	uint8_t *bytes;

	raw_obj = ucv_object_get(rdata, "raw", NULL);
	if (!raw_obj || ucv_type(raw_obj) != UC_STRING) {
		mdns_set_error("Raw rdata missing raw hex string");
		return -1;
	}

	hex = ucv_string_get(raw_obj);
	hex_len = ucv_string_length(raw_obj);

	if (hex_len % 2 != 0) {
		mdns_set_error("Raw hex string must have even length");
		return -1;
	}

	bytes = malloc(hex_len / 2);
	if (!bytes) {
		mdns_set_error("Memory allocation failed");
		return -1;
	}

	for (i = 0; i < hex_len / 2; i++) {
		unsigned int byte;
		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			free(bytes);
			mdns_set_error("Invalid hex string");
			return -1;
		}
		bytes[i] = byte;
	}

	int ret = builder_append(pb, bytes, hex_len / 2);
	free(bytes);
	return ret;
}

/**
 * build_rdata() - encode the rdata of one record
 * @pb: builder context
 * @type_val: DNS record type
 * @rdata: ucode rdata object
 *
 * Return: 0 on success, -1 on error
 */
static int build_rdata(struct packet_builder *pb, uint16_t type_val, uc_value_t *rdata)
{
	switch (type_val) {
	case DNS_TYPE_A:
		return build_rdata_a(pb, rdata);

	case DNS_TYPE_AAAA:
		return build_rdata_aaaa(pb, rdata);

	case DNS_TYPE_PTR:
		return build_rdata_name(pb, rdata, "ptr");

	case DNS_TYPE_CNAME:
		return build_rdata_name(pb, rdata, "cname");

	case DNS_TYPE_SRV:
		return build_rdata_srv(pb, rdata);

	case DNS_TYPE_TXT:
		return build_rdata_txt(pb, rdata);

	case DNS_TYPE_NSEC:
		return build_rdata_raw(pb, rdata);

	default:
		mdns_set_error("Unsupported record type for assembly: %s",
			       mdns_type_to_string(type_val));
		return -1;
	}
}

/**
 * mdns_rdata_encode() - encode a record's rdata on its own
 * @rec: ucode record object with type and rdata
 * @buf: output buffer
 * @size: size of @buf
 *
 * RFC 6762 Section 8.2 compares proposed records by their raw rdata with any
 * names uncompressed. The builder starts empty, so no name has an earlier
 * occurrence to point at and the output is always uncompressed.
 *
 * Return: number of bytes written, or -1 on error
 */
int mdns_rdata_encode(uc_value_t *rec, uint8_t *buf, size_t size)
{
	struct packet_builder pb;
	uc_value_t *rdata = ucv_object_get(rec, "rdata", NULL);
	uint16_t type_val;

	builder_init(&pb, buf, size, size);

	if (resolve_type(ucv_object_get(rec, "type", NULL), &type_val) < 0)
		return -1;

	if (!rdata || ucv_type(rdata) != UC_OBJECT) {
		mdns_set_error("Record missing rdata");
		return -1;
	}

	if (build_rdata(&pb, type_val, rdata) < 0)
		return -1;

	return (int)pb.pos;
}

/**
 * build_record() - build DNS resource record from ucode object
 * @pb: builder context
 * @rec: ucode record object
 *
 * Encodes record name, type, class, TTL, flush-cache flag, and type-specific rdata.
 *
 * Return: 0 on success, -1 on error
 */
static int build_record(struct packet_builder *pb, uc_value_t *rec)
{
	uc_value_t *name, *type, *class, *ttl, *flush, *rdata;
	uint16_t type_val, class_val;
	uint32_t ttl_val;
	size_t rdlength_pos, rdata_start, rdata_len;

	name = ucv_object_get(rec, "name", NULL);
	type = ucv_object_get(rec, "type", NULL);
	class = ucv_object_get(rec, "class", NULL);
	ttl = ucv_object_get(rec, "ttl", NULL);
	flush = ucv_object_get(rec, "flush_cache", NULL);
	rdata = ucv_object_get(rec, "rdata", NULL);

	if (!name || ucv_type(name) != UC_STRING) {
		mdns_set_error("Record missing name");
		return -1;
	}

	if (builder_append_name(pb, ucv_string_get(name)) < 0)
		return -1;

	if (resolve_type(type, &type_val) < 0)
		return -1;

	if (resolve_class(class, &class_val) < 0)
		return -1;

	if (flush && ucv_is_truish(flush))
		class_val |= DNS_CLASS_FLUSH;

	ttl_val = ttl ? ucv_int64_get(ttl) : 120;

	if (builder_append_u16(pb, type_val) < 0)
		return -1;
	if (builder_append_u16(pb, class_val) < 0)
		return -1;
	if (builder_append_u32(pb, ttl_val) < 0)
		return -1;

	rdlength_pos = pb->pos;
	if (builder_append_u16(pb, 0) < 0)
		return -1;

	rdata_start = pb->pos;

	if (!rdata || ucv_type(rdata) != UC_OBJECT) {
		mdns_set_error("Record missing rdata");
		return -1;
	}

	if (build_rdata(pb, type_val, rdata) < 0)
		return -1;

	rdata_len = pb->pos - rdata_start;
	if (rdata_len > 0xffff) {
		mdns_set_error("RDATA too large");
		return -1;
	}

	uint16_t rdata_len_net = htons(rdata_len);
	memcpy(pb->data + rdlength_pos, &rdata_len_net, sizeof(rdata_len_net));

	return 0;
}

/* build_section() outcomes beyond success */
#define BUILD_FULL	-1
#define BUILD_ERROR	-2

/**
 * section_length() - number of items in a packet section
 * @arr: ucode array, or anything else for an absent section
 *
 * Return: item count
 */
static size_t section_length(uc_value_t *arr)
{
	if (!arr || ucv_type(arr) != UC_ARRAY)
		return 0;

	return ucv_array_length(arr);
}

/**
 * build_section() - append as many items of one section as the packet holds
 * @pb: builder context
 * @arr: ucode array holding the section
 * @n: item count in @arr
 * @idx: in/out cursor into @arr, left on the first item not written
 * @written: in/out count of items written to this packet
 * @question: true for the question section, false for a record section
 *
 * An item that does not fit leaves the packet unchanged and ends the packet,
 * so the caller can put it in the next one. A malformed item is the caller's
 * error and fails the whole build, because emitting a packet without it would
 * hide the fault.
 *
 * Return: 0 when the section is complete, BUILD_FULL when the packet is full,
 * BUILD_ERROR when the item cannot be encoded at all
 */
static int build_section(struct packet_builder *pb, uc_value_t *arr, size_t n,
			 size_t *idx, uint16_t *written, bool question)
{
	while (*idx < n) {
		uc_value_t *item = ucv_array_get(arr, *idx);
		size_t pos = pb->pos;
		size_t ptrs = builder_ptrs_used(pb);
		int rv;

		pb->overflow = false;

		rv = question ? build_question(pb, item) : build_record(pb, item);

		if (rv == 0) {
			(*idx)++;
			(*written)++;
			continue;
		}

		builder_rollback(pb, pos, ptrs);

		if (!pb->overflow)
			return BUILD_ERROR;

		if (pb->pos > sizeof(struct dns_header))
			return BUILD_FULL;

		/* RFC 6762 Section 17: a record larger than the MTU may travel
		 * in a packet of its own and be fragmented by IP */
		pb->limit = pb->size;
		pb->overflow = false;

		rv = question ? build_question(pb, item) : build_record(pb, item);

		if (rv < 0) {
			builder_rollback(pb, pos, ptrs);
			pb->limit = SOFT_PACKET_SIZE;
			return BUILD_ERROR;
		}

		(*idx)++;
		(*written)++;

		return BUILD_FULL;
	}

	return 0;
}

/**
 * mdns_packet_from_ucode() - convert ucode packet object to wire format
 * @val: ucode packet object
 * @buffers: output array of at least MAX_SPLIT_PACKETS allocated buffers
 * @lengths: output array of at least MAX_SPLIT_PACKETS packet lengths
 * @count: output number of packets generated
 *
 * Builds DNS packet(s) from ucode representation. Records that do not fit go
 * in further packets, except for a legacy unicast response, which RFC 6762
 * Section 18.5 says must instead carry the TC bit. Caller must free buffers.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_packet_from_ucode(uc_value_t *val, uint8_t **buffers, size_t *lengths, int *count)
{
	struct packet_builder pb;
	uint8_t *buffer;
	struct dns_header hdr, tmpl;
	uc_value_t *header, *questions, *answers, *authority, *additional;
	uc_value_t *flags, *id;
	size_t nq, na, nn, nd;
	size_t qi = 0, ai = 0, ni = 0, di = 0;
	bool legacy, remaining;

	*count = 0;

	if (!val || ucv_type(val) != UC_OBJECT) {
		mdns_set_error("packet_build requires object argument");
		return -1;
	}

	legacy = ucv_is_truish(ucv_object_get(val, "legacy", NULL));

	memset(&tmpl, 0, sizeof(tmpl));

	header = ucv_object_get(val, "header", NULL);
	if (header && ucv_type(header) == UC_OBJECT) {
		id = ucv_object_get(header, "id", NULL);
		if (id)
			tmpl.id = htons(ucv_int64_get(id));

		flags = ucv_object_get(header, "flags", NULL);
		if (flags && ucv_type(flags) == UC_OBJECT) {
			uc_value_t *flag;

			flag = ucv_object_get(flags, "response", NULL);
			if (flag && ucv_is_truish(flag))
				tmpl.flags |= htons(DNS_FLAG_RESPONSE);

			flag = ucv_object_get(flags, "authoritative", NULL);
			if (flag && ucv_is_truish(flag))
				tmpl.flags |= htons(DNS_FLAG_AUTHORITATIVE);

			flag = ucv_object_get(flags, "truncated", NULL);
			if (flag && ucv_is_truish(flag))
				tmpl.flags |= htons(DNS_FLAG_TRUNCATED);

			flag = ucv_object_get(flags, "recursion_desired", NULL);
			if (flag && ucv_is_truish(flag))
				tmpl.flags |= htons(DNS_FLAG_RD);
		}
	}

	questions = ucv_object_get(val, "questions", NULL);
	answers = ucv_object_get(val, "answers", NULL);
	authority = ucv_object_get(val, "authority", NULL);
	additional = ucv_object_get(val, "additional", NULL);

	nq = section_length(questions);
	na = section_length(answers);
	nn = section_length(authority);
	nd = section_length(additional);

	do {
		uint16_t cq = 0, ca = 0, cn = 0, cd = 0;
		int rv;

		buffer = malloc(MAX_PACKET_SIZE);
		if (!buffer) {
			mdns_set_error("Out of memory");
			goto error;
		}

		builder_init(&pb, buffer, MAX_PACKET_SIZE, SOFT_PACKET_SIZE);
		pb.legacy = legacy;

		hdr = tmpl;

		if (builder_append(&pb, &hdr, sizeof(hdr)) < 0) {
			free(buffer);
			goto error;
		}

		rv = build_section(&pb, questions, nq, &qi, &cq, true);

		if (rv != BUILD_ERROR && rv != BUILD_FULL)
			rv = build_section(&pb, answers, na, &ai, &ca, false);

		if (rv != BUILD_ERROR && rv != BUILD_FULL)
			rv = build_section(&pb, authority, nn, &ni, &cn, false);

		/* RFC 6762 Section 12: the additional records follow every
		 * section the response must carry, so they start once those
		 * are complete and spill into a further packet of their own */
		if (rv == 0 && qi == nq && ai == na && ni == nn)
			rv = build_section(&pb, additional, nd, &di, &cd, false);

		if (rv == BUILD_ERROR) {
			free(buffer);
			goto error;
		}

		remaining = qi < nq || ai < na || ni < nn || di < nd;

		hdr.questions = htons(cq);
		hdr.answers = htons(ca);
		hdr.authority = htons(cn);
		hdr.additional = htons(cd);

		/* RFC 6762 Section 18.5: the TC bit says a legacy unicast
		 * response was too large; a multicast response splits instead
		 * and MUST leave the bit zero */
		if (legacy && remaining)
			hdr.flags |= htons(DNS_FLAG_TRUNCATED);

		memcpy(buffer, &hdr, sizeof(hdr));

		buffers[*count] = buffer;
		lengths[*count] = pb.pos;
		(*count)++;

		if (legacy)
			break;
	} while (remaining && *count < MAX_SPLIT_PACKETS);

	if (remaining && !legacy)
		ulog(LOG_WARNING, "build: dropped %zu records past the %d packet limit\n",
		     (nq - qi) + (na - ai) + (nn - ni) + (nd - di),
		     MAX_SPLIT_PACKETS);

	return 0;

error:
	while (*count > 0)
		free(buffers[--*count]);

	return -1;
}
