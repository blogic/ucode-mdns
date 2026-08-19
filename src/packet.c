/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "mdns.h"

/**
 * free_record() - free resources in single record structure
 * @rec: record to free (structure itself not freed)
 *
 * Frees dynamically allocated name and type-specific rdata.
 */
static void free_record(struct mdns_record *rec)
{
	if (!rec)
		return;

	free(rec->name);

	switch (rec->type) {
	case DNS_TYPE_A:
	case DNS_TYPE_AAAA:
		break;
	case DNS_TYPE_PTR:
		free(rec->rdata.ptr.name);
		break;
	case DNS_TYPE_CNAME:
		free(rec->rdata.cname.name);
		break;
	case DNS_TYPE_SRV:
		free(rec->rdata.srv.target);
		break;
	case DNS_TYPE_TXT:
		for (int i = 0; i < rec->rdata.txt.count; i++)
			free(rec->rdata.txt.strings[i]);
		free(rec->rdata.txt.strings);
		break;
	default:
		free(rec->rdata.raw.data);
		break;
	}
}

/**
 * mdns_packet_parse() - parse DNS packet from wire format
 * @data: pointer to packet data
 * @len: length of packet data
 *
 * Parses complete DNS packet including header, questions, answers, authority,
 * and additional sections. Validates RFC 6762 Section 18.3 (OPCODE=0) and
 * Section 18.11 (RCODE=0). All names are expanded from wire format.
 *
 * Return: allocated packet structure, or NULL on error
 */
struct mdns_packet *mdns_packet_parse(const uint8_t *data, size_t len)
{
	struct mdns_packet *pkt = NULL;
	const uint8_t *ptr = data;
	size_t remaining = len;
	struct dns_header *hdr;
	int i;

	if (len < sizeof(struct dns_header)) {
		mdns_set_error("Packet too small");
		return NULL;
	}

	pkt = calloc(1, sizeof(*pkt));
	if (!pkt) {
		mdns_set_error("Out of memory");
		return NULL;
	}

	hdr = (struct dns_header *)ptr;
	pkt->header.id = ntohs(hdr->id);
	pkt->header.flags = ntohs(hdr->flags);
	pkt->header.questions = ntohs(hdr->questions);
	pkt->header.answers = ntohs(hdr->answers);
	pkt->header.authority = ntohs(hdr->authority);
	pkt->header.additional = ntohs(hdr->additional);

	uint16_t opcode = (pkt->header.flags & DNS_OPCODE_MASK) >> DNS_OPCODE_SHIFT;
	if (opcode != 0) {
		mdns_set_error("Invalid OPCODE (must be 0)");
		goto error;
	}

	uint16_t rcode = pkt->header.flags & DNS_RCODE_MASK;
	if (rcode != 0) {
		mdns_set_error("Invalid RCODE (must be 0)");
		goto error;
	}

	if (pkt->header.flags & DNS_RESERVED_BITS) {
		mdns_debug("Received packet with reserved bits set (Z/AD/CD): 0x%04x\n",
			   pkt->header.flags);
	}

	ptr += sizeof(*hdr);
	remaining -= sizeof(*hdr);

	/* The declared counts are attacker controlled and are used to size the
	 * section arrays. A question occupies at least 5 bytes on the wire and a
	 * record at least 11, so anything above that cannot be present. */
	if (pkt->header.questions > remaining / DNS_QUESTION_MIN_SIZE)
		pkt->header.questions = remaining / DNS_QUESTION_MIN_SIZE;
	if (pkt->header.answers > remaining / DNS_RECORD_MIN_SIZE)
		pkt->header.answers = remaining / DNS_RECORD_MIN_SIZE;
	if (pkt->header.authority > remaining / DNS_RECORD_MIN_SIZE)
		pkt->header.authority = remaining / DNS_RECORD_MIN_SIZE;
	if (pkt->header.additional > remaining / DNS_RECORD_MIN_SIZE)
		pkt->header.additional = remaining / DNS_RECORD_MIN_SIZE;

	if (pkt->header.questions > 0) {
		pkt->questions = calloc(pkt->header.questions, sizeof(struct mdns_question));
		if (!pkt->questions)
			goto error;
	}

	if (pkt->header.answers > 0) {
		pkt->answers = calloc(pkt->header.answers, sizeof(struct mdns_record));
		if (!pkt->answers)
			goto error;
	}

	if (pkt->header.authority > 0) {
		pkt->authority = calloc(pkt->header.authority, sizeof(struct mdns_record));
		if (!pkt->authority)
			goto error;
	}

	if (pkt->header.additional > 0) {
		pkt->additional = calloc(pkt->header.additional, sizeof(struct mdns_record));
		if (!pkt->additional)
			goto error;
	}

	/* A record we cannot parse leaves the stream position unknown, so the
	 * rest of the packet is abandoned. What parsed before it is still good,
	 * and keeping it stops one bad record from letting a hostile device
	 * suppress a legitimate responder's whole answer. */
	for (i = 0; i < pkt->header.questions; i++) {
		if (parse_question(data, len, &ptr, &remaining, &pkt->questions[i]) < 0)
			goto truncated;
		pkt->question_count++;
	}

	for (i = 0; i < pkt->header.answers; i++) {
		if (parse_record(data, len, &ptr, &remaining, &pkt->answers[i]) < 0)
			goto truncated;
		pkt->answer_count++;
	}

	for (i = 0; i < pkt->header.authority; i++) {
		if (parse_record(data, len, &ptr, &remaining, &pkt->authority[i]) < 0)
			goto truncated;
		pkt->authority_count++;
	}

	for (i = 0; i < pkt->header.additional; i++) {
		if (parse_record(data, len, &ptr, &remaining, &pkt->additional[i]) < 0)
			goto truncated;
		pkt->additional_count++;
	}

	mdns_debug("Parsed packet: %d questions, %d answers, %d authority, %d additional (flags=0x%04x)\n",
		   pkt->question_count, pkt->answer_count, pkt->authority_count,
		   pkt->additional_count, pkt->header.flags);

	return pkt;

truncated:
	mdns_debug("Stopped parsing at %d questions, %d answers, %d authority, %d additional: %s\n",
		   pkt->question_count, pkt->answer_count, pkt->authority_count,
		   pkt->additional_count, ctx.error);

	return pkt;

error:
	mdns_packet_free(pkt);
	return NULL;
}

/**
 * mdns_packet_free() - free parsed packet and all resources
 * @pkt: packet to free
 *
 * Frees all questions, records, and the packet structure itself.
 */
void mdns_packet_free(struct mdns_packet *pkt)
{
	if (!pkt)
		return;

	for (int i = 0; i < pkt->question_count; i++)
		free(pkt->questions[i].name);
	free(pkt->questions);

	for (int i = 0; i < pkt->answer_count; i++)
		free_record(&pkt->answers[i]);
	free(pkt->answers);

	for (int i = 0; i < pkt->authority_count; i++)
		free_record(&pkt->authority[i]);
	free(pkt->authority);

	for (int i = 0; i < pkt->additional_count; i++)
		free_record(&pkt->additional[i]);
	free(pkt->additional);

	free(pkt);
}

/**
 * rdata_to_hex() - convert binary rdata to hex string
 * @data: binary data
 * @len: data length
 *
 * Return: allocated hex string, or NULL on allocation failure
 */
static char *rdata_to_hex(const uint8_t *data, uint16_t len)
{
	char *hex;

	if (len == 0)
		return NULL;

	hex = malloc(len * 2 + 1);
	if (!hex)
		return NULL;

	for (int i = 0; i < len; i++)
		sprintf(hex + i * 2, "%02x", data[i]);

	return hex;
}

/**
 * record_to_ucode() - convert record structure to ucode object
 * @rec: record to convert
 * @vm: ucode VM context
 *
 * Creates ucode object with name, type, class, ttl, flush_cache, and
 * type-specific rdata fields.
 *
 * Return: ucode object, or NULL on error
 */
static uc_value_t *record_to_ucode(struct mdns_record *rec, uc_vm_t *vm)
{
	uc_value_t *obj, *rdata;
	char addr_str[INET6_ADDRSTRLEN];

	obj = ucv_object_new(vm);

	ucv_object_add(obj, "name", ucv_string_new(rec->name));
	ucv_object_add(obj, "type", ucv_string_new(mdns_type_to_string(rec->type)));
	ucv_object_add(obj, "class", ucv_string_new(mdns_class_to_string(rec->class)));
	ucv_object_add(obj, "ttl", ucv_int64_new(rec->ttl));
	ucv_object_add(obj, "flush_cache", ucv_boolean_new(rec->flush_cache));

	rdata = ucv_object_new(vm);

	switch (rec->type) {
	case DNS_TYPE_A:
		inet_ntop(AF_INET, &rec->rdata.a.addr, addr_str, sizeof(addr_str));
		ucv_object_add(rdata, "address", ucv_string_new(addr_str));
		break;

	case DNS_TYPE_AAAA:
		inet_ntop(AF_INET6, &rec->rdata.aaaa.addr, addr_str, sizeof(addr_str));
		ucv_object_add(rdata, "address", ucv_string_new(addr_str));
		break;

	case DNS_TYPE_PTR:
		ucv_object_add(rdata, "ptr", ucv_string_new(rec->rdata.ptr.name));
		break;

	case DNS_TYPE_CNAME:
		ucv_object_add(rdata, "cname", ucv_string_new(rec->rdata.cname.name));
		break;

	case DNS_TYPE_SRV:
		ucv_object_add(rdata, "priority", ucv_int64_new(rec->rdata.srv.priority));
		ucv_object_add(rdata, "weight", ucv_int64_new(rec->rdata.srv.weight));
		ucv_object_add(rdata, "port", ucv_int64_new(rec->rdata.srv.port));
		ucv_object_add(rdata, "target", ucv_string_new(rec->rdata.srv.target));
		break;

	case DNS_TYPE_TXT:
		{
			uc_value_t *txt_array = ucv_array_new(vm);
			for (int i = 0; i < rec->rdata.txt.count; i++)
				ucv_array_push(txt_array, ucv_string_new(rec->rdata.txt.strings[i]));
			ucv_object_add(rdata, "strings", txt_array);
		}
		break;

	case DNS_TYPE_NSEC:
		{
			char *hex = rdata_to_hex(rec->rdata.raw.data, rec->rdata.raw.len);
			if (hex) {
				ucv_object_add(rdata, "raw", ucv_string_new(hex));
				free(hex);
			}
		}
		break;

	default:
		{
			char *hex = rdata_to_hex(rec->rdata.raw.data, rec->rdata.raw.len);
			if (hex) {
				ucv_object_add(rdata, "raw", ucv_string_new(hex));
				free(hex);
			}
		}
		break;
	}

	ucv_object_add(obj, "rdata", rdata);
	return obj;
}

/**
 * mdns_packet_to_ucode() - convert parsed packet to ucode object
 * @pkt: parsed packet structure
 * @vm: ucode VM context
 *
 * Converts entire packet including header, flags, and all sections to
 * ucode object for business logic processing.
 *
 * Return: ucode object, or NULL on error
 */
uc_value_t *mdns_packet_to_ucode(struct mdns_packet *pkt, uc_vm_t *vm)
{
	uc_value_t *obj, *header, *questions, *answers, *authority, *additional;
	uc_value_t *flags;

	if (!pkt)
		return NULL;

	obj = ucv_object_new(vm);

	header = ucv_object_new(vm);
	ucv_object_add(header, "id", ucv_int64_new(pkt->header.id));

	flags = ucv_object_new(vm);
	ucv_object_add(flags, "response", ucv_boolean_new(!!(pkt->header.flags & DNS_FLAG_RESPONSE)));
	ucv_object_add(flags, "authoritative", ucv_boolean_new(!!(pkt->header.flags & DNS_FLAG_AUTHORITATIVE)));
	ucv_object_add(flags, "truncated", ucv_boolean_new(!!(pkt->header.flags & DNS_FLAG_TRUNCATED)));
	ucv_object_add(flags, "recursion_desired", ucv_boolean_new(!!(pkt->header.flags & DNS_FLAG_RD)));
	ucv_object_add(header, "flags", flags);

	ucv_object_add(header, "question_count", ucv_int64_new(pkt->header.questions));
	ucv_object_add(header, "answer_count", ucv_int64_new(pkt->header.answers));
	ucv_object_add(header, "authority_count", ucv_int64_new(pkt->header.authority));
	ucv_object_add(header, "additional_count", ucv_int64_new(pkt->header.additional));
	ucv_object_add(obj, "header", header);

	questions = ucv_array_new(vm);
	for (int i = 0; i < pkt->question_count; i++) {
		uc_value_t *q = ucv_object_new(vm);
		ucv_object_add(q, "name", ucv_string_new(pkt->questions[i].name));
		ucv_object_add(q, "type", ucv_string_new(mdns_type_to_string(pkt->questions[i].type)));
		ucv_object_add(q, "class", ucv_string_new(mdns_class_to_string(pkt->questions[i].class)));
		ucv_object_add(q, "unicast_response", ucv_boolean_new(pkt->questions[i].unicast_response));
		ucv_array_push(questions, q);
	}
	ucv_object_add(obj, "questions", questions);

	answers = ucv_array_new(vm);
	for (int i = 0; i < pkt->answer_count; i++)
		ucv_array_push(answers, record_to_ucode(&pkt->answers[i], vm));
	ucv_object_add(obj, "answers", answers);

	authority = ucv_array_new(vm);
	for (int i = 0; i < pkt->authority_count; i++)
		ucv_array_push(authority, record_to_ucode(&pkt->authority[i], vm));
	ucv_object_add(obj, "authority", authority);

	additional = ucv_array_new(vm);
	for (int i = 0; i < pkt->additional_count; i++)
		ucv_array_push(additional, record_to_ucode(&pkt->additional[i], vm));
	ucv_object_add(obj, "additional", additional);

	return obj;
}
