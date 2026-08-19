/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * query.uc - Query handling and response logic
 *
 * Processes incoming DNS questions and determines appropriate responses.
 * Implements known-answer suppression (RFC 6762 Section 7.1).
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as service from 'service';
import * as host from 'host';
import * as nsec from 'nsec';
import * as response from 'response';
import * as utils from 'utils';
import * as mdns from 'mdns';
import * as c from 'const';
import * as announce from 'announce';
import * as registry from 'dnssd_registry';

function host_ready(name, iface_name) {
	const canonical = host.canonical(name);
	return canonical != null && announce.is_announced(canonical, iface_name);
}

function host_records(name, iface_name) {
	return host_ready(name, iface_name) ? host.build_records(name, null, iface_name) : [];
}

function address_records(name, iface_name) {
	return [ ...host_records(name, iface_name), ...filter(registry.records_query(iface_name, name, 'ANY'),
		record => record.type === 'A' || record.type === 'AAAA') ];
}

function owned_records(name, iface_name) {
	return [ ...host_records(name, iface_name),
		...filter(registry.records_query(iface_name, name, 'ANY'), record => record.flush_cache) ];
}

function denial_build(name, records) {
	return nsec.build(name, uniq(map(records, record => record.type)));
}

/**
 * Collect the records of a service
 *
 * The RFC 6762 Section 6 one-per-second limit applies to multicast on an
 * interface, so response.uc enforces it where the send happens rather than
 * here, where a unicast, legacy or probe-defence answer would also be caught.
 *
 * @param {string} instance_name - Full instance name
 * @param {array} target - Response records, appended to in place
 */
function service_records_collect(instance_name, target) {
	for (let record in service.build_records(instance_name))
		push(target, record);
}

function addresses_complement(record, iface_name) {
	const owned = owned_records(record.name, iface_name);
	const other = record.type === 'A' ? 'AAAA' : 'A';
	const complementary = filter(owned, item => item.type === other);

	if (length(complementary) || !length(owned))
		return complementary;

	return filter([ denial_build(record.name, owned) ], item => item != null);
}

/**
 * RFC 6763 Section 12: build the additional section for a set of answers
 *
 * A PTR answer carries the SRV and TXT of the instance, and any SRV carries
 * the address records of its target. An address answer carries the addresses
 * of the other family, or an NSEC if there are none (RFC 6762 Section 6.2).
 * This saves the querier a round trip.
 *
 * @param {array} records - Answer records
 * @param {string} iface_name - Interface the question arrived on
 * @returns {array} Additional records
 */
function additional_build(records, iface_name) {
	const additional = [];

	for (let record in records) {
		if (record.type === 'A' || record.type === 'AAAA')
			response.records_merge(additional, addresses_complement(record, iface_name));
		if (record.type !== 'PTR')
			continue;

		const instance_name = service.find_by_name(record.rdata?.ptr);
		const instance_records = instance_name ? service.build_records(instance_name) :
			registry.records_query(iface_name, record.rdata?.ptr, 'ANY');

		for (let extra in instance_records) {
			if (extra.type === 'SRV' || extra.type === 'TXT')
				push(additional, extra);
		}
	}

	const targets = {};

	for (let record in [ ...records, ...additional ]) {
		if (record.type === 'SRV' && record.rdata?.target)
			targets[record.rdata.target] = true;
	}

	for (let target in targets)
		response.records_merge(additional, address_records(target, iface_name));

	return additional;
}

function question_is_probe(question, ctx) {
	/* RFC 6762 Section 6: a probe carries a proposed record in the Authority
	 * Section answering the question. The QU bit does not identify one: an
	 * ordinary wake-up query sets it too, and Section 8.1 makes it only a
	 * SHOULD for probes. */
	if (ctx.is_legacy)
		return false;

	for (let record in ctx.authority) {
		if (utils.name_equal(record.name, question.name))
			return true;
	}

	return false;
}

function records_collect(name, type, iface_name, instance_name, published) {
	const records = registry.records_query(iface_name, name, type);

	/* RFC 6762 Section 6.2: address queries for a name this host claims */
	if (type === 'A' || type === 'AAAA' || type === 'ANY') {
		for (let record in host_records(name, iface_name)) {
			if (type === 'ANY' || record.type === type)
				push(records, record);
		}
	}

	if (published) {
		/* Direct name match - respond with SRV/TXT/ANY records */
		if (type === 'SRV' || type === 'TXT' || type === 'ANY')
			service_records_collect(instance_name, records);
		return records;
	}

	if (type !== 'PTR' && type !== 'ANY')
		return records;

	/* RFC 6763 Section 9: enumerate the service types we announce */
	if (utils.name_equal(name, c.SERVICE_ENUM_NAME)) {
		for (let service_type in registry.service_types(iface_name))
			push(records, service.enumeration_record(service_type));
	}

	/* PTR query - lookup by service type */
	for (let inst in service.get_by_type(name)) {
		if (announce.is_announced(inst, iface_name))
			service_records_collect(inst, records);
	}

	return records;
}

function answers_schedule(question, ctx, records, extra, is_probe) {
	/* RFC 6762 Section 6: Determine if all records are unique (non-shared)
	 * Unique records can be responded to quickly when we're the sole responder */
	let all_unique = true;
	for (let record in records) {
		if (!record.flush_cache) {  /* Shared records don't have cache-flush bit */
			all_unique = false;
			break;
		}
	}

	const iface_name = ctx.iface.name;
	const from = ctx.from;
	const private_allowed = from?.local && (question.unicast_response || !ctx.multicast);
	const unicast_records = [];
	const multicast_records = [];

	for (let record in records) {
		const private_response = private_allowed &&
			(is_probe || response.multicast_recent(iface_name, record));

		push(private_response ? unicast_records : multicast_records, record);
	}

	for (let group in [ { records: multicast_records, dest: null }, { records: unicast_records, dest: from } ]) {
		if (!length(group.records))
			continue;

		const additional = additional_build(group.records, iface_name);

		response.records_merge(additional, extra);
		response.schedule(iface_name, group.records, additional, group.dest,
			ctx.tc_bit_set, all_unique && !ctx.multiquestion, is_probe, null, from?.address);
	}
}

/**
 * Process a single question
 *
 * RFC 6762 Section 8.1: Detects probes (QU bit + no known answers).
 * RFC 6762 Section 6.1: Generates NSEC for negative responses.
 *
 * @param {object} question - DNS question with name, type, unicast_response
 * @param {object} ctx - Query context { known_answers, authority, iface,
 *   multicast, tc_bit_set, is_legacy, from, legacy_batch, multiquestion }
 */
function query_process_question(question, ctx) {
	if (question.class !== 'IN' && question.class !== 'ANY')
		return;

	const name = question.name;
	const type = question.type;
	const iface_name = ctx.iface.name;
	const is_probe = question_is_probe(question, ctx);

	/* O(1) lookup by name instead of O(n) iteration */
	const instance_name = service.find_by_name(name);
	const published = instance_name != null && announce.is_announced(instance_name, iface_name);

	/* Determine what records we should respond with */
	const response_records = records_collect(name, type, iface_name, instance_name, published);
	const reverse = host_ready(host.hostname(), iface_name) ? host.reverse_records(name, iface_name) : [];

	if (type === 'PTR' || type === 'ANY')
		push(response_records, ...reverse);

	/* RFC 6762 Section 6: the Answer Section holds records that answer the
	 * question. The rest belong in the Additional Section. */
	const answers = [];
	for (let record in response_records) {
		if (!utils.name_equal(record.name, name))
			continue;
		if (type !== 'ANY' && record.type !== type && record.type !== 'NSEC')
			continue;

		push(answers, record);
	}

	const extra = response.records_missing(response_records, answers);

	/* RFC 6762 Section 6.1: NSEC for negative responses
	 * If we have the name but not the requested type, send NSEC */
	if (length(answers) === 0) {
		/* RFC 6762 Section 6.1: only for a name we claimed by probing. A
		 * DNS-SD service type name is shared and never probed, so denying
		 * types at it would poison the negative caches of the other
		 * responders that legitimately own records there. */
		const owned = published ?
			filter(service.build_records(instance_name), record => utils.name_equal(record.name, name)) :
			owned_records(name, iface_name);

		/* Only send NSEC if we have the name but not the requested type
		 * Don't send NSEC for names we don't own at all */
		const nsec_record = type !== 'ANY' ? denial_build(name, [ ...reverse, ...owned ]) : null;

		if (!nsec_record)
			return;  /* Nothing to respond with */

		push(answers, nsec_record);

		mdns.debug(`query: Generated NSEC for ${name}, asked for ${type}\n`);
	}

	const suppressed_records = response.suppress_known_answers(answers, ctx.known_answers);

	if (length(suppressed_records) === 0)
		return;

	if (!ctx.is_legacy) {
		answers_schedule(question, ctx, suppressed_records, extra, is_probe);
		return;
	}

	response.records_merge(ctx.legacy_batch.records, suppressed_records);
	response.records_merge(ctx.legacy_batch.additional, additional_build(suppressed_records, iface_name));
	response.records_merge(ctx.legacy_batch.additional, extra);
}

/**
 * Handle incoming question
 *
 * RFC 6762 Section 6, 7.2: Handles TC bit for multipacket known-answer lists.
 * RFC 6762 Section 6.7: Legacy queries (non-5353 port) require special handling.
 *
 * @param {object} packet - Parsed DNS packet
 * @param {object} from - Source address { address, port, family, local }
 * @param {object} iface - Interface object { name, index }
 * @param {boolean} multicast - True if received on multicast socket
 * @param {boolean} is_legacy - True if source port != 5353
 */
export function handle(packet, from, iface, multicast, is_legacy) {
	if (!packet?.questions)
		return;

	if (is_legacy && !from?.local) {
		mdns.debug(`query: Ignoring legacy query from off-link ${from?.address}\n`);
		return;
	}

	/* RFC 6762 Section 6.7: Legacy queries require special handling */
	const query_id = packet.header?.id || 0;

	const questions = slice(packet.questions, 0, c.MAX_QUESTIONS_PER_PACKET);

	if (length(questions) < length(packet.questions))
		mdns.debug(`query: Ignoring ${length(packet.questions) - length(questions)} of ${length(packet.questions)} questions from ${from?.address}\n`);

	const ctx = {
		/* Extract known answers for suppression */
		known_answers: packet.answers || [],
		authority: packet.authority ?? [],
		iface,
		multicast,
		/* RFC 6762 Section 6, 7.2: Check for TC (truncated) bit in query */
		tc_bit_set: packet.header?.flags?.truncated || false,
		is_legacy,
		from,
		legacy_batch: { records: [], additional: [] },
		multiquestion: length(questions) > 1
	};
	const seen = {};

	for (let question in questions) {
		const key = `${utils.name_normalise(question.name)}:${question.type}:${question.class}:${question.unicast_response}`;
		if (seen[key])
			continue;

		seen[key] = true;
		query_process_question(question, ctx);
	}

	if (is_legacy && length(ctx.legacy_batch.records))
		response.schedule(iface.name, ctx.legacy_batch.records, ctx.legacy_batch.additional, null,
			false, false, false, { query_id, questions, dest: from });
};
