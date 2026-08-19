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

/**
 * RFC 6763 Section 12: build the additional section for a set of answers
 *
 * A PTR answer carries the SRV and TXT of the instance, and any SRV carries
 * the address records of its target. This saves the querier a round trip.
 *
 * @param {array} records - Answer records
 * @param {string} iface_name - Interface the question arrived on
 * @returns {array} Additional records
 */
function additional_build(records, iface_name) {
	const additional = [];

	for (let record in records) {
		if (record.type !== 'PTR')
			continue;

		const instance_name = service.find_by_name(record.rdata?.ptr);

		if (!instance_name)
			continue;

		for (let extra in service.build_records(instance_name)) {
			if (extra.type === 'SRV' || extra.type === 'TXT')
				push(additional, extra);
		}
	}

	const targets = {};

	for (let record in [ ...records, ...additional ]) {
		if (record.type === 'SRV' && record.rdata?.target)
			targets[record.rdata.target] = true;
	}

	for (let target in targets) {
		for (let extra in host.build_records(target, null, iface_name))
			push(additional, extra);
	}

	return additional;
}

/**
 * Process a single question
 *
 * RFC 6762 Section 8.1: Detects probes (QU bit + no known answers).
 * RFC 6762 Section 6.1: Generates NSEC for negative responses.
 *
 * @param {object} question - DNS question with name, type, unicast_response
 * @param {array} known_answers - Known answer records for suppression
 * @param {object} iface - Interface object { name, index }
 * @param {boolean} multicast - True if received on multicast socket
 * @param {boolean} tc_bit_set - True if TC bit set in query
 * @param {boolean} is_legacy - True if source port != 5353
 * @param {number} query_id - DNS query ID for legacy responses
 * @param {object} from - Source address for unicast/legacy responses
 */
function query_process_question(question, known_answers, authority, iface, multicast, tc_bit_set, is_legacy, query_id, from) {
	const name = question.name;
	const type = question.type;
	const unicast_response = question.unicast_response;

	/* RFC 6762 Section 6: a probe carries a proposed record in the Authority
	 * Section answering the question. The QU bit does not identify one: an
	 * ordinary wake-up query sets it too, and Section 8.1 makes it only a
	 * SHOULD for probes. */
	let is_probe = false;

	for (let record in authority) {
		if (!utils.name_equal(record.name, name))
			continue;

		is_probe = !is_legacy;
		break;
	}

	/* Determine what records we should respond with */
	const response_records = [];

	/* RFC 6762 Section 6.2: address queries for a name this host claims */
	if (host.owns(name) && (type === 'A' || type === 'AAAA' || type === 'ANY')) {
		for (let record in host.build_records(name, null, iface.name)) {
			if (type === 'ANY' || record.type === type)
				push(response_records, record);
		}
	}

	/* O(1) lookup by name instead of O(n) iteration */
	const instance_name = service.find_by_name(name);

	if (instance_name && service.is_announced(instance_name)) {
		/* Direct name match - respond with SRV/TXT/ANY records */
		if (type === 'SRV' || type === 'TXT' || type === 'ANY')
			service_records_collect(instance_name, response_records);
	} else if (type === 'PTR' || type === 'ANY') {
		/* RFC 6763 Section 9: enumerate the service types we announce */
		if (utils.name_equal(name, c.SERVICE_ENUM_NAME)) {
			for (let service_type in service.types())
				push(response_records, service.enumeration_record(service_type));
		}

		/* PTR query - lookup by service type */
		for (let inst in service.get_by_type(name)) {
			if (!service.is_announced(inst))
				continue;

			service_records_collect(inst, response_records);
		}
	}

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
		let have_name = false;
		const existing_types = [];

		const inst = service.find_by_name(name);
		if (inst && service.is_announced(inst)) {
			have_name = true;
			/* Instance name has SRV and TXT records */
			push(existing_types, 'SRV');
			push(existing_types, 'TXT');
		} else if (host.owns(name)) {
			const host_types = host.types_for(name, iface.name);

			if (length(host_types) > 0) {
				have_name = true;
				for (let host_type in host_types)
					push(existing_types, host_type);
			}
		}

		/* Only send NSEC if we have the name but not the requested type
		 * Don't send NSEC for names we don't own at all */
		if (have_name && type !== 'ANY') {
			const nsec_record = nsec.build(name, existing_types);
			push(answers, nsec_record);

			mdns.debug(`query: Generated NSEC for ${name} (have ${join(", ", existing_types)}, asked for ${type})\n`);
		} else {
			return;  /* Nothing to respond with */
		}
	}

	const suppressed_records = response.suppress_known_answers(answers, known_answers);

	if (length(suppressed_records) === 0)
		return;

	/* RFC 6762 Section 6: Determine if all records are unique (non-shared)
	 * Unique records can be responded to quickly when we're the sole responder */
	let all_unique = true;
	for (let record in suppressed_records) {
		if (!record.flush_cache) {  /* Shared records don't have cache-flush bit */
			all_unique = false;
			break;
		}
	}

	const additional = additional_build(suppressed_records, iface.name);

	response.records_merge(additional, extra);

	/* RFC 6762 Section 6.7: legacy responses repeat query ID and question */
	const legacy_info = is_legacy ? { query_id: query_id, question: question, dest: from } : null;
	const unicast_dest = unicast_response ? from : null;
	response.schedule(iface.name, suppressed_records, additional, unicast_dest, tc_bit_set, all_unique, is_probe, legacy_info);
}

/**
 * Handle incoming question
 *
 * RFC 6762 Section 6, 7.2: Handles TC bit for multipacket known-answer lists.
 * RFC 6762 Section 6.7: Legacy queries (non-5353 port) require special handling.
 *
 * @param {object} packet - Parsed DNS packet
 * @param {object} from - Source address { address, port, family }
 * @param {object} iface - Interface object { name, index }
 * @param {boolean} multicast - True if received on multicast socket
 * @param {boolean} is_legacy - True if source port != 5353
 */
export function handle(packet, from, iface, multicast, is_legacy) {
	if (!packet?.questions)
		return;

	/* Extract known answers for suppression */
	const known_answers = packet.answers || [];

	/* RFC 6762 Section 6, 7.2: Check for TC (truncated) bit in query */
	const tc_bit_set = packet.header?.flags?.truncated || false;

	/* RFC 6762 Section 6.7: Legacy queries require special handling */
	const query_id = packet.header?.id || 0;

	/* A 9000 byte packet holds close to 1500 questions once the names are
	 * compression pointers, and a legacy query answers each one with its own
	 * unicast packet */
	const questions = length(packet.questions) > c.MAX_QUESTIONS_PER_PACKET
	                  ? slice(packet.questions, 0, c.MAX_QUESTIONS_PER_PACKET)
	                  : packet.questions;

	if (length(questions) < length(packet.questions))
		mdns.debug(`query: Ignoring ${length(packet.questions) - length(questions)} of ${length(packet.questions)} questions from ${from?.address}\n`);

	for (let question in questions) {
		query_process_question(question, known_answers, packet.authority ?? [],
		                       iface, multicast, tc_bit_set, is_legacy, query_id, from);
	}
};
