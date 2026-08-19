/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * packet.uc - DNS packet construction and sending
 *
 * Handles packet assembly, size estimation, and transmission.
 * Implements TC bit multi-packet splitting for known-answers.
 */

import * as mdns from 'mdns';
import * as utils from 'utils';
import * as log from 'log';
import * as c from 'const';

/* RFC 6762 Section 6: questions we sent with the unicast-response bit set,
 * keyed "iface:name:type" and holding the utils.now_ms() time the question
 * went out. A unicast response is only acceptable if it answers one of these. */
const qu_questions = {};

const HEADER_SIZE = 12;

function qu_key(iface_name, name, type) {
	return `${iface_name}:${utils.name_normalise(name)}:${type}`;
}

function qu_record(iface_name, name, type) {
	qu_questions[qu_key(iface_name, name, type)] = utils.now_ms();
}

/**
 * RFC 6762 Section 6: was a unicast response solicited?
 *
 * "A Multicast DNS querier MUST only accept unicast responses if they answer a
 * recently sent query that explicitly requested unicast responses."
 *
 * @param {string} iface_name - Interface the response arrived on
 * @param {string} name - Record name
 * @param {string} type - Record type
 * @returns {boolean} True if a matching QU question is still recent
 */
export function qu_pending(iface_name, name, type) {
	const now = utils.now_ms();

	for (let record_type in [ type, 'ANY' ]) {
		const sent = qu_questions[qu_key(iface_name, name, record_type)];

		if (sent && now - sent <= c.QU_RESPONSE_WINDOW_SEC * 1000)
			return true;
	}

	return false;
};

/**
 * Drop QU questions that are past the acceptance window
 * @returns {number} Number of entries removed
 */
export function qu_expire() {
	const threshold = utils.now_ms() - c.QU_RESPONSE_WINDOW_SEC * 1000;
	let removed = 0;

	for (let key in qu_questions) {
		if (qu_questions[key] < threshold) {
			delete qu_questions[key];
			removed++;
		}
	}

	return removed;
};

/**
 * RFC 6762 Section 7.2: Estimate DNS record size in bytes
 *
 * Rough approximation: name + type/class/ttl (10 bytes) + rdata length.
 *
 * @param {object} record - DNS record to estimate
 * @returns {number} Estimated size in bytes
 */
function estimate_record_size(record) {
	let size = length(record.name) + 1;
	size += 10;

	const rdata_str = sprintf('%J', record.rdata);
	size += length(rdata_str);

	return size;
}

/**
 * RFC 6762 Section 7.2: estimate the size of a query packet
 *
 * @param {array} questions - Questions of the packet
 * @param {array} answers - Known answers of the packet
 * @returns {number} Estimated size in bytes, header included
 */
export function size_estimate(questions, answers) {
	let size = HEADER_SIZE;

	for (let q in questions)
		size += length(q.name) + 5;
	for (let record in answers)
		size += estimate_record_size(record);

	return size;
};

/**
 * RFC 6762 Section 7.1: select the cached records to send as known answers
 *
 * A record goes in with its remaining TTL and without the cache-flush bit. A
 * goodbye, and a record with less than half of its TTL left, stays out.
 *
 * @param {array} records - Cached records, as returned by cache.lookup()
 * @returns {array} The known-answer list
 */
export function known_answers_filter(records) {
	const list = [];
	const now = utils.now_ms();

	for (let record in records) {
		const remaining = record.expires_at != null
			? min(record.ttl, max(0, int((record.expires_at - now) / 1000))) : record.ttl;
		if (record.is_goodbye || remaining <= 0 || remaining < record.ttl / 2.0)
			continue;
		push(list, { ...record, ttl: remaining, flush_cache: false });
	}

	return list;
};

function query_packet(questions, answers, authority, truncated) {
	return {
		header: {
			id: 0,
			flags: {
				response: false,
				authoritative: false,
				truncated: truncated,
				recursion_desired: false
			}
		},
		questions: questions,
		answers: answers,
		authority: authority,
		additional: []
	};
}

function known_answers_split(ka_list, base_size) {
	const packets = [];
	let current_size = base_size;
	let current_ka = [];

	for (let record in ka_list) {
		const record_size = estimate_record_size(record);

		if (current_size + record_size > c.MAX_PACKET_SIZE && length(current_ka) > 0) {
			push(packets, current_ka);
			current_ka = [];
			current_size = base_size;
		}

		push(current_ka, record);
		current_size += record_size;
	}

	push(packets, current_ka);

	return packets;
}

function send_result_log(result, index, count) {
	if (result === false)
		mdns.debug(`packet: Query packet ${index + 1}/${count} not sent yet: ${mdns.error()}\n`);
	else
		log.ERR(`packet: Failed to send query packet ${index + 1}/${count}: ${mdns.error()}\n`);
}

/**
 * RFC 6762 Section 7.1, 8.2: Send query with optional known-answers and authority records
 *
 * RFC 6762 Section 7.2: Splits known-answers across multiple packets if needed (TC bit).
 * Uses 1400 bytes as conservative limit (well under 1500 MTU).
 *
 * @param {string} iface_name - Interface name
 * @param {array} questions - Array of DNS questions
 * @param {boolean} unicast - True for unicast query
 * @param {array} known_answers - Records already in cache (suppresses responses)
 * @param {array} authority_records - Authority section records (used in probes for tiebreaking)
 * @returns {boolean|null} True if sent (or queued, for a query without
 *   authority records), false if it may succeed later, null if it never can
 */
export function send_query(iface_name, questions, unicast, known_answers, authority_records) {
	const authority = authority_records ?? [];
	const immediate = length(authority) > 0;
	const ka_list = known_answers_filter(known_answers ?? []);

	if (!mdns.first_binder())
		questions = map(questions, q => ({ ...q, unicast_response: false }));

	/* RFC 6762 Section 7.2: Split known-answers if packet would exceed reasonable size
	 * Use 1400 bytes as conservative limit (well under 1500 MTU, allows for headers) */
	const packets = known_answers_split(ka_list, size_estimate(questions, []));
	const count = length(packets);

	for (let i = 0; i < count; i++) {
		/* RFC 6762 Section 7.2: only the first packet carries
		 * the questions; the continuations hold known answers
		 * and nothing else */
		const packet = query_packet(i === 0 ? questions : [], packets[i],
			i === 0 ? authority : [], i < count - 1);
		const result = mdns.packet_send(iface_name, packet, null, immediate);

		if (result !== true) {
			send_result_log(result, i, count);
			return result === false ? false : null;
		}

		if (i > 0)
			continue;

		for (let q in questions) {
			if (q.unicast_response)
				qu_record(iface_name, q.name, q.type);
		}
	}

	if (length(ka_list) > 0)
		mdns.debug(`packet: Sent query in ${count} packet(s) with ${length(ka_list)} known answer(s)\n`);

	return true;
};
