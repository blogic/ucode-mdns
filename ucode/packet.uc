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
 * keyed "iface:name:type" and holding the time the question went out. A
 * unicast response is only acceptable if it answers one of these. */
const qu_questions = {};

function qu_key(iface_name, name, type) {
	return `${iface_name}:${utils.name_normalise(name)}:${type}`;
}

function qu_record(iface_name, name, type) {
	qu_questions[qu_key(iface_name, name, type)] = time();
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
	for (let record_type in [ type, 'ANY' ]) {
		const sent = qu_questions[qu_key(iface_name, name, record_type)];

		if (sent && time() - sent <= c.QU_RESPONSE_WINDOW_SEC)
			return true;
	}

	return false;
};

/**
 * Drop QU questions that are past the acceptance window
 * @returns {number} Number of entries removed
 */
export function qu_expire() {
	const threshold = time() - c.QU_RESPONSE_WINDOW_SEC;
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
 * @returns {boolean} True if sent successfully
 */
export function send_query(iface_name, questions, unicast, known_answers, authority_records) {
	const ka_list = known_answers || [];

	for (let q in questions) {
		if (q.unicast_response)
			qu_record(iface_name, q.name, q.type);
	}

	/* RFC 6762 Section 7.2: Split known-answers if packet would exceed reasonable size
	 * Use 1400 bytes as conservative limit (well under 1500 MTU, allows for headers) */
	const MAX_PACKET_SIZE = c.MAX_PACKET_SIZE;

	let base_size = 12;
	for (let q in questions)
		base_size += length(q.name) + 5;

	if (length(ka_list) > 0) {
		let current_size = base_size;
		const packets_to_send = [];
		let current_ka = [];

		for (let record in ka_list) {
			const record_size = estimate_record_size(record);

			if (current_size + record_size > MAX_PACKET_SIZE && length(current_ka) > 0) {
				push(packets_to_send, current_ka);
				current_ka = [];
				current_size = base_size;
			}

			push(current_ka, record);
			current_size += record_size;
		}

		if (length(current_ka) > 0)
			push(packets_to_send, current_ka);

		if (length(packets_to_send) > 1) {
			for (let i = 0; i < length(packets_to_send); i++) {
				const is_last = (i === length(packets_to_send) - 1);
				const packet = {
					header: {
						id: 0,
						flags: {
							response: false,
							authoritative: false,
							truncated: !is_last,
							recursion_desired: false
						}
					},
					/* RFC 6762 Section 7.2: only the first packet carries
					 * the questions; the continuations hold known answers
					 * and nothing else */
					questions: i === 0 ? questions : [],
					answers: packets_to_send[i],
					authority: i === 0 ? (authority_records || []) : [],
					additional: []
				};

				if (!mdns.packet_send(iface_name, packet, null)) {
					log.ERR(`packet: Failed to send query packet ${i + 1}/${length(packets_to_send)}: ${mdns.error()}\n`);
					return false;
				}
			}

			mdns.debug(`packet: Sent query in ${length(packets_to_send)} packets with ${length(ka_list)} known answer(s)\n`);

			return true;
		}
	}

	const packet = {
		header: {
			id: 0,
			flags: {
				response: false,
				authoritative: false,
				truncated: false,
				recursion_desired: false
			}
		},
		questions: questions,
		answers: ka_list,
		authority: authority_records || [],
		additional: []
	};

	if (!mdns.packet_send(iface_name, packet, null)) {
		log.ERR(`packet: Failed to send query: ${mdns.error()}\n`);
		return false;
	}

	if (length(ka_list) > 0)
		mdns.debug(`packet: Sent query with ${length(ka_list)} known answer(s)\n`);

	return true;
};
