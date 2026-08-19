/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * response.uc - Response scheduling and sending
 *
 * Handles response aggregation, scheduling, and transmission.
 * Implements known-answer suppression and probe defence.
 */

import * as utils from 'utils';
import * as uloop from 'uloop';
import * as mdns from 'mdns';
import * as log from 'log';
import * as c from 'const';

/* RFC 6762 Section 6.4: Pending responses (delayed for aggregation)
 * Responses are delayed and aggregated to reduce network traffic */
const pending_responses = {};

/* RFC 6762 Section 6: Probe defence rate limiting (≥250ms between probe responses)
 * Tracks last send time per interface:name:type
 * Cleaned up periodically to prevent unbounded growth */
const probe_defence_sent = {};

/* RFC 6762 Section 6.7: legacy responses sent per source in the current second */
const legacy_sent = {};

/* RFC 6762 Section 6: when each record was last multicast, keyed
 * "iface:name:type". The limit is on multicast on a given interface, so
 * unicast answers, legacy answers and probe defence are not subject to it. */
const multicast_sent = {};

function multicast_key(iface_name, record) {
	return `${iface_name}:${utils.name_normalise(record.name)}:${record.type}`;
}

/**
 * RFC 6762 Section 6: drop records multicast less than a second ago
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records
 * @returns {array} Records that may go out now
 */
function multicast_filter(iface_name, records) {
	const now = utils.now_ms();
	const allowed = [];

	for (let record in records) {
		const last = multicast_sent[multicast_key(iface_name, record)];

		if (last != null && now - last < c.MULTICAST_RATE_LIMIT_MS) {
			mdns.debug(`response: Rate limited ${record.type} ${record.name} on ${iface_name}\n`);
			continue;
		}

		push(allowed, record);
	}

	return allowed;
}

function multicast_stamp(iface_name, records) {
	const now = utils.now_ms();

	for (let record in records)
		multicast_sent[multicast_key(iface_name, record)] = now;
}

/**
 * RFC 6762 Section 7.1: Check if a record is in the known-answer list
 *
 * Known-answer suppression allows queriers to indicate records they already have.
 * TTL must be at least half of our record's TTL to match.
 *
 * @param {object} record - DNS record to check
 * @param {array} known_answers - Array of known answer records
 * @returns {boolean} True if record is in known-answer list
 */
function is_known_answer(record, known_answers) {
	for (let ka in known_answers) {
		if (utils.name_equal(ka.name, record.name) &&
		    ka.type === record.type &&
		    ka.class === record.class &&
		    ka.ttl >= (record.ttl / 2)) {  /* TTL must be at least half */
			if (utils.rdata_equal(record.type, record.rdata, ka.rdata))
				return true;
		}
	}

	return false;
}

/**
 * Check whether a record is already in a list
 * @param {object} record - DNS record
 * @param {array} list - DNS records
 * @returns {boolean} True if an equal record is present
 */
function record_present(record, list) {
	for (let existing in list) {
		if (utils.records_equal(existing, record))
			return true;
	}

	return false;
}

/**
 * Append the records that are not in the target yet
 * @param {array} target - DNS records, modified in place
 * @param {array} records - DNS records to add
 */
export function records_merge(target, records) {
	for (let record in records) {
		if (!record_present(record, target))
			push(target, record);
	}
}

/**
 * The candidates that the present list does not already hold
 * @param {array} candidates - DNS records
 * @param {array} present - DNS records
 * @returns {array} Candidates not present
 */
export function records_missing(candidates, present) {
	const missing = [];

	for (let record in candidates) {
		if (!record_present(record, present))
			push(missing, record);
	}

	return missing;
}

/**
 * RFC 6762 Section 6.7: Adapt a record for a legacy client
 *
 * Legacy clients do not understand the cache-flush bit and do not do cache
 * coherency, so the bit goes and the TTL is capped at 10 seconds.
 *
 * @param {object} record - DNS record
 * @returns {object} Copy suitable for a legacy response
 */
function legacy_record(record) {
	const copy = { ...record };

	copy.flush_cache = false;

	if (copy.ttl > c.LEGACY_MAX_TTL_SEC)
		copy.ttl = c.LEGACY_MAX_TTL_SEC;

	return copy;
}

/**
 * RFC 6762 Section 6.7: Send legacy unicast response
 *
 * Legacy queries from non-5353 ports require special handling:
 * - Remove cache-flush bit (not understood by legacy clients)
 * - Cap TTL at 10 seconds (legacy clients don't do cache coherency)
 * - MUST match query ID
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records to send
 * @param {array} additional - Records for the additional section
 * @param {object} legacy_info - Legacy query info with { query_id, question, dest }
 */
function legacy_allowed(dest) {
	const key = dest?.address ?? '';

	if (!legacy_sent[key])
		legacy_sent[key] = {};

	return utils.rate_allow(legacy_sent[key], c.LEGACY_RESPONSE_LIMIT);
}

function send_legacy_response(iface_name, records, additional, legacy_info) {
	if (!legacy_allowed(legacy_info.dest)) {
		mdns.debug(`response: Legacy response rate limited for ${legacy_info.dest?.address}\n`);
		return;
	}

	/* RFC 6762 Section 6.7: Modify records for legacy clients
	 * - Remove cache-flush bit (not understood by legacy clients)
	 * - Cap TTL at 10 seconds (legacy clients don't do cache coherency) */
	const legacy_records = map(records, legacy_record);
	const legacy_additional = map(records_missing(additional || [], records), legacy_record);

	const packet = {
		/* RFC 6762 Section 18.14: no name compression on SRV in a legacy
		 * unicast response */
		legacy: true,
		header: {
			id: legacy_info.query_id,  /* RFC 6762 Section 6.7: MUST match query ID */
			flags: {
				response: true,
				authoritative: true,
				truncated: false,
				recursion_desired: false
			}
		},
		/* RFC 6762 Section 6.7: MUST repeat the question from the query */
		questions: legacy_info.question ? [legacy_info.question] : [],
		answers: legacy_records,
		authority: [],
		additional: legacy_additional
	};

	if (!mdns.packet_send(iface_name, packet, legacy_info.dest)) {
		log.ERR(`response: Failed to send legacy response: ${mdns.error()}\n`);
		return;
	}

	mdns.info(`response: Sent legacy unicast response to ${legacy_info.dest.address}:${legacy_info.dest.port}\n`);
}

/**
 * RFC 6762 Section 6, 8.1: Send immediate response for probe defence
 *
 * Probe responses MUST be sent immediately to defend our name.
 * Applies ≥250ms rate limit for probe defence.
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records to send
 * @param {object} unicast_dest - Unicast destination or null for multicast
 */
function send_response_immediate(iface_name, records, additional, unicast_dest) {
	/* RFC 6762 Section 6: Apply ≥250ms rate limit for probe defence */
	const now = utils.now_ms();
	const filtered_records = [];

	for (let record in records) {
		const key = `${iface_name}:${record.name}:${record.type}`;
		const last = probe_defence_sent[key] || 0;

		if (now - last >= c.PROBE_DEFENCE_RATE_LIMIT_MS) {
			push(filtered_records, record);
			probe_defence_sent[key] = now;
		} else {
			mdns.debug(`response: Probe defence rate limited for ${record.type} ${record.name}\n`);
		}
	}

	if (length(filtered_records) === 0)
		return;  /* All rate limited */

	const packet = {
		header: {
			id: 0,
			flags: {
				response: true,
				authoritative: true,
				truncated: false,
				recursion_desired: false
			}
		},
		questions: [],
		answers: filtered_records,
		authority: [],
		additional: records_missing(additional || [], filtered_records)
	};

	if (!mdns.packet_send(iface_name, packet, unicast_dest)) {
		log.ERR(`response: Failed to send probe defence: ${mdns.error()}\n`);
		return;
	}

	mdns.debug(`response: Sent immediate probe defence response${unicast_dest ? " (unicast)" : ""}\n`);
}

/**
 * Send pending response
 *
 * RFC 6762 Section 6: Updates rate limit timestamps after successful send.
 *
 * @param {string} iface_name - Interface name
 */
function send_response(key) {
	const pending = pending_responses[key];
	if (!pending)
		return;

	const iface_name = pending.iface_name;

	delete pending_responses[key];

	const answers = pending.unicast_dest ? pending.records
	                                     : multicast_filter(iface_name, pending.records);

	if (!length(answers))
		return;

	const packet = {
		header: {
			id: 0,
			flags: {
				response: true,
				authoritative: true,
				truncated: false,
				recursion_desired: false
			}
		},
		questions: [],
		answers: answers,
		authority: [],
		additional: records_missing(pending.additional, answers)
	};

	/* Send via C binding - unicast if dest specified, multicast otherwise */
	if (!mdns.packet_send(iface_name, packet, pending.unicast_dest)) {
		log.ERR(`response: Failed to send response: ${mdns.error()}\n`);
		return;
	}

	if (pending.unicast_dest) {
		mdns.debug(`response: Sent unicast response to ${pending.unicast_dest.address}:${pending.unicast_dest.port}\n`);
		return;
	}

	multicast_stamp(iface_name, answers);
	multicast_stamp(iface_name, packet.additional);
}

/**
 * Suppress known answers from response records
 *
 * RFC 6762 Section 7.1: Known-answer suppression.
 *
 * @param {array} records - DNS records to filter
 * @param {array} known_answers - Known answer records from query
 * @returns {array} Filtered records excluding known answers
 */
export function suppress_known_answers(records, known_answers) {
	const suppressed = [];
	for (let record in records) {
		if (!is_known_answer(record, known_answers))
			push(suppressed, record);
	}
	return suppressed;
};

/**
 * RFC 6762 Section 6: Schedule a response with delay for aggregation
 *
 * Response delay logic:
 * - Probe defence: 0ms (immediate)
 * - TC bit set: 400-500ms (Section 7.2)
 * - All unique records (sole responder): ≤10ms
 * - Shared records: 20-120ms
 * - Legacy unicast: immediate (Section 6.7)
 *
 * RFC 6762 Section 6.4: Aggregates responses to reduce network traffic.
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records to send
 * @param {array} additional - RFC 6763 Section 12 additional records, may be null
 * @param {object} unicast_dest - Unicast destination or null for multicast
 * @param {boolean} tc_bit_set - True if TC bit set in query
 * @param {boolean} all_unique - True if all records are unique (non-shared)
 * @param {boolean} is_probe - True if this is a probe query
 * @param {object} legacy_info - Legacy query info with { query_id, dest } or null
 */
export function schedule(iface_name, records, additional, unicast_dest, tc_bit_set, all_unique, is_probe, legacy_info) {
	/* RFC 6762 Section 6: a multicast response and a unicast one go to
	 * different audiences, so they aggregate separately */
	const key = `${iface_name}|${unicast_dest?.address ?? ''}`;
	const pending = pending_responses[key];

	/* RFC 6762 Section 6.7: Legacy unicast responses sent immediately,
	 * independent of any pending multicast aggregate */
	if (legacy_info) {
		send_legacy_response(iface_name, records, additional, legacy_info);
		return;
	}

	/* RFC 6762 Section 6, 8.1: Probe defence responses MUST be immediate
	 * Send immediately without delay to defend our name */
	if (is_probe) {
		send_response_immediate(iface_name, records, additional, unicast_dest);
		return;
	}

	if (pending) {
		/* RFC 6762 Section 6.4: Response aggregation
		 * Already have a pending response, add new records to it.
		 * Duplicate detection must include rdata: shared records from
		 * different instances share name, type and class. */
		records_merge(pending.records, records);
		records_merge(pending.additional, additional || []);

	} else {
		/* RFC 6762 Section 6: Choose appropriate response delay
		 * - Probe defence: 0ms (immediate)
		 * - TC bit set: 400-500ms (Section 7.2)
		 * - All unique records (sole responder): ≤10ms
		 * - Shared records: 20-120ms */
		let delay_ms;

		if (tc_bit_set) {
			/* RFC 6762 Section 7.2: Delay 400-500ms when TC bit set
			 * to allow multipacket known-answer suppression */
			delay_ms = utils.tc_delay();
		} else if (all_unique) {
			/* RFC 6762 Section 6: Fast response for unique records
			 * when we're the sole responder */
			delay_ms = c.RESPONSE_DELAY_UNIQUE_MS;
		} else {
			/* RFC 6762 Section 6: Random delay 20-120ms for shared records
			 * to reduce collisions */
			delay_ms = utils.random_delay();
		}

		pending_responses[key] = {
			timer: uloop.timer(delay_ms, function() {
				send_response(key);
			}),
			iface_name: iface_name,
			records: records,
			additional: additional || [],
			unicast_dest: unicast_dest
		};
	}
};

/**
 * Cancel pending responses for interface
 * @param {string} iface_name - Interface name
 */
export function cancel_pending(iface_name) {
	for (let key in keys(pending_responses)) {
		if (pending_responses[key].iface_name !== iface_name)
			continue;

		pending_responses[key].timer.cancel();
		delete pending_responses[key];
	}
};

/**
 * RFC 6762 Section 7.2: apply a late known-answer list to pending responses
 *
 * The continuation packets of a multipacket known-answer list carry no
 * questions, so they arrive after the response they should suppress has
 * already been scheduled.
 *
 * @param {string} iface_name - Interface the continuation arrived on
 * @param {array} known_answers - Known answer records
 */
export function suppress_pending(iface_name, known_answers) {
	for (let key in keys(pending_responses)) {
		const pending = pending_responses[key];

		if (pending.iface_name !== iface_name)
			continue;

		pending.records = suppress_known_answers(pending.records, known_answers);
		pending.additional = suppress_known_answers(pending.additional, known_answers);

		if (length(pending.records))
			continue;

		pending.timer.cancel();
		delete pending_responses[key];
	}
};

/**
 * RFC 6762 Section 6: note that records went out by multicast
 *
 * Announcements and probe defence bypass the pending-response path, so they
 * report their sends here to keep the one-per-second limit honest.
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - Records that were multicast
 */
export function multicast_record(iface_name, records) {
	multicast_stamp(iface_name, records);
};

/**
 * Clean up old probe defence timestamps
 *
 * Remove entries older than specified age to prevent unbounded memory growth.
 *
 * @param {number} max_age_seconds - Maximum age in seconds (default: 3600)
 * @returns {number} Number of entries removed
 */
export function cleanup_probe_defence(max_age_seconds) {
	const threshold = utils.now_ms() - (max_age_seconds || 3600) * 1000;
	let removed = 0;

	for (let key in probe_defence_sent) {
		if (probe_defence_sent[key] < threshold) {
			delete probe_defence_sent[key];
			removed++;
		}
	}

	for (let key in multicast_sent) {
		if (multicast_sent[key] < threshold) {
			delete multicast_sent[key];
			removed++;
		}
	}

	const second = time();

	for (let key in legacy_sent) {
		if (legacy_sent[key].second !== second) {
			delete legacy_sent[key];
			removed++;
		}
	}

	return removed;
};
