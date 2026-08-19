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
 * Tracks last send time per destination and record
 * Cleaned up periodically to prevent unbounded growth */
const probe_defence_sent = {};

/* RFC 6762 Section 6.7: legacy responses sent per source in the current second */
const legacy_sent = {};

/* RFC 6762 Section 6: when each record was last multicast, keyed
 * "iface:name:type:class" for a unique record and with the rdata appended for
 * a shared one. The limit is on multicast on a given interface, so unicast
 * answers, legacy answers and probe defence are not subject to it. */
const multicast_sent = {};

const pending_defences = {};

function pending_key(iface_name, unicast_dest) {
	return `${iface_name}|${unicast_dest?.address ?? ''}`;
}

function record_entry(iface_name, record) {
	const name = utils.name_normalise(record.name);
	const rrset = `${name}:${record.type}:${record.class}`;
	const rdata = name != null ? mdns.rdata_canonical(record) : null;
	const id = rdata != null ? `${rrset}:${hexenc(rdata)}` : null;

	return {
		record,
		rrset,
		id,
		key: `${iface_name}:${record.flush_cache || id == null ? rrset : id}`
	};
}

function entries_make(iface_name, records) {
	return map(records ?? [], record => record_entry(iface_name, record));
}

function entries_records(entries) {
	return map(entries, entry => entry.record);
}

function entries_ids(entries) {
	const ids = {};

	for (let entry in entries) {
		if (entry.id != null)
			ids[entry.id] = entry;
	}

	return ids;
}

function entries_merge(target, entries) {
	const present = entries_ids(target);

	for (let entry in entries) {
		const existing = entry.id != null ? present[entry.id] : null;

		if (existing) {
			if (entry.correction)
				existing.correction = true;
			continue;
		}

		push(target, entry);
		if (entry.id != null)
			present[entry.id] = entry;
	}
}

function entries_missing(candidates, present) {
	const ids = entries_ids(present);

	return filter(candidates, entry => entry.id == null || !ids[entry.id]);
}

/**
 * Append the records that are not in the target yet
 * @param {array} target - DNS records, modified in place
 * @param {array} records - DNS records to add
 */
export function records_merge(target, records) {
	const entries = entries_make(null, target);
	const count = length(entries);

	entries_merge(entries, entries_make(null, records));
	push(target, ...entries_records(slice(entries, count)));
};

/**
 * The candidates that the present list does not already hold
 * @param {array} candidates - DNS records
 * @param {array} present - DNS records
 * @returns {array} Candidates not present
 */
export function records_missing(candidates, present) {
	return entries_records(entries_missing(entries_make(null, candidates), entries_make(null, present)));
};

/**
 * Build an unsolicited response packet
 *
 * @param {array} answers - Records for the answer section
 * @param {array} additional - Records for the additional section, may be null
 * @returns {object} Response packet with query ID 0 and no questions
 */
export function packet_compose(answers, additional) {
	return {
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
		additional: additional ?? []
	};
};

function sent_hold(table, key, now, limit) {
	const last = table[key];

	return last != null ? last + limit - now : 0;
}

function entries_hold(table, entries, now, limit) {
	let hold = 0;

	for (let entry in entries)
		hold = max(hold, sent_hold(table, entry.key, now, limit));

	return hold;
}

function entries_stamp(table, entries, now) {
	for (let entry in entries)
		table[entry.key] = now;
}

/**
 * RFC 6762 Section 6: drop records multicast less than a second ago
 *
 * @param {string} iface_name - Interface name
 * @param {array} entries - Keyed DNS records
 * @param {number} now - Current monotonic time in ms
 * @returns {array} Entries that may go out now
 */
function multicast_filter(iface_name, entries, now) {
	return filter(entries, entry => {
		if (sent_hold(multicast_sent, entry.key, now, c.MULTICAST_RATE_LIMIT_MS) <= 0)
			return true;

		mdns.debug(`response: Rate limited ${entry.record.type} ${entry.record.name} on ${iface_name}\n`);
		return false;
	});
}

/**
 * RFC 6762 Section 6: note that records went out by multicast
 *
 * Announcements and probe defence bypass the pending-response path, so they
 * report their sends here to keep the one-per-second limit honest.
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - Records that were multicast
 */
export function multicast_stamp(iface_name, records) {
	entries_stamp(multicast_sent, entries_make(iface_name, records), utils.now_ms());
};

/**
 * RFC 6762 Section 5.4: check whether a record went out by multicast recently
 *
 * A QU question may get a unicast answer only while the record was multicast
 * within a quarter of its TTL. A record multicast less than a second ago also
 * counts as recent, because the rate limit would hold a multicast back.
 *
 * @param {string} iface_name - Interface name
 * @param {object} record - DNS record
 * @returns {boolean} True if the record was multicast recently
 */
export function multicast_recent(iface_name, record) {
	const limit = max(record.ttl * 250, c.MULTICAST_RATE_LIMIT_MS);

	return sent_hold(multicast_sent, record_entry(iface_name, record).key, utils.now_ms(), limit) > 0;
};

/**
 * RFC 6762 Section 6: time until records may be multicast again
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records
 * @returns {number} Milliseconds to wait, 0 if all records may go out now
 */
export function multicast_wait(iface_name, records) {
	return entries_hold(multicast_sent, entries_make(iface_name, records), utils.now_ms(),
		c.MULTICAST_RATE_LIMIT_MS);
};

function known_index(known_answers) {
	const known = {};

	for (let ka in known_answers) {
		const id = record_entry(null, ka).id;

		if (id != null && (known[id] == null || known[id] < ka.ttl))
			known[id] = ka.ttl;
	}

	return known;
}

function entry_known(entry, known, ttl_share) {
	const ttl = entry.id != null ? known[entry.id] : null;

	return ttl != null && ttl >= entry.record.ttl * ttl_share;
}

/**
 * RFC 6762 Section 7.1: drop the records that are in the known-answer list
 *
 * Known-answer suppression allows queriers to indicate records they already have.
 * The TTL must be at least half of our record's TTL to match, or the given
 * share of it. A unique RRSet that still has to be sent goes out whole
 * (Section 10.2).
 *
 * @param {array} entries - Keyed DNS records
 * @param {object} known - Known answers from known_index()
 * @param {number} ttl_share - Least share of our TTL, 0.5 if null
 * @returns {array} Entries still to send
 */
function entries_suppress(entries, known, ttl_share) {
	const share = ttl_share ?? 0.5;
	const unknown = {};
	const kept = [];

	for (let entry in entries) {
		if (!entry_known(entry, known, share))
			unknown[entry.rrset] = true;
	}

	for (let entry in entries) {
		if (unknown[entry.rrset] && (entry.record.flush_cache || !entry_known(entry, known, share)))
			push(kept, entry);
	}

	return kept;
}

/**
 * Suppress known answers from response records
 *
 * RFC 6762 Section 7.1: Known-answer suppression. A unique RRSet that still
 * has to be sent goes out whole (Section 10.2).
 *
 * @param {array} records - DNS records to filter
 * @param {array} known_answers - Known answer records from query
 * @returns {array} Filtered records excluding known answers
 */
export function suppress_known_answers(records, known_answers) {
	return entries_records(entries_suppress(entries_make(null, records), known_index(known_answers)));
};

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

function legacy_budget(dest) {
	const key = dest?.address ?? '';

	legacy_sent[key] ??= {};

	return legacy_sent[key];
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
 * @param {object} legacy_info - Legacy query info with { query_id, questions, dest }
 */
function send_legacy_response(iface_name, records, additional, legacy_info) {
	const budget = legacy_budget(legacy_info.dest);

	if (!utils.rate_allow(budget, c.LEGACY_RESPONSE_LIMIT)) {
		mdns.debug(`response: Legacy response rate limited for ${legacy_info.dest?.address}\n`);
		return;
	}

	/* RFC 6762 Section 6.7: Modify records for legacy clients
	 * - Remove cache-flush bit (not understood by legacy clients)
	 * - Cap TTL at 10 seconds (legacy clients don't do cache coherency) */
	const packet = packet_compose(map(records, legacy_record),
		map(records_missing(additional ?? [], records), legacy_record));

	/* RFC 6762 Section 18.14: no name compression on SRV in a legacy
	 * unicast response */
	packet.legacy = true;
	packet.header.id = legacy_info.query_id;  /* RFC 6762 Section 6.7: MUST match query ID */
	/* RFC 6762 Section 6.7: MUST repeat the question from the query */
	packet.questions = legacy_info.questions;

	const sent = mdns.packet_send(iface_name, packet, legacy_info.dest, true);

	if (sent) {
		mdns.info(`response: Sent legacy unicast response to ${legacy_info.dest.address}:${legacy_info.dest.port}\n`);
		return;
	}

	budget.count--;

	legacy_info.retry_until ??= utils.now_ms() + c.LEGACY_RETRY_LIMIT_MS;

	if (sent == null || utils.now_ms() >= legacy_info.retry_until) {
		log.ERR(`response: Failed to send legacy response: ${mdns.error()}\n`);
		return;
	}

	uloop.timer(c.SEND_RETRY_MS, () => send_legacy_response(iface_name, records, additional, legacy_info));
}

function response_send(iface_name, answers, additional, unicast_dest, now) {
	const extra = entries_missing(unicast_dest ? additional : multicast_filter(iface_name, additional, now), answers);
	const packet = packet_compose(entries_records(answers), entries_records(extra));

	/* Send via C binding - unicast if dest specified, multicast otherwise */
	const sent = mdns.packet_send(iface_name, packet, unicast_dest, true);

	if (sent == null)
		log.ERR(`response: Failed to send response on ${iface_name}: ${mdns.error()}\n`);
	else if (sent && !unicast_dest)
		entries_stamp(multicast_sent, [ ...answers, ...extra ], now);

	return sent;
}

function defence_table(key, unicast_dest) {
	if (!unicast_dest)
		return multicast_sent;

	probe_defence_sent[key] ??= {};

	return probe_defence_sent[key];
}

function defence_send(key) {
	const defence = pending_defences[key];
	const now = utils.now_ms();
	const table = defence_table(key, defence.unicast_dest);
	let wait = entries_hold(table, defence.answers, now, c.PROBE_DEFENCE_RATE_LIMIT_MS);

	defence.timer = null;

	if (wait <= 0 && length(defence.answers)) {
		const sent = response_send(defence.iface_name, defence.answers, defence.additional,
			defence.unicast_dest, now);

		if (sent && defence.unicast_dest)
			entries_stamp(table, defence.answers, now);

		wait = sent === false ? c.SEND_RETRY_MS : 0;
	}

	if (wait <= 0) {
		delete pending_defences[key];
		return;
	}

	mdns.debug(`response: Probe defence on ${defence.iface_name} delayed by ${wait} ms\n`);
	defence.timer = uloop.timer(wait, () => defence_send(key));
}

/**
 * RFC 6762 Section 6, 8.1: Send immediate response for probe defence
 *
 * Probe responses MUST be sent immediately to defend our name.
 * Applies ≥250ms rate limit for probe defence. A defence that has to wait
 * takes in the records of later defences to the same destination.
 *
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records to send
 * @param {array} additional - Records for the additional section
 * @param {object} unicast_dest - Unicast destination or null for multicast
 */
function send_response_immediate(iface_name, records, additional, unicast_dest) {
	const key = pending_key(iface_name, unicast_dest);
	const defence = pending_defences[key] ?? { iface_name, unicast_dest, answers: [], additional: [] };

	entries_merge(defence.answers, entries_make(iface_name, records));
	entries_merge(defence.additional, entries_make(iface_name, additional));
	pending_defences[key] = defence;

	defence.timer?.cancel();
	defence_send(key);
}

/**
 * Send pending response
 *
 * RFC 6762 Section 6: Updates rate limit timestamps after successful send.
 * A correction the rate limit holds back stays pending.
 *
 * @param {string} key - Pending response key
 * @returns {number|null} Monotonic time in ms to try again, null when done
 */
function send_response(key) {
	const pending = pending_responses[key];
	if (!pending)
		return null;

	const now = utils.now_ms();
	const multicast = !pending.unicast_dest;
	const answers = multicast ? multicast_filter(pending.iface_name, pending.answers, now) : pending.answers;
	const held = filter(pending.answers, entry => entry.correction &&
		sent_hold(multicast_sent, entry.key, now, c.MULTICAST_RATE_LIMIT_MS) > 0);
	const sent = length(answers) ?
		response_send(pending.iface_name, answers, pending.additional, pending.unicast_dest, now) : true;

	if (sent === false)
		return now + c.SEND_RETRY_MS;

	if (sent && !multicast)
		mdns.debug(`response: Sent unicast response to ${pending.unicast_dest.address}:${pending.unicast_dest.port}\n`);

	if (sent == null || !length(held)) {
		delete pending_responses[key];
		return null;
	}

	pending.answers = held;
	pending.additional = [];

	return now + entries_hold(multicast_sent, held, now, c.MULTICAST_RATE_LIMIT_MS);
}

function pending_timer(key, deadline, not_before) {
	const pending = pending_responses[key];

	pending.deadline = deadline;
	pending.not_before = not_before;
	pending.timer?.cancel();
	pending.timer = uloop.timer(max(0, deadline - utils.now_ms()), () => {
		const next = send_response(key);

		if (next != null)
			pending_timer(key, next, next);
	});
}

function pending_postpone(key) {
	const deadline = utils.now_ms() + utils.tc_delay();

	pending_timer(key, deadline, deadline);
}

function pending_add(key, iface_name, unicast_dest, answers, additional, querier) {
	pending_responses[key] = {
		iface_name: iface_name,
		unicast_dest: unicast_dest,
		answers: answers,
		additional: additional,
		queriers: querier != null ? { [querier]: true } : {}
	};
}

function pending_prune(table, key) {
	const pending = table[key];

	if (length(pending.answers))
		return;

	pending.timer?.cancel();
	delete table[key];
}

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
 * @param {object} legacy_info - Legacy query info with { query_id, questions, dest } or null
 * @param {string} querier - Source address of the query
 */
export function schedule(iface_name, records, additional, unicast_dest, tc_bit_set, all_unique, is_probe, legacy_info, querier) {
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

	/* RFC 6762 Section 6: a multicast response and a unicast one go to
	 * different audiences, so they aggregate separately */
	const key = pending_key(iface_name, unicast_dest);
	const pending = pending_responses[key];
	const answers = entries_make(iface_name, records);
	const extra = entries_make(iface_name, additional);

	if (pending) {
		/* RFC 6762 Section 6.4: Response aggregation
		 * Already have a pending response, add new records to it.
		 * Duplicate detection must include rdata: shared records from
		 * different instances share name, type and class. */
		entries_merge(pending.answers, answers);
		entries_merge(pending.additional, extra);
		pending.queriers[querier] = true;

		if (tc_bit_set)
			pending_postpone(key);
		return;
	}

	pending_add(key, iface_name, unicast_dest, answers, extra, querier);

	/* RFC 6762 Section 6: Choose appropriate response delay
	 * - Probe defence: 0ms (immediate)
	 * - TC bit set: 400-500ms (Section 7.2)
	 * - All unique records (sole responder): ≤10ms
	 * - Shared records: 20-120ms */
	const now = utils.now_ms();

	if (tc_bit_set) {
		/* RFC 6762 Section 7.2: Delay 400-500ms when TC bit set
		 * to allow multipacket known-answer suppression */
		pending_postpone(key);
	} else if (all_unique) {
		/* RFC 6762 Section 6: Fast response for unique records
		 * when we're the sole responder */
		pending_timer(key, now + c.RESPONSE_DELAY_UNIQUE_MS, now);
	} else {
		/* RFC 6762 Section 6: Random delay 20-120ms for shared records
		 * to reduce collisions */
		pending_timer(key, now + utils.random_delay(), now + c.RESPONSE_DELAY_MIN_MS);
	}
};

/**
 * Cancel pending responses for interface
 * @param {string} iface_name - Interface name
 */
export function cancel_pending(iface_name) {
	for (let table in [ pending_responses, pending_defences ]) {
		for (let key in keys(table)) {
			if (table[key].iface_name !== iface_name)
				continue;

			table[key].timer?.cancel();
			delete table[key];
		}
	}
};

function entry_names(entry, name) {
	const record = entry.record;

	return utils.name_equal(record.name, name) ||
	       (record.type === 'PTR' && utils.name_equal(record.rdata?.ptr, name));
}

/**
 * Drop the delayed answers that belong to a name we stopped claiming
 *
 * Removes the records of the name, and PTR records that point to it, from
 * every pending response on the interface.
 *
 * @param {string} iface_name - Interface name
 * @param {string} name - Name that is no longer ours
 */
export function cancel_name(iface_name, name) {
	for (let table in [ pending_responses, pending_defences ]) {
		for (let key in keys(table)) {
			const pending = table[key];

			if (pending.iface_name !== iface_name)
				continue;

			pending.answers = filter(pending.answers, entry => !entry_names(entry, name));
			pending.additional = filter(pending.additional, entry => !entry_names(entry, name));
			pending_prune(table, key);
		}
	}
};

/**
 * RFC 6762 Section 7.2: apply a late known-answer list to pending responses
 *
 * The continuation packets of a multipacket known-answer list carry no
 * questions, so they arrive after the response they should suppress has
 * already been scheduled. A continuation affects only the responses its
 * sender waits for, and deletes answers only from a response no other host
 * waits for. Known answers never suppress a probe defence.
 *
 * @param {string} iface_name - Interface the continuation arrived on
 * @param {array} known_answers - Known answer records
 * @param {boolean} tc_bit_set - True if more known answers follow
 * @param {string} querier - Source address of the continuation
 */
export function suppress_pending(iface_name, known_answers, tc_bit_set, querier) {
	const known = known_index(known_answers);

	for (let key in keys(pending_responses)) {
		const pending = pending_responses[key];

		if (pending.iface_name !== iface_name || !pending.queriers[querier])
			continue;

		if (length(pending.queriers) == 1) {
			pending.answers = entries_suppress(pending.answers, known);
			pending.additional = entries_suppress(pending.additional, known);
		}

		if (tc_bit_set)
			pending_postpone(key);

		pending_prune(pending_responses, key);
	}
};

/**
 * RFC 6762 Section 7.4: drop answers another host just multicast
 *
 * A record we plan to multicast, seen in another host's multicast response
 * with a TTL no less than ours, counts as sent. A unique RRSet is dropped
 * only when every member was seen.
 *
 * @param {string} iface_name - Interface the response arrived on
 * @param {array} records - Records of the received response
 */
export function duplicate_observe(iface_name, records) {
	const known = known_index(records);

	for (let key in keys(pending_responses)) {
		const pending = pending_responses[key];

		if (pending.iface_name !== iface_name || pending.unicast_dest)
			continue;

		pending.answers = entries_suppress(pending.answers, known, 1);
		pending.additional = entries_suppress(pending.additional, known, 1);
		pending_prune(pending_responses, key);
	}
};

function table_expire(table, threshold) {
	let removed = 0;

	for (let key in keys(table)) {
		if (table[key] >= threshold)
			continue;

		delete table[key];
		removed++;
	}

	return removed;
}

/**
 * Clean up old rate limit timestamps
 *
 * Remove entries older than specified age to prevent unbounded memory growth.
 *
 * @param {number} max_age_seconds - Maximum age in seconds (default: 3600)
 * @returns {number} Number of entries removed
 */
export function history_expire(max_age_seconds) {
	const now = utils.now_ms();
	const threshold = now - (max_age_seconds || 3600) * 1000;
	const second = int(now / 1000);
	let removed = table_expire(multicast_sent, threshold);

	for (let key in keys(probe_defence_sent)) {
		removed += table_expire(probe_defence_sent[key], threshold);

		if (!length(probe_defence_sent[key]))
			delete probe_defence_sent[key];
	}

	for (let key in keys(legacy_sent)) {
		if (legacy_sent[key].second === second)
			continue;

		delete legacy_sent[key];
		removed++;
	}

	return removed;
};

function correction_schedule(iface_name, rrset, unique) {
	const key = pending_key(iface_name, null);
	const entries = entries_make(iface_name, rrset);
	const now = utils.now_ms();
	const earliest = now + entries_hold(multicast_sent, entries, now, c.MULTICAST_RATE_LIMIT_MS);
	const deadline = max(earliest, now + (unique ? c.RESPONSE_DELAY_UNIQUE_MS : utils.random_delay()));
	const pending = pending_responses[key];

	for (let entry in entries)
		entry.correction = true;

	if (!pending) {
		pending_add(key, iface_name, null, entries, [], null);
		pending_timer(key, deadline, unique ? now : now + c.RESPONSE_DELAY_MIN_MS);
		return;
	}

	entries_merge(pending.answers, entries);

	const target = max(deadline, pending.not_before);

	if (target < pending.deadline)
		pending_timer(key, target, pending.not_before);
}

/**
 * RFC 6762 Section 6.6: correct a stale TTL that another host advertised
 *
 * A copy of one of our records with less than half its TTL, a goodbye of a
 * cooperating responder included, makes listeners drop data we still serve.
 * The whole RRSet is multicast again, as soon as the rate limit allows. A
 * response already pending keeps its deadline unless the correction may go
 * out earlier, and a response held back for a multipacket known-answer list
 * keeps its deadline.
 *
 * @param {string} iface_name - Interface the copy arrived on
 * @param {array} records - Our authoritative records on that interface
 * @param {object} observed - Received record
 * @returns {boolean} True if a correction was scheduled
 */
export function correct_low_ttl(iface_name, records, observed) {
	for (let ours in records) {
		if (!utils.records_equal(ours, observed) || observed.ttl >= ours.ttl / 2.0)
			continue;

		const rrset = filter(records, record => utils.name_equal(record.name, ours.name) &&
			record.type === ours.type && record.class === ours.class);

		correction_schedule(iface_name, rrset, !!ours.flush_cache);
		return true;
	}

	return false;
};
