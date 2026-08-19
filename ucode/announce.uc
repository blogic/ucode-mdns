/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * announce.uc - Probing and announcing
 *
 * Implements RFC 6762 probing/announcing/conflict resolution.
 * Handles name claiming with tiebreaking.
 *
 * The state machine works on named entries. An entry supplies its records,
 * its conflict handler and its state reporter through the ops object passed
 * to start_probe(), so service instances, the host name and the dynamic
 * DNS-SD registrations share one implementation. An entry that cannot rename
 * supplies a fail handler instead, which removes the link that lost.
 *
 * RFC 6762 Sections 8 and 14: uniqueness is verified per link. Every link a
 * name is claimed on runs its own probe and announce sequence, so a link that
 * comes up later probes alone and the links already announced keep answering.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as utils from 'utils';
import * as packet from 'packet';
import * as response from 'response';
import * as uloop from 'uloop';
import * as mdns from 'mdns';
import * as log from 'log';
import * as c from 'const';

/* Probing/announcing state per claimed name
 * {
 *   "My Printer._http._tcp.local.": {
 *     ops: { records, conflict, state, link, fail },
 *     reported: "probing|announcing|announced",
 *     links: {
 *       "br-lan": {
 *         iface: "br-lan",
 *         state: "probing|announcing|announced",
 *         probe_count: 0,
 *         announce_count: 0,
 *         timer: uloop_timer,
 *         updates: [now_ms1, now_ms2, ...]  (RFC 6762 Section 8.4),
 *         update_timer: uloop_timer
 *       }
 *     },
 *     conflict_history: [now_ms1, now_ms2, ...]  (RFC 6762 Section 8.1)
 *   }
 * }
 */
const announce_state = {};
const goodbye_retries = {};
const update_history = {};
const conflict_history = {};

export const FAIL_CONFLICT = 1;
export const FAIL_SEND = 2;

function link_key(name, iface_name) {
	return `${name}|${iface_name}`;
}

function history_recent(table, key, window_ms, now) {
	table[key] = filter(table[key] ?? [], stamp => stamp > now - window_ms);

	return table[key];
}

function link_release(name, link) {
	link.timer?.cancel();
	link.update_timer?.cancel();
	response.cancel_name(link.iface, name);

	if (link.state === 'probing')
		return;

	const now = utils.now_ms();

	push(history_recent(update_history, link_key(name, link.iface), c.UPDATE_WINDOW_MS, now), now);
}

/**
 * Cancel probing/announcing for an entry
 * @param {string} name - Claimed name
 */
export function cancel(name) {
	const state = announce_state[name];
	if (!state)
		return;

	for (let iface_name, link in state.links)
		link_release(name, link);

	delete announce_state[name];
};

function record_order(record) {
	return {
		class: utils.code_number(c.CLASS_NUMBERS, record.class),
		type: utils.code_number(c.TYPE_NUMBERS, record.type),
		rdata: mdns.rdata_encode(record) ?? ''
	};
}

/**
 * RFC 6762 Section 8.2: Lexicographic comparison for simultaneous probe tiebreaking
 *
 * Compare records byte-by-byte as unsigned 8-bit values in order: class, type, rdata.
 *
 * @param {object} r1 - First record, as returned by record_order()
 * @param {object} r2 - Second record, as returned by record_order()
 * @returns {number} -1 if r1 < r2, 0 if equal, 1 if r1 > r2
 */
function compare_records_lexicographic(r1, r2) {
	/* Compare class (as 16-bit big-endian) */
	if (r1.class < r2.class) return -1;
	if (r1.class > r2.class) return 1;

	/* Compare type (as 16-bit big-endian) */
	if (r1.type < r2.type) return -1;
	if (r1.type > r2.type) return 1;

	/* RFC 6762 Section 8.2: the raw binary rdata, names uncompressed */
	const rdata1 = r1.rdata;
	const rdata2 = r2.rdata;

	const len = min(length(rdata1), length(rdata2));
	for (let i = 0; i < len; i++) {
		const byte1 = ord(rdata1, i);
		const byte2 = ord(rdata2, i);
		if (byte1 < byte2) return -1;
		if (byte1 > byte2) return 1;
	}

	/* If all bytes equal, shorter record wins */
	if (length(rdata1) < length(rdata2)) return -1;
	if (length(rdata1) > length(rdata2)) return 1;

	return 0;
}

/**
 * Send an unsolicited response carrying the entry records
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 * @param {array} records - DNS records to announce
 * @param {boolean} immediate - True to fail rather than queue the packet
 * @returns {boolean|null} True if sent, false if a later try may succeed,
 *   null if the send can never succeed
 */
function send_records(name, iface_name, records, immediate) {
	const sent = mdns.packet_send(iface_name, response.packet_compose(records), null, immediate);

	if (sent)
		response.multicast_stamp(iface_name, records);
	else if (sent == null)
		log.ERR(`announce: Failed to send records of ${name} on ${iface_name}: ${mdns.error()}\n`);

	return sent;
}

/**
 * Report the combined state of all links to the entry owner
 *
 * A name counts as announced once every link announced it, and as announcing
 * while it is published on at least one link.
 *
 * @param {string} name - Claimed name
 * @param {object} state - Entry state
 */
function state_report(name, state) {
	let published = false;
	let announced = true;

	for (let iface_name, link in state.links) {
		if (link.state !== 'probing')
			published = true;
		if (link.state !== 'announced')
			announced = false;
	}

	const combined = announced ? 'announced' : (published ? 'announcing' : 'probing');

	if (combined === state.reported)
		return;

	state.reported = combined;
	if (state.ops.state)
		state.ops.state(name, combined);
}

function link_current(name, link) {
	return announce_state[name]?.links?.[link.iface] === link;
}

function link_state_set(name, link, value) {
	const state = announce_state[name];

	link.state = value;
	state.ops.link?.(name, link.iface, value);

	if (announce_state[name] === state)
		state_report(name, state);
}

/**
 * Stop claiming a name on one interface
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 */
export function iface_remove(name, iface_name) {
	const state = announce_state[name];
	const link = state?.links[iface_name];

	if (!link)
		return;

	link_release(name, link);
	delete state.links[iface_name];

	if (!length(state.links))
		cancel(name);
	else
		state_report(name, state);
};

function link_fail(name, link, reason) {
	const ops = announce_state[name].ops;

	if (!ops.fail)
		return false;

	iface_remove(name, link.iface);
	ops.fail(name, link.iface, reason);

	return true;
}

function link_timer(name, link, delay, callback) {
	link.timer?.cancel();
	link.timer = uloop.timer(delay, function() {
		if (link_current(name, link))
			callback(name, link);
	});
}

/**
 * Send an announcement on one link
 *
 * RFC 6762 Section 8.3: Sends announcements with exponential backoff
 * (1 second, 2 seconds, 4 seconds, ...). Limited to 8 announcements.
 *
 * @param {string} name - Claimed name
 * @param {object} link - Link state
 */
function send_announcement(name, link) {
	const state = announce_state[name];
	const records = state.ops.records(name, null, link.iface);
	const wait = response.multicast_wait(link.iface, records);

	if (wait > 0) {
		link_timer(name, link, wait, send_announcement);
		return;
	}

	if (!length(records)) {
		link_timer(name, link, c.ANNOUNCE_RETRY_MS, send_announcement);
		return;
	}

	const sent = send_records(name, link.iface, records, true);

	if (sent === false) {
		link_timer(name, link, c.SEND_RETRY_MS, send_announcement);
		return;
	}

	if (sent == null) {
		link.timer = null;
		link_fail(name, link, FAIL_SEND);
		return;
	}

	link.announce_count++;

	if (link.announce_count < c.ANNOUNCEMENT_COUNT_MAX) {
		link_timer(name, link, utils.announcement_delay(link.announce_count),
			send_announcement);
		return;
	}

	link.timer = null;
	link_state_set(name, link, 'announced');
}

/**
 * Start announcing on one link after successful probing
 * @param {string} name - Claimed name
 * @param {object} link - Link state
 */
function start_announcing(name, link) {
	link.announce_count = 0;
	link_state_set(name, link, 'announcing');

	if (link_current(name, link))
		send_announcement(name, link);
}

/**
 * Send a probe query on one link
 *
 * RFC 6762 Section 8.2: Populates Authority Section with ALL proposed records
 * for simultaneous probe tiebreaking via lexicographic comparison.
 *
 * @param {string} name - Claimed name
 * @param {object} link - Link state
 */
function send_probe(name, link) {
	const state = announce_state[name];

	/* Build probe query (question for our name, with our records as authority) */
	const questions = [
		{
			name: name,
			type: 'ANY',
			class: 'IN',
			unicast_response: true  /* RFC 6762 Section 8.1: SHOULD set QU bit */
		}
	];

	/* RFC 6762 Section 8.2: MUST populate Authority Section with ALL proposed
	 * records. This allows simultaneous probe tiebreaking via lexicographic
	 * comparison.
	 *
	 * Section 10.2 puts the cache-flush bit in the Resource Record Sections
	 * of responses only, and a probe is a query. Section 8.1 probes for the
	 * records we want to be unique, which excludes the shared DNS-SD PTR
	 * whose owner name is the service type rather than the name we claim. */
	const authority_records = [];

	for (let record in state.ops.records(name, null, link.iface)) {
		if (!utils.name_equal(record.name, name))
			continue;

		push(authority_records, { ...record, flush_cache: false });
	}

	if (!length(authority_records)) {
		link_timer(name, link, c.ANNOUNCE_RETRY_MS, send_probe);
		return;
	}

	const sent = packet.send_query(link.iface, questions, false, null, authority_records);

	if (sent === false) {
		link_timer(name, link, c.SEND_RETRY_MS, send_probe);
		return;
	}

	if (sent == null) {
		log.ERR(`announce: Cannot send a probe for ${name} on ${link.iface}\n`);
		link.timer = null;
		link_fail(name, link, FAIL_SEND);
		return;
	}

	link.probe_count++;

	/* RFC 6762 Section 8.1: Send 3 probes, 250ms apart, then wait 250ms */
	if (link.probe_count < c.PROBE_COUNT)
		link_timer(name, link, c.PROBE_INTERVAL_MS, send_probe);
	else
		link_timer(name, link, c.PROBE_INTERVAL_MS, start_announcing);
}

/**
 * Restart the probe sequence on one link
 *
 * @param {string} name - Claimed name
 * @param {object} link - Link state
 * @param {number} delay - Milliseconds before the first probe
 */
function link_probe(name, link, delay) {
	response.cancel_name(link.iface, name);
	link.update_timer?.cancel();
	link.update_timer = null;
	link.probe_count = 0;
	link.announce_count = 0;
	link_state_set(name, link, 'probing');

	link_timer(name, link, delay, send_probe);
}

function history_wait(history, limit, window_ms, now) {
	return length(history) >= limit ? history[0] + window_ms - now : 0;
}

/**
 * update_wait - time until a name may be updated again on one interface
 * @name: claimed name
 * @iface_name: interface name
 *
 * Return: milliseconds until the RFC 6762 Section 8.4 limit allows an
 *         update, 0 if an update may happen now
 */
export function update_wait(name, iface_name) {
	const now = utils.now_ms();
	const history = history_recent(update_history, link_key(name, iface_name), c.UPDATE_WINDOW_MS, now);

	return history_wait(history, c.UPDATE_RATE_LIMIT, c.UPDATE_WINDOW_MS, now);
};

function claim_delay(name, iface_name) {
	const now = utils.now_ms();
	const conflicts = history_recent(conflict_history, name, c.CONFLICT_HISTORY_WINDOW_SEC * 1000, now);
	const backoff = length(conflicts) >= c.CONFLICT_RATE_LIMIT ? c.CONFLICT_BACKOFF_MS : 0;

	return max(backoff, update_wait(name, iface_name)) + utils.probe_delay();
}

/**
 * Start probing for an entry on one interface (RFC 6762 Section 8.1)
 *
 * Sends first probe after random delay [0-250ms], added to the wait of the
 * conflict backoff (Section 8.1) or the update limit (Section 8.4) while
 * either holds for the name.
 * Probes are queries with QU bit and authority section containing our records.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 * @param {object} ops - Entry operations { records, conflict, state, link,
 *   fail }; link(name, iface_name, state) hears each state change of a link,
 *   fail(name, iface_name, reason) replaces renaming and hears a link lost
 *   to FAIL_CONFLICT or FAIL_SEND
 * @returns {boolean} True if the interface is now claimed
 */
export function start_probe(name, iface_name, ops) {
	let state = announce_state[name];

	if (state?.links[iface_name])
		return false;

	if (!state) {
		if (!ops?.records)
			return false;

		state = announce_state[name] = { ops, links: {}, conflict_history: conflict_history[name] };
	}

	const link = { iface: iface_name };
	const retry = link_key(name, iface_name);

	for (let timer in goodbye_retries[retry] ?? [])
		timer.cancel();
	delete goodbye_retries[retry];

	state.links[iface_name] = link;
	link_probe(name, link, claim_delay(name, iface_name));

	return true;
};

function link_update(name, link) {
	link.update_timer = null;

	if (!link_current(name, link) || link.state === 'probing')
		return;

	const now = utils.now_ms();

	link.updates = history_recent(update_history, link_key(name, link.iface), c.UPDATE_WINDOW_MS, now);

	const wait = history_wait(link.updates, c.UPDATE_RATE_LIMIT, c.UPDATE_WINDOW_MS, now);

	if (wait > 0) {
		link.update_timer = uloop.timer(wait, () => link_update(name, link));
		return;
	}

	push(link.updates, now);
	start_announcing(name, link);
}

/**
 * Re-announce a claimed name after its addresses changed
 *
 * RFC 6762 Sections 8 and 8.4: an address change makes the records we
 * published stale. The name itself is not in question, so the link restarts
 * its announcements rather than its probes. A link restarts at most ten
 * times per minute; a later change waits for the limit and then announces
 * the records current at that time.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface whose addresses changed
 * @returns {boolean} True if the link announces again, now or once the
 *   limit allows
 */
export function refresh(name, iface_name) {
	const link = announce_state[name]?.links[iface_name];

	if (!link || link.state === 'probing')
		return false;

	if (!link.update_timer)
		link_update(name, link);

	return true;
};

/**
 * RFC 6762 Section 8.2.1: compare two proposed record sets
 *
 * Both sets are sorted and walked in step. The first difference decides; if
 * one set runs out first the longer set wins.
 *
 * @param {array} ours - Our proposed records
 * @param {array} theirs - The peer's proposed records
 * @returns {number} -1 if ours loses, 0 if identical, 1 if ours wins
 */
function compare_record_sets(ours, theirs) {
	const a = sort(map(ours, record_order), compare_records_lexicographic);
	const b = sort(map(theirs, record_order), compare_records_lexicographic);
	const len = min(length(a), length(b));

	for (let i = 0; i < len; i++) {
		const cmp = compare_records_lexicographic(a[i], b[i]);
		if (cmp !== 0)
			return cmp;
	}

	if (length(a) > length(b)) return 1;
	if (length(a) < length(b)) return -1;

	return 0;
}

/**
 * RFC 6762 Section 8.1: track conflicts and back off after too many
 *
 * @param {string} name - Claimed name
 * @param {object} state - Entry state
 * @returns {boolean} True to act on this conflict, false if backing off
 */
function conflict_budget(name, state) {
	const now = utils.now_ms();
	const history = history_recent(conflict_history, name, c.CONFLICT_HISTORY_WINDOW_SEC * 1000, now);

	push(history, now);

	if (length(history) > c.CONFLICT_RATE_LIMIT)
		splice(history, 0, length(history) - c.CONFLICT_RATE_LIMIT);

	state.conflict_history = history;

	if (length(history) < c.CONFLICT_RATE_LIMIT)
		return true;

	log.WARN(`announce: Conflict rate limit hit for ${name}, waiting 5 seconds\n`);

	return false;
}

/**
 * Check whether a name finished probing on an interface
 *
 * @param {string} name - Name to check
 * @param {string} iface_name - Interface name
 * @returns {boolean} True if the name is announcing or announced on the interface
 */
export function is_announced(name, iface_name) {
	const link = announce_state[name]?.links?.[iface_name];

	return link != null && link.state !== 'probing';
};

function goodbye_send(name, iface_name, records) {
	const key = link_key(name, iface_name);
	const sent = send_records(name, iface_name, records, false);

	if (sent !== false)
		return sent;

	let timer;

	timer = uloop.timer(c.SEND_RETRY_MS, () => {
		goodbye_retries[key] = filter(goodbye_retries[key] ?? [], pending => pending !== timer);

		if (!length(goodbye_retries[key]))
			delete goodbye_retries[key];

		goodbye_send(name, iface_name, records);
	});

	goodbye_retries[key] ??= [];
	push(goodbye_retries[key], timer);

	return sent;
}

/**
 * Send goodbye announcement (TTL=0)
 *
 * RFC 6762 Section 10.1: Goodbye packets have TTL=0. A goodbye goes out
 * only on a link the name was published on. A goodbye the link cannot take
 * yet is sent again shortly, until the name is claimed on that link again.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 * @param {function} records_fn - Record source, defaults to the entry's own
 * @returns {boolean|null} True if sent, false if not sent yet or there was
 *   nothing to send, null if the send can never succeed
 */
export function goodbye(name, iface_name, records_fn) {
	if (!is_announced(name, iface_name))
		return false;

	const fn = records_fn || announce_state[name].ops.records;
	const records = fn(name, 0, iface_name);
	if (!length(records))
		return false;

	return goodbye_send(name, iface_name, records);
};

/**
 * Handle a conflicting response (someone else is answering for our name)
 *
 * RFC 6762 Section 8.1: while probing, a conflicting response means the name
 * belongs to the other host. We defer to it and claim a different name; the
 * lexicographic tiebreak is for simultaneous probes only, see handle_probe().
 * The links that already announced the name get a goodbye first.
 *
 * RFC 6762 Section 8.3, 9: a conflict seen once we assert the name resets
 * the link it was seen on to probing.
 *
 * An entry with a fail handler does not rename: a conflict while probing
 * removes only the link it was seen on and reports it to the handler.
 *
 * @param {string} name - Claimed name
 * @param {object} conflicting_record - Conflicting DNS record
 * @param {string} iface_name - Interface the record arrived on
 */
export function handle_conflict(name, conflicting_record, iface_name) {
	const state = announce_state[name];
	const link = state?.links[iface_name];

	if (!link)
		return;

	if (link.state !== 'probing') {
		log.NOTE(`announce: Conflict detected for ${name} on ${iface_name} while ${link.state}, reprobing...\n`);

		const backoff = conflict_budget(name, state) ? 0 : c.CONFLICT_BACKOFF_MS;

		link_probe(name, link, backoff + utils.probe_delay());
		return;
	}

	/* RFC 6762 Section 8.1: responses received before our first probe went
	 * out MUST be ignored */
	if (!link.probe_count)
		return;

	const within_budget = conflict_budget(name, state);

	if (link_fail(name, link, FAIL_CONFLICT))
		return;

	if (!within_budget) {
		link_probe(name, link, c.CONFLICT_BACKOFF_MS + utils.probe_delay());
		return;
	}

	log.NOTE(`announce: ${name} is already answered by another host, claiming a different name\n`);

	const ops = state.ops;
	const ifaces = keys(state.links);

	for (let claimed in ifaces)
		goodbye(name, claimed);

	cancel(name);

	const replacement = ops.conflict?.(name, ifaces);

	if (!replacement)
		return;

	conflict_history[replacement] = state.conflict_history;

	if (announce_state[replacement])
		announce_state[replacement].conflict_history = state.conflict_history;
};

/**
 * history_expire - drop update and conflict times past their window
 *
 * Return: number of names and links whose history was dropped
 */
export function history_expire() {
	const now = utils.now_ms();
	let removed = 0;

	for (let table in [ update_history, conflict_history ]) {
		const window_ms = table === update_history ? c.UPDATE_WINDOW_MS : c.CONFLICT_HISTORY_WINDOW_SEC * 1000;

		for (let key in keys(table)) {
			if (length(history_recent(table, key, window_ms, now)))
				continue;

			delete table[key];
			removed++;
		}
	}

	return removed;
};

/**
 * RFC 6762 Section 8.2: handle a simultaneous probe for a name we are claiming
 *
 * The loser of the lexicographic comparison waits one second and probes again
 * on that link; it does not rename.
 *
 * @param {string} name - Claimed name
 * @param {array} their_records - The peer's proposed records for that name
 * @param {string} iface_name - Interface the probe arrived on
 */
export function handle_probe(name, their_records, iface_name) {
	const state = announce_state[name];
	const link = state?.links[iface_name];

	if (!link || link.state !== 'probing')
		return;

	const ours = filter(state.ops.records(name, null, iface_name),
		record => utils.name_equal(record.name, name));

	if (compare_record_sets(ours, their_records) >= 0)
		return;

	const delay = conflict_budget(name, state) ? c.PROBE_DEFER_MS : c.CONFLICT_BACKOFF_MS;

	log.NOTE(`announce: Lost the probe tiebreak for ${name} on ${iface_name}, deferring\n`);

	link_probe(name, link, delay + utils.probe_delay());
};

/**
 * Get announcement state
 * @param {string} name - Claimed name
 * @returns {object|undefined} Announcement state or undefined
 */
export function get_state(name) {
	return announce_state[name];
};
