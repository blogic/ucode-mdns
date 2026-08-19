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
 * to start_probe(), so service instances and the host name share one
 * implementation.
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
 *     state: "probing|announcing|announced",
 *     probe_count: 0,
 *     announce_count: 0,
 *     ifaces: [ "br-lan" ],
 *     timer: uloop_timer,
 *     ops: { records, conflict, state },
 *     conflict_history: [timestamp1, timestamp2, ...]  (RFC 6762 Section 8.1)
 *   }
 * }
 */
const announce_state = {};

/**
 * Cancel probing/announcing for an entry
 * @param {string} name - Claimed name
 */
export function cancel(name) {
	const state = announce_state[name];
	if (!state)
		return;

	if (state.timer)
		state.timer.cancel();

	delete announce_state[name];
};

/**
 * RFC 6762 Section 8.2: Lexicographic comparison for simultaneous probe tiebreaking
 *
 * Compare records byte-by-byte as unsigned 8-bit values in order: class, type, rdata.
 *
 * @param {object} r1 - First DNS record
 * @param {object} r2 - Second DNS record
 * @returns {number} -1 if r1 < r2, 0 if equal, 1 if r1 > r2
 */
function compare_records_lexicographic(r1, r2) {
	/* Compare class (as 16-bit big-endian) */
	const class1 = c.CLASS_NUMBERS[r1.class] ?? 255;
	const class2 = c.CLASS_NUMBERS[r2.class] ?? 255;
	if (class1 < class2) return -1;
	if (class1 > class2) return 1;

	/* Compare type (as 16-bit big-endian) */
	const type1 = c.TYPE_NUMBERS[r1.type] ?? 255;
	const type2 = c.TYPE_NUMBERS[r2.type] ?? 255;
	if (type1 < type2) return -1;
	if (type1 > type2) return 1;

	/* RFC 6762 Section 8.2: the raw binary rdata, names uncompressed */
	const rdata1 = mdns.rdata_encode(r1) ?? '';
	const rdata2 = mdns.rdata_encode(r2) ?? '';

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
 * @returns {boolean} True if sent successfully
 */
function send_records(name, iface_name, records) {
	const pkt = {
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
		answers: records,
		authority: [],
		additional: []
	};

	if (!mdns.packet_send(iface_name, pkt, null)) {
		log.ERR(`announce: Failed to send announcement for ${name} on ${iface_name}: ${mdns.error()}\n`);
		return false;
	}

	response.multicast_record(iface_name, records);

	return true;
}

/**
 * Send an announcement
 *
 * RFC 6762 Section 8.3: Sends announcements with exponential backoff
 * (1 second, 2 seconds, 4 seconds, ...). Limited to 8 announcements.
 *
 * @param {string} name - Claimed name
 */
function send_announcement(name) {
	const state = announce_state[name];

	if (!state)
		return;

	state.announce_count++;

	let sent = false;
	for (let iface_name in state.ifaces) {
		const records = state.ops.records(name, null, iface_name);

		if (!length(records))
			continue;

		if (send_records(name, iface_name, records))
			sent = true;
	}

	/* A send that failed is retried on the next tick. Giving the name up
	 * would be permanent, and the usual cause is an interface that has no
	 * address yet, which resolves itself. */
	if (!sent)
		state.announce_count--;

	/* RFC 6762 Section 8.3: Send announcements with exponential backoff */
	/* 1 second, 2 seconds, 4 seconds, ... */
	if (!sent || state.announce_count < c.ANNOUNCEMENT_COUNT_MAX) {
		const delay = sent ? utils.announcement_delay(state.announce_count)
		                   : c.ANNOUNCE_RETRY_MS;

		state.timer = uloop.timer(delay, function() {
			send_announcement(name);
		});
	} else {
		/* Announcing complete */
		state.state = 'announced';
		if (state.ops.state)
			state.ops.state(name, 'announced');
		state.timer = null;
	}
}

/**
 * Start announcing (after successful probing)
 * @param {string} name - Claimed name
 */
function start_announcing(name) {
	const state = announce_state[name];

	if (!state)
		return;

	state.state = 'announcing';
	state.announce_count = 0;
	if (state.ops.state)
		state.ops.state(name, 'announcing');

	send_announcement(name);
}

/**
 * Send a probe query
 *
 * RFC 6762 Section 8.2: Populates Authority Section with ALL proposed records
 * for simultaneous probe tiebreaking via lexicographic comparison.
 *
 * @param {string} name - Claimed name
 */
function send_probe(name) {
	const state = announce_state[name];

	if (!state)
		return;

	state.probe_count++;

	/* Build probe query (question for our name, with our records as authority) */
	const questions = [
		{
			name: name,
			type: 'ANY',
			class: 'IN',
			unicast_response: true  /* RFC 6762 Section 8.1: SHOULD set QU bit */
		}
	];

	let sent = false;
	for (let iface_name in state.ifaces) {
		/* RFC 6762 Section 8.2: MUST populate Authority Section with ALL proposed
		 * records. This allows simultaneous probe tiebreaking via lexicographic
		 * comparison.
		 *
		 * Section 10.2 puts the cache-flush bit in the Resource Record Sections
		 * of responses only, and a probe is a query. Section 8.1 probes for the
		 * records we want to be unique, which excludes the shared DNS-SD PTR
		 * whose owner name is the service type rather than the name we claim. */
		const authority_records = [];

		for (let record in state.ops.records(name, null, iface_name)) {
			if (!utils.name_equal(record.name, name))
				continue;

			push(authority_records, { ...record, flush_cache: false });
		}

		if (!length(authority_records))
			continue;

		if (packet.send_query(iface_name, questions, false, null, authority_records))
			sent = true;
	}

	/* A probe that could not go out is retried, not abandoned: the usual
	 * cause is an interface without an address yet, and giving up would
	 * leave the name unclaimed until the next reload */
	if (!sent) {
		state.probe_count--;

		state.timer = uloop.timer(c.ANNOUNCE_RETRY_MS, function() {
			send_probe(name);
		});

		return;
	}

	/* RFC 6762 Section 8.1: Send 3 probes, 250ms apart */
	if (state.probe_count < c.PROBE_COUNT) {
		state.timer = uloop.timer(c.PROBE_INTERVAL_MS, function() {
			send_probe(name);
		});
	} else {
		/* Probing complete, start announcing */
		state.timer = uloop.timer(c.PROBE_INTERVAL_MS, function() {
			start_announcing(name);
		});
	}
}

/**
 * Start probing for an entry (RFC 6762 Section 8.1)
 *
 * Sends first probe after random delay [0-250ms].
 * Probes are queries with QU bit and authority section containing our records.
 *
 * A name already being claimed gains the interface instead of restarting the
 * state machine. An entry that finished announcing sends one announcement on
 * the new interface straight away, so a link that appears late is not left
 * without our records until the next query.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 * @param {object} ops - Entry operations { records, conflict, state }
 * @returns {boolean} True if the interface is now claimed
 */
export function start_probe(name, iface_name, ops) {
	const state = announce_state[name];

	if (state) {
		if (index(state.ifaces, iface_name) >= 0)
			return false;

		push(state.ifaces, iface_name);

		if (state.state === 'announced')
			send_records(name, iface_name, state.ops.records(name, null, iface_name));

		return true;
	}

	if (!ops?.records)
		return false;

	announce_state[name] = {
		state: 'probing',
		probe_count: 0,
		announce_count: 0,
		ifaces: [ iface_name ],
		timer: null,
		ops: ops
	};

	if (ops.state)
		ops.state(name, 'probing');

	/* Send first probe after random delay [0-250ms] */
	const delay = utils.probe_delay();

	announce_state[name].timer = uloop.timer(delay, function() {
		send_probe(name);
	});

	return true;
};

/**
 * Re-announce a claimed name after its addresses changed
 *
 * RFC 6762 Section 8: an address change makes the records we published stale.
 * The name itself is not in question, so this announces rather than re-probes.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface whose addresses changed
 * @returns {boolean} True if an announcement went out
 */
export function refresh(name, iface_name) {
	const state = announce_state[name];

	if (!state || index(state.ifaces, iface_name) < 0)
		return false;

	if (state.state !== 'announced' && state.state !== 'announcing')
		return false;

	return send_records(name, iface_name, state.ops.records(name, null, iface_name));
};

/**
 * Stop claiming a name on one interface
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 */
export function iface_remove(name, iface_name) {
	const state = announce_state[name];
	if (!state)
		return;

	const idx = index(state.ifaces, iface_name);
	if (idx >= 0)
		splice(state.ifaces, idx, 1);

	if (length(state.ifaces) === 0)
		cancel(name);
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
	const a = sort([ ...ours ], compare_records_lexicographic);
	const b = sort([ ...theirs ], compare_records_lexicographic);
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
 * @returns {boolean} True to act on this conflict, false if backing off
 */
function conflict_budget(name) {
	const state = announce_state[name];
	const now = time();
	const ops = state.ops;
	const ifaces = state.ifaces;

	if (!state.conflict_history)
		state.conflict_history = [];

	push(state.conflict_history, now);

	const window_start = now - c.CONFLICT_HISTORY_WINDOW_SEC;
	const recent = [];
	for (let timestamp in state.conflict_history) {
		if (timestamp >= window_start)
			push(recent, timestamp);
	}
	state.conflict_history = recent;

	if (length(recent) < c.CONFLICT_RATE_LIMIT)
		return true;

	log.WARN(`announce: Conflict rate limit hit for ${name}, waiting 5 seconds\n`);

	cancel(name);

	uloop.timer(c.CONFLICT_BACKOFF_MS, function() {
		for (let iface_name in ifaces) {
			if (start_probe(name, iface_name, ops))
				announce_state[name].conflict_history = recent;
		}
	});

	return false;
}

/**
 * Handle a conflicting response (someone else is answering for our name)
 *
 * RFC 6762 Section 8.1: while probing, a conflicting response means the name
 * belongs to the other host. We defer to it and claim a different name; the
 * lexicographic tiebreak is for simultaneous probes only, see handle_probe().
 *
 * RFC 6762 Section 8.3, 9: a conflict seen once we assert the name resets us
 * to probing.
 *
 * @param {string} name - Claimed name
 * @param {object} conflicting_record - Conflicting DNS record
 */
export function handle_conflict(name, conflicting_record) {
	const state = announce_state[name];

	if (!state)
		return;

	const ops = state.ops;
	const ifaces = state.ifaces;

	if (state.state === 'announced' || state.state === 'announcing') {
		log.NOTE(`announce: Conflict detected for ${name} while ${state.state}, reprobing...\n`);

		cancel(name);

		for (let iface_name in ifaces)
			start_probe(name, iface_name, ops);

		return;
	}

	if (state.state !== 'probing')
		return;

	/* RFC 6762 Section 8.1: responses received before our first probe went
	 * out MUST be ignored */
	if (!state.probe_count)
		return;

	if (!conflict_budget(name))
		return;

	log.NOTE(`announce: ${name} is already answered by another host, claiming a different name\n`);

	cancel(name);

	if (ops.conflict)
		ops.conflict(name, ifaces);
};

/**
 * RFC 6762 Section 8.2: handle a simultaneous probe for a name we are claiming
 *
 * The loser of the lexicographic comparison waits one second and probes again;
 * it does not rename.
 *
 * @param {string} name - Claimed name
 * @param {array} their_records - The peer's proposed records for that name
 */
export function handle_probe(name, their_records) {
	const state = announce_state[name];

	if (!state || state.state !== 'probing')
		return;

	const ops = state.ops;
	const ifaces = state.ifaces;
	const cmp = compare_record_sets(ops.records(name, null, ifaces[0]), their_records);

	if (cmp >= 0)
		return;

	if (!conflict_budget(name))
		return;

	log.NOTE(`announce: Lost the probe tiebreak for ${name}, deferring one second\n`);

	cancel(name);

	uloop.timer(c.PROBE_DEFER_MS, function() {
		for (let iface_name in ifaces)
			start_probe(name, iface_name, ops);
	});
};

/**
 * Send goodbye announcement (TTL=0)
 *
 * RFC 6762 Section 10.1: Goodbye packets have TTL=0.
 *
 * @param {string} name - Claimed name
 * @param {string} iface_name - Interface name
 * @param {function} records_fn - Record source, defaults to the entry's own
 * @returns {boolean} True if sent successfully
 */
export function goodbye(name, iface_name, records_fn) {
	const fn = records_fn || announce_state[name]?.ops?.records;
	if (!fn)
		return false;

	const records = fn(name, 0, iface_name);
	if (!length(records))
		return false;

	return send_records(name, iface_name, records);
};

/**
 * Get announcement state
 * @param {string} name - Claimed name
 * @returns {object|undefined} Announcement state or undefined
 */
export function get_state(name) {
	return announce_state[name];
};
