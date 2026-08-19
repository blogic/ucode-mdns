/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * tracker.uc - Active query tracking with exponential backoff
 *
 * Manages ongoing queries for continuous monitoring and cache refresh.
 * Implements RFC 6762 Section 5.2 exponential backoff algorithm.
 */

import * as cache from 'cache';
import * as nsec from 'nsec';
import * as packet from 'packet';
import * as utils from 'utils';
import * as uloop from 'uloop';
import * as log from 'log';
import * as mdns from 'mdns';
import * as c from 'const';

/* RFC 6762 Section 5.2: Active query tracking with exponential backoff
 * Tracks ongoing continuous queries */
const active_queries = {};

const interest = {};

const batches = {};


let batch_send;

function query_key(iface_name, question) {
	const canonical = utils.name_normalise(question.name);

	return canonical != null ? `${iface_name}\t${canonical}\t${question.type}` : null;
}

function known_answers(iface_name, question) {
	const records = question.type === 'ANY'
		? cache.lookup_name(question.name, question.class, iface_name)
		: cache.lookup(question.name, question.type, question.class, iface_name);

	return packet.known_answers_filter(filter(records, record => !record.doubted));
}

function type_denied(iface_name, question) {
	const denials = cache.lookup(question.name, 'NSEC', question.class ?? 'IN', iface_name);

	return length(filter(denials, record => nsec.denies(record, question.type))) > 0;
}

function interest_change(iface_name, question, delta) {
	const key = `${iface_name}\t${utils.name_normalise(question.name)}`;
	const types = interest[key] ??= {};

	types[question.type] = (types[question.type] ?? 0) + delta;

	if (types[question.type] <= 0)
		delete types[question.type];
	if (!length(types))
		delete interest[key];
}

function batch_find(iface_name, from_ms, to_ms) {
	for (let batch in batches[iface_name] ?? []) {
		if (batch.due_ms >= from_ms && batch.due_ms <= to_ms)
			return batch;
	}

	return null;
}

function batch_open(iface_name, due_ms, now) {
	const batch = { iface_name, due_ms, entries: {}, oneshots: {} };

	batch.timer = uloop.timer(max(0, int(due_ms - now)), () => batch_send(batch));
	push(batches[iface_name] ??= [], batch);

	return batch;
}

function batch_close(batch) {
	const list = batches[batch.iface_name] ?? [];
	const at = index(list, batch);

	if (at >= 0)
		splice(list, at, 1);
	if (!length(list))
		delete batches[batch.iface_name];
}

function batch_at(iface_name, due_ms, now) {
	return batch_find(iface_name, due_ms, due_ms) ?? batch_open(iface_name, due_ms, now);
}

function batch_initial(iface_name, now) {
	return batch_find(iface_name, now + c.RESPONSE_DELAY_MIN_MS, now + c.RESPONSE_DELAY_MAX_MS) ??
		batch_open(iface_name, now + utils.random_delay(), now);
}

function query_place(key, batch) {
	const q = active_queries[key];

	q.batch = batch;
	batch.entries[key] = q.question;
}

function query_unschedule(key) {
	const q = active_queries[key];
	const batch = q.batch;

	if (!batch)
		return;

	q.batch = null;

	if (!batch.oneshots[key])
		delete batch.entries[key];
	if (length(batch.entries))
		return;

	batch.timer.cancel();
	batch_close(batch);
}

function query_reschedule(key, now) {
	const q = active_queries[key];

	query_place(key, batch_at(q.iface_name, now + q.next_interval * 1000, now));
}

function query_advance(key, now) {
	const q = active_queries[key];

	q.attempt++;

	/* RFC 6762 Section 5.2: Exponential backoff with factor ≥ 2
	 * Cap at 3600 seconds (1 hour) */
	q.next_interval = min(q.next_interval * 2, c.QUERY_INTERVAL_MAX_SEC);
	query_reschedule(key, now);
}

function query_result(iface_name, item, result, now) {
	const question = item.question;
	const q = item.tracked ? active_queries[item.key] : null;

	if (result === null)
		log.ERR(`tracker: Query for ${question.type} ${question.name} on ${iface_name} cannot be sent\n`);
	else if (result === false)
		mdns.debug(`tracker: Query for ${question.type} ${question.name} on ${iface_name} not sent${q ? ', retrying' : ''}\n`);

	if (!q)
		return;

	if (result === false) {
		query_reschedule(item.key, now);
		return;
	}

	query_advance(item.key, now);

	if (result === true)
		mdns.debug(`tracker: Sent query attempt ${q.attempt} for ${question.type} ${question.name} (next in ${q.next_interval}s)\n`);
}

function answers_merge(list, answers) {
	for (let record in answers) {
		if (!length(filter(list, known => utils.records_equal(known, record))))
			push(list, record);
	}
}

function chunks_build(iface_name, items) {
	const header = packet.size_estimate([], []);
	const chunks = [];
	let chunk = null;

	for (let item in items) {
		const answers = known_answers(iface_name, item.question);
		const size = packet.size_estimate([ item.question ], answers) - header;

		if (!chunk || chunk.size + size > c.MAX_PACKET_SIZE) {
			chunk = { size: header, items: [], questions: [], answers: [] };
			push(chunks, chunk);
		}

		chunk.size += size;
		push(chunk.items, item);
		push(chunk.questions, item.question);
		answers_merge(chunk.answers, answers);
	}

	return chunks;
}

batch_send = function(batch) {
	const iface_name = batch.iface_name;
	const now = utils.now_ms();
	const items = [];

	batch_close(batch);

	for (let key, question in batch.entries) {
		const q = active_queries[key];
		const tracked = q != null && q.batch === batch;

		if (tracked)
			q.batch = null;

		if (!type_denied(iface_name, question)) {
			push(items, { key, question, tracked });
			continue;
		}

		mdns.debug(`tracker: ${question.name} has no ${question.type}, query skipped\n`);

		if (tracked)
			query_advance(key, now);
	}

	for (let chunk in chunks_build(iface_name, items)) {
		const result = packet.send_query(iface_name, chunk.questions, false, chunk.answers);

		for (let item in chunk.items)
			query_result(iface_name, item, result, now);
	}
};

/**
 * RFC 6762 Section 5.2: Start continuous query with exponential backoff
 *
 * Interval between first two queries ≥ 1 second.
 * Successive intervals increase by factor ≥ 2.
 * Maximum interval capped at 1 hour.
 * Includes cached records as known-answers (RFC 6762 Section 7.1).
 * Adds random delay 20-120ms before first query.
 *
 * Questions that come due on one interface together go out in one query
 * (Section 5.3). A transmission is skipped while a cached NSEC from that link
 * says the type does not exist (Section 6.1).
 *
 * One query runs per question and interface. Each scope that starts it
 * keeps it running until the same scope stops it.
 *
 * @param {string} iface_name - Interface name
 * @param {object} question - DNS question object
 * @param {string} scope - Name of the user of the query, null for the default
 * @returns {boolean|null} True if a new query started, false if the query
 *   was already running, null for an invalid name
 */
export function start_continuous(iface_name, question, scope) {
	const key = query_key(iface_name, question);
	const scope_name = scope ?? '';

	if (key == null)
		return null;

	if (active_queries[key]) {
		active_queries[key].scopes[scope_name] = true;
		return false;
	}

	interest_change(iface_name, question, 1);

	active_queries[key] = {
		iface_name: iface_name,
		question: question,
		attempt: 0,
		next_interval: 1,
		scopes: { [scope_name]: true }
	};

	/* RFC 6762 Section 5.2: SHOULD add random delay 20-120ms before first query */
	query_place(key, batch_initial(iface_name, utils.now_ms()));

	mdns.debug(`tracker: Started continuous query for ${question.type} ${question.name}\n`);

	return true;
};

/**
 * Check whether a continuous query runs for a question
 *
 * @param {string} iface_name - Interface name
 * @param {object} question - DNS question object
 * @returns {boolean} True if the question is queried on the interface
 */
export function query_active(iface_name, question) {
	const key = query_key(iface_name, question);

	return key != null && active_queries[key] != null;
};

/**
 * RFC 6762 Sections 5.2, 5.3 and 7.1: send one query with the current known answers
 *
 * Used for cache refresh points and for queries asked once. The question goes
 * out with the other questions that come due on the interface in the same
 * event loop iteration.
 *
 * @param {string} iface_name - Interface name
 * @param {object} question - DNS question object
 * @returns {boolean} True if the question is queued, false for an invalid name
 */
export function query_send(iface_name, question) {
	const key = query_key(iface_name, question);

	if (key == null)
		return false;

	const now = utils.now_ms();
	const batch = batch_find(iface_name, 0, now) ?? batch_open(iface_name, now, now);

	batch.entries[key] ??= question;
	batch.oneshots[key] = true;

	return true;
};

function known_answers_covered(ours, theirs, question) {
	for (let record in theirs) {
		if (!utils.name_equal(record.name, question.name))
			continue;
		if (question.type !== 'ANY' && record.type !== question.type)
			continue;
		if (!length(filter(ours, our => utils.records_equal(our, record))))
			return false;
	}

	return true;
}

/**
 * RFC 6762 Section 7.3: treat our query as sent when another host asks it
 *
 * A continuous query whose QM question another host just sent, with a
 * known-answer list that holds nothing ours would not, counts as sent: its
 * backoff advances and the next transmission moves out accordingly.
 *
 * @param {string} iface_name - Interface the query arrived on
 * @param {object} question - Received question
 * @param {array} their_answers - Known-answer list of the received query
 */
export function duplicate_observe(iface_name, question, their_answers) {
	if (question.unicast_response)
		return;

	const key = query_key(iface_name, question);
	const q = key != null ? active_queries[key] : null;

	if (!q || !known_answers_covered(known_answers(iface_name, q.question), their_answers, q.question))
		return;

	mdns.debug(`tracker: Duplicate question for ${question.type} ${question.name}, treated as sent\n`);

	query_unschedule(key);
	query_advance(key, utils.now_ms());
};

/**
 * Check whether a continuous query wants a record
 *
 * @param {string} iface_name - Interface name
 * @param {string} name - Record name, as returned by utils.name_normalise()
 * @param {string} type - Record type
 * @returns {boolean} True if a continuous query on the interface asks for it
 */
export function has_interest(iface_name, name, type) {
	const types = interest[`${iface_name}\t${name}`];

	return types != null && (types[type] > 0 || types.ANY > 0);
};

/**
 * RFC 6762 Section 5.2: Stop continuous query
 *
 * The query ends once the last scope that started it stops it.
 *
 * @param {string} iface_name - Interface name
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} scope - Scope passed to start_continuous()
 * @returns {boolean} True if stopped, false if not found
 */
export function stop_continuous(iface_name, name, type, scope) {
	const key = query_key(iface_name, { name: name, type: type });
	const q = key != null ? active_queries[key] : null;
	const scope_name = scope ?? '';

	if (!q || !(scope_name in q.scopes))
		return false;

	delete q.scopes[scope_name];

	if (length(q.scopes))
		return true;

	query_unschedule(key);
	delete active_queries[key];
	interest_change(iface_name, q.question, -1);

	mdns.debug(`tracker: Stopped continuous query for ${type} ${name}\n`);

	return true;
};

/**
 * RFC 6762 Sections 5.2 and 8: start the continuous queries of a link over
 *
 * After a link change the queries go out again from the first interval, so
 * the cache is refilled without waiting for a long backoff.
 *
 * @param {string} iface_name - Interface name
 */
export function restart(iface_name) {
	const now = utils.now_ms();

	for (let key, q in active_queries) {
		if (q.iface_name !== iface_name)
			continue;

		query_unschedule(key);
		q.attempt = 0;
		q.next_interval = 1;
		query_place(key, batch_initial(iface_name, now));
	}
};
