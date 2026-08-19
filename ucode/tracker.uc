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
import * as packet from 'packet';
import * as utils from 'utils';
import * as uloop from 'uloop';
import * as log from 'log';
import * as mdns from 'mdns';
import * as c from 'const';

/* RFC 6762 Section 5.2: Active query tracking with exponential backoff
 * Tracks ongoing queries for continuous monitoring or cache refresh */
const active_queries = {};

/* A continuous query and a cache refresh for the same question are different
 * things: without the purpose in the key, cache maintenance on a record we
 * also track continuously cancels the continuous query for good. */
function query_key(purpose, iface_name, question) {
	return `${purpose}\t${iface_name}\t${utils.name_normalise(question.name)}\t${question.type}`;
}

/**
 * RFC 6762 Section 5.2: Send query and schedule next retry with exponential backoff
 *
 * Exponential backoff with factor ≥ 2, capped at 3600 seconds (1 hour).
 * A cache refresh query stops after the four refresh attempts.
 *
 * @param {string} key - Query tracking key from query_key()
 */
function query_send_tracked(key) {
	const q = active_queries[key];
	if (!q)
		return;

	if (!packet.send_query(q.iface_name, [q.question], false, q.known_answers)) {
		log.ERR(`tracker: Failed to send tracked query for ${q.question.name}\n`);
	}

	mdns.debug(`tracker: Sent query attempt ${q.attempt + 1} for ${q.question.type} ${q.question.name} (next in ${q.next_interval}s)\n`);

	q.attempt++;

	/* RFC 6762 Section 5.2: the record is deleted at 100 percent of its TTL,
	 * not once four refresh attempts have been made. The four attempts are
	 * spread across the last fifth of the lifetime; expiry does the removal. */
	if (q.purpose === 'cache_refresh' && q.attempt >= length(c.CACHE_REFRESH_PERCENTAGES)) {
		delete active_queries[key];
		return;
	}

	/* RFC 6762 Section 5.2: Exponential backoff with factor ≥ 2
	 * Cap at 3600 seconds (1 hour) */
	const next_interval = min(q.next_interval * 2, 3600);
	q.next_interval = next_interval;

	q.timer = uloop.timer(next_interval * 1000, function() {
		query_send_tracked(key);
		return false;
	});
}

/**
 * RFC 6762 Section 5.2: Start continuous query with exponential backoff
 *
 * Interval between first two queries ≥ 1 second.
 * Successive intervals increase by factor ≥ 2.
 * Maximum interval capped at 1 hour.
 * Includes cached records as known-answers (RFC 6762 Section 7.1).
 * Adds random delay 20-120ms before first query.
 *
 * @param {string} iface_name - Interface name
 * @param {object} question - DNS question object
 * @returns {boolean} True if started successfully
 */
export function start_continuous(iface_name, question) {
	const key = query_key('continuous', iface_name, question);

	if (active_queries[key]) {
		active_queries[key].timer.cancel();
	}

	/* RFC 6762 Section 7.1: Include cached records as known-answers */
	const known_answers = cache.lookup(question.name, question.type);

	/* RFC 6762 Section 5.2: SHOULD add random delay 20-120ms before first query */
	const initial_delay_ms = utils.random_delay();

	active_queries[key] = {
		iface_name: iface_name,
		question: question,
		attempt: 0,
		next_interval: 1,
		purpose: 'continuous',
		known_answers: known_answers,
		timer: uloop.timer(initial_delay_ms, function() {
			query_send_tracked(key);
			return false;
		})
	};

	mdns.debug(`tracker: Started continuous query for ${question.type} ${question.name}\n`);

	return true;
};

/**
 * RFC 6762 Section 5.2: Start cache refresh query with exponential backoff
 *
 * Same as continuous but stops after the four refresh attempts. Expiry at
 * 100 percent of the TTL removes the record, not this function.
 * Adds random delay 20-120ms before first query.
 *
 * @param {string} iface_name - Interface name
 * @param {object} question - DNS question object
 * @param {string} cache_key - Cache key for tracking
 * @param {array} known_answers - Array of cached records for known-answer suppression
 * @returns {boolean} True if started successfully
 */
export function start_cache_refresh(iface_name, question, cache_key, known_answers) {
	const key = query_key('cache_refresh', iface_name, question);

	if (active_queries[key]) {
		active_queries[key].timer.cancel();
	}

	/* RFC 6762 Section 5.2: SHOULD add random delay 20-120ms before first query */
	const initial_delay_ms = utils.random_delay();

	active_queries[key] = {
		iface_name: iface_name,
		question: question,
		attempt: 0,
		next_interval: 1,
		purpose: 'cache_refresh',
		cache_key: cache_key,
		known_answers: known_answers || [],
		timer: uloop.timer(initial_delay_ms, function() {
			query_send_tracked(key);
			return false;
		})
	};

	mdns.debug(`tracker: Started cache refresh query for ${question.type} ${question.name}\n`);

	return true;
};

/**
 * RFC 6762 Section 5.2: Stop continuous query
 * @param {string} iface_name - Interface name
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @returns {boolean} True if stopped, false if not found
 */
export function stop_continuous(iface_name, name, type) {
	const key = query_key('continuous', iface_name, { name: name, type: type });
	const q = active_queries[key];

	if (!q)
		return false;

	q.timer.cancel();
	delete active_queries[key];

	mdns.debug(`tracker: Stopped continuous query for ${type} ${name}\n`);

	return true;
};

/**
 * RFC 6762 Section 5.2: Handle answer for an active query
 *
 * Called when we receive an answer matching an active query.
 * For cache refresh queries: stops querying.
 * For continuous queries: no schedule change; the intervals between
 * successive queries MUST keep increasing by at least a factor of two,
 * and cache maintenance takes over as records approach expiry.
 *
 * @param {string} iface_name - Interface name
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 */
export function answer_received(iface_name, name, type) {
	const key = query_key('cache_refresh', iface_name, { name: name, type: type });
	const q = active_queries[key];

	if (!q)
		return;

	q.timer.cancel();
	delete active_queries[key];

	mdns.debug(`tracker: Cache refresh succeeded for ${type} ${name}\n`);
};
