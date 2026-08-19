/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * cache.uc - DNS record cache with TTL tracking
 *
 * Manages cached DNS records with automatic expiry.
 * Provides lookup, insertion, and conflict detection.
 * Implements RFC 6762 Section 5.2 cache maintenance queries.
 */

import * as math from 'math';
import * as utils from 'utils';
import * as log from 'log';
import * as mdns from 'mdns';
import * as c from 'const';

/* Cache entry structure
 * {
 *   name: "service._http._tcp.local",
 *   canonical: "service._http._tcp.local",  (utils.name_normalise() of name)
 *   type: "PTR",
 *   class: "IN",
 *   records: [ {
 *     rdata: { ... },
 *     iface: "lan",
 *     ttl: 120,
 *     flush_cache: false,
 *     inserted_at: 12345678,  (seconds since the epoch, for display)
 *     received_ms: 98645432,  (utils.now_ms() at reception)
 *     expires_at: 98765432    (received_ms + ttl in ms)
 *   } ]
 * }
 */

const cache = {};  /* Keyed by "name:type:class" */


let cache_full_logged;
let observer;

/**
 * observer_set - install the function told about changed cache records
 * @fn: function taking (name, type, iface) of a changed set of records, the
 *      name as utils.name_normalise() returns it, or null
 *
 * Return: nothing
 */
export function observer_set(fn) {
	observer = fn;
};

function entry_changed(entry, iface) {
	observer?.(entry.canonical, entry.type, iface);
}

function records_changed(entry, records) {
	for (let iface in uniq(map(records, rec => rec.iface)))
		entry_changed(entry, iface);
}

function flush_expired(record, now) {
	return record.marked_for_deletion && now >= record.deletion_deadline;
}

function ttl_expired(record, now) {
	return record.expires_at && now >= record.expires_at;
}

function key_build(canonical, type, rclass) {
	return `${canonical}:${type}:${rclass || 'IN'}`;
}

/**
 * Generate cache key from record components
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @returns {string|null} Cache key in format "name:type:class", null for an
 *   invalid name
 */
function cache_key(name, type, rclass) {
	const canonical = utils.name_normalise(name);

	return canonical != null ? key_build(canonical, type, rclass) : null;
}

function refresh_deadlines(ttl) {
	return map(c.CACHE_REFRESH_PERCENTAGES, pct =>
		ttl * 10 * (pct + (math.rand() % (c.CACHE_REFRESH_VARIATION_PCT * 100 + 1)) / 100.0));
}

/**
 * RFC 6762 Section 5.2: find the records due for a refresh query
 *
 * A record with local interest is queried for at 80-82, 85-87, 90-92 and
 * 95-97 percent of its TTL on the interface it was learned on. The points
 * are drawn once when the record is cached.
 *
 * @param {function} interested - Called with (iface, name, type) of a record,
 *   name in the form of utils.name_normalise(); true if a query wants it
 * @param {number} timestamp - Current monotonic time in ms, defaults to now
 * @returns {object} { due: [ { cache_key, record } ], next: ms until the
 *   next scan is needed }
 */
export function maintenance(interested, timestamp) {
	const now = timestamp ?? utils.now_ms();
	const due = [];
	const emitted = {};
	let next = c.CACHE_MAINTENANCE_INTERVAL_MS;

	for (let key, entry in cache) {
		for (let record in entry.records) {
			if (record.is_goodbye || record.marked_for_deletion || !record.refresh_deadlines)
				continue;

			const elapsed = now - record.received_ms;
			const deadlines = record.refresh_deadlines;

			if (elapsed >= record.ttl * 1000 || record.refresh_index >= length(deadlines))
				continue;
			if (!interested(record.iface, entry.canonical, entry.type))
				continue;

			const index = record.refresh_index;

			while (record.refresh_index < length(deadlines) &&
			       elapsed >= deadlines[record.refresh_index])
				record.refresh_index++;

			if (record.refresh_index < length(deadlines))
				next = min(next, deadlines[record.refresh_index] - elapsed);

			const scoped = `${record.iface}:${key}`;

			if (record.refresh_index == index || emitted[scoped])
				continue;

			emitted[scoped] = true;
			push(due, { cache_key: scoped, record: { name: entry.name, type: entry.type,
				class: entry.class, iface: record.iface } });
		}
	}

	return { due, next: int(max(next, c.CACHE_MAINTENANCE_MIN_MS)) };
};

/**
 * Clean up empty cache entry
 * @param {string} key - Cache key
 * @param {object} entry - Cache entry
 */
function cleanup_empty_entry(key, entry) {
	if (length(entry.records) === 0)
		delete cache[key];
}

function entry_iface_drop(key, entry, iface) {
	const before = length(entry.records);

	entry.records = filter(entry.records, (record) => record.iface !== iface);
	cleanup_empty_entry(key, entry);

	if (length(entry.records) < before)
		entry_changed(entry, iface);

	return before - length(entry.records);
}

/**
 * Expand internal record structure to full record format
 * @param {object} entry - Cache entry with name, type, class
 * @param {object} rec - Individual record with ttl, rdata, timestamps
 * @returns {object} Full record format for backward compatibility
 */
function expand_record(entry, rec) {
	return {
		name: entry.name,
		type: entry.type,
		class: entry.class,
		ttl: rec.ttl,
		rdata: rec.rdata,
		flush_cache: rec.flush_cache,
		inserted_at: rec.inserted_at,
		expires_at: rec.expires_at,
		valid_until: rec.marked_for_deletion ? min(rec.expires_at, rec.deletion_deadline) : rec.expires_at,
		is_goodbye: rec.is_goodbye || false,
		doubted: rec.doubt_deadline != null,
		iface: rec.iface
	};
}

/**
 * Expire old records (call periodically)
 *
 * RFC 6762 Section 10.2: Deletes records marked for deletion after grace period.
 *
 * Handles per-record TTL expiry in the new array-based structure.
 *
 * @returns {number} Number of individual records expired
 */
export function expire() {
	const now = utils.now_ms();
	let expired = 0;

	for (let key, entry in cache) {
		const removed = [];

		for (let i = length(entry.records) - 1; i >= 0; i--) {
			const rec = entry.records[i];

			/* RFC 6762 Section 10.2: Delete records marked for deletion after
			 * grace period, and records past their TTL */
			if (!flush_expired(rec, now) && !ttl_expired(rec, now))
				continue;

			push(removed, rec);
			splice(entry.records, i, 1);
		}

		expired += length(removed);
		cleanup_empty_entry(key, entry);
		records_changed(entry, removed);
	}

	return expired;
};

/**
 * Evict the least recently used cache entries
 *
 * Evicts a batch, so the scan of the whole cache is amortised over the
 * inserts that follow.
 *
 * @param {number} count - Number of entries to evict
 * @returns {number} Number of entries evicted
 */
function evict_lru(count) {
	const candidates = [];

	for (let key, entry in cache) {
		let oldest = null;

		for (let rec in entry.records) {
			if (oldest === null || rec.received_ms < oldest)
				oldest = rec.received_ms;
		}

		push(candidates, { key: key, age: oldest ?? 0 });
	}

	sort(candidates, (a, b) => a.age - b.age);

	let evicted = 0;

	for (let candidate in candidates) {
		if (evicted >= count)
			break;

		const entry = cache[candidate.key];

		delete cache[candidate.key];
		records_changed(entry, entry.records);
		evicted++;
	}

	return evicted;
}

function capacity_ensure(now) {
	if (length(cache) < c.MAX_CACHE_ENTRIES)
		return;

	/* Check cache size limit for new entries. A full cache is remotely
	 * triggerable, so it is reported once per interval. */
	if (cache_full_logged == null || now - cache_full_logged >= c.CACHE_FULL_LOG_INTERVAL_SEC * 1000) {
		log.WARN(`cache: At the limit of ${c.MAX_CACHE_ENTRIES} entries, evicting to make room\n`);
		cache_full_logged = now;
	}

	expire();

	if (length(cache) >= c.MAX_CACHE_ENTRIES)
		evict_lru(c.CACHE_EVICT_BATCH);
}

/* RFC 6762 Section 10.2: Cache-flush with 1-second grace period
 * Mark records for deletion but keep them for 1 second to allow
 * packets already in flight to be processed */
function flush_mark(entry, record, iface, received_ms) {
	for (let rec in entry.records) {
		if (rec.iface !== iface || rec.marked_for_deletion)
			continue;
		if (utils.rdata_equal(entry.type, rec.rdata, record.rdata))
			continue;

		/* RFC 6762 Section 10.2: only records received more than a
		 * second ago are invalidated, so a large unique RRSet split
		 * across a burst of packets does not evict itself */
		if (received_ms - rec.received_ms < c.CACHE_FLUSH_GRACE_MS)
			continue;

		rec.marked_for_deletion = true;
		rec.deletion_deadline = received_ms + c.CACHE_FLUSH_GRACE_MS;
	}
}

function record_find(entry, record, iface) {
	for (let rec in entry.records) {
		if (rec.iface === iface && utils.rdata_equal(entry.type, rec.rdata, record.rdata))
			return rec;
	}

	return null;
}

function record_set(rec, record, ttl, received_ms) {
	rec.rdata = record.rdata;
	rec.ttl = ttl;
	rec.inserted_at = time();
	rec.received_ms = received_ms;
	rec.refresh_deadlines = ttl >= c.CACHE_REFRESH_MIN_TTL_SEC ? refresh_deadlines(ttl) : null;
	rec.refresh_index = 0;
	rec.expires_at = received_ms + ttl * 1000;
	rec.flush_cache = record.flush_cache || false;

	/* Clear any goodbye/deletion flags */
	delete rec.is_goodbye;
	delete rec.marked_for_deletion;
	delete rec.deletion_deadline;
	delete rec.doubt_since;
	delete rec.doubt_queries;
	delete rec.doubt_deadline;
}

function record_valid(record) {
	if (!record?.name || !record?.type) {
		log.ERR(`cache: Cannot insert record: name=${record?.name || "MISSING"}, type=${record?.type || "MISSING"}\n`);
		return false;
	}

	/* RFC 6763 Section 6.1: Validate TXT record size */
	if (record.type === 'TXT' && record.rdata?.strings) {
		const total_size = utils.txt_size(record.rdata.strings);
		if (total_size > c.MAX_TXT_SIZE) {
			log.WARN(`cache: Dropping TXT record with excessive size: ${total_size} bytes (limit ${c.MAX_TXT_SIZE}) for ${record.name}\n`);
			return false;
		}
	}

	return true;
}

/**
 * Insert or update record in cache
 *
 * RFC 6762 Section 10.1: Handles goodbye packets (TTL=0) by setting TTL to 1.
 * RFC 6762 Section 10.2: Cache flush bit handling for unique records.
 *
 * Support for multiple A/AAAA records per hostname: Records with same name+type+class
 * are stored as an array, allowing hosts to have multiple IP addresses.
 *
 * @param {object} record - DNS record with name, type, class, ttl, rdata, flush_cache
 * @param {string} iface - Interface name where record was received (optional)
 * @returns {boolean} True if inserted successfully, false otherwise
 */
export function insert(record, iface) {
	if (!record_valid(record))
		return false;

	const canonical = utils.name_normalise(record.name);

	if (canonical == null) {
		mdns.debug(`cache: Dropping ${record.type} with invalid name ${record.name}\n`);
		return false;
	}

	const key = key_build(canonical, record.type, record.class);
	const received_ms = utils.now_ms();

	/* RFC 6762 Section 10.1: Goodbye packet handling
	 * When TTL=0 received, set TTL to 1 and delete after 1 second */
	const goodbye = record.ttl === c.GOODBYE_TTL_SEC;
	const ttl = goodbye ? 1 : min(record.ttl ?? 0, c.MAX_RECEIVED_TTL_SEC);
	let entry = cache[key];
	let rec = null;

	if (!entry) {
		capacity_ensure(received_ms);
		entry = cache[key] = { name: record.name, canonical, type: record.type,
			class: record.class || 'IN', records: [] };
	}
	else {
		if (record.flush_cache && !goodbye)
			flush_mark(entry, record, iface, received_ms);

		rec = record_find(entry, record, iface);
	}

	if (rec && !goodbye)
		mdns.info(`cache: Updated ${record.type} ${record.name} (TTL ${ttl})\n`);
	else if (!rec && length(entry.records) >= c.MAX_RECORDS_PER_ENTRY) {
		mdns.debug(`cache: Dropping ${record.type} for ${record.name}, entry holds ${c.MAX_RECORDS_PER_ENTRY} records\n`);
		return false;
	}
	else if (!rec && !goodbye)
		mdns.info(`cache: ${length(entry.records) ? 'Added additional' : 'Discovered'} ${record.type} ${record.name} (TTL ${ttl})\n`);

	if (!rec) {
		rec = { iface };
		push(entry.records, rec);
	}

	record_set(rec, record, ttl, received_ms);

	if (goodbye)
		rec.is_goodbye = true;

	entry_changed(entry, iface);

	return true;
};

/**
 * Lookup records in cache
 *
 * RFC 6762 Section 10.2: Keeps cache-flushed records usable until their grace deadline.
 *
 * Returns array of all matching records (expanded from internal array structure).
 *
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @param {string} iface - Interface the records were learned on, null for all
 * @returns {array} Array of cached records (empty if not found/expired)
 */
export function lookup(name, type, rclass, iface) {
	const key = cache_key(name, type, rclass);
	const entry = key != null ? cache[key] : null;

	if (!entry)
		return [];

	const now = utils.now_ms();
	const results = [];

	/* Skip records of other interfaces, past their grace period or expired,
	 * without modifying cache */
	for (let rec in entry.records) {
		if (iface != null && rec.iface !== iface)
			continue;
		/* RFC 6762 Section 10.2: skip records after their grace period */
		if (flush_expired(rec, now))
			continue;

		/* Check expiry - skip but don't remove (expire() will handle cleanup) */
		if (ttl_expired(rec, now))
			continue;

		push(results, expand_record(entry, rec));
	}

	return results;
};

function entry_collect(key, entry, iface, now, results) {
	for (let i = length(entry.records) - 1; i >= 0; i--) {
		const rec = entry.records[i];
		if (iface != null && rec.iface !== iface)
			continue;

		/* RFC 6762 Section 10.2: skip records after their grace period */
		if (flush_expired(rec, now))
			continue;

		/* Check expiry */
		if (ttl_expired(rec, now)) {
			splice(entry.records, i, 1);
			continue;
		}

		push(results, expand_record(entry, rec));
	}

	cleanup_empty_entry(key, entry);
}

/**
 * Lookup all records for a name (any type)
 *
 * RFC 6762 Section 10.2: Skips records whose cache-flush grace deadline has elapsed.
 *
 * @param {string} name - DNS name
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @param {string} iface - Interface the records were learned on, null for all
 * @returns {array} Array of cached records for this name
 */
export function lookup_name(name, rclass, iface) {
	const canonical = utils.name_normalise(name);
	const results = [];

	if (canonical == null)
		return results;

	const now = utils.now_ms();
	const cls = rclass || 'IN';

	for (let key, entry in cache) {
		if (entry.canonical !== canonical || entry.class !== cls)
			continue;

		entry_collect(key, entry, iface, now, results);
	}

	return results;
};

/**
 * Remove all records for a specific name+type+class from cache
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @param {string} iface - Interface whose records go, null for all
 */
export function remove(name, type, rclass, iface) {
	const key = cache_key(name, type, rclass);

	if (key == null || !cache[key])
		return;

	const entry = cache[key];

	if (iface != null) {
		entry_iface_drop(key, entry, iface);
		return;
	}

	delete cache[key];
	records_changed(entry, entry.records);
};

/**
 * RFC 6762 Section 10.3: drop every record learned on one interface
 *
 * Used when the link goes away, so stale records do not come back as known
 * answers once it returns.
 *
 * @param {string} iface_name - Interface name
 * @returns {number} Number of records removed
 */
export function interface_flush(iface_name) {
	let removed = 0;

	for (let key, entry in cache)
		removed += entry_iface_drop(key, entry, iface_name);

	return removed;
};

/**
 * Get cache statistics
 * @returns {object} Object with entries, total records, expired, and active counts
 */
export function stats() {
	let entries = 0;
	let total_records = 0;
	let expired = 0;
	const now = utils.now_ms();

	for (let key in cache) {
		const entry = cache[key];
		entries++;

		for (let rec in entry.records) {
			total_records++;
			if (ttl_expired(rec, now))
				expired++;
		}
	}

	return {
		entries: entries,
		total: total_records,
		expired: expired,
		active: total_records - expired
	};
};

/**
 * Get all cache entries (optionally filtered by type)
 *
 * RFC 6762 Section 10.2: Skips records whose cache-flush grace deadline has elapsed.
 *
 * Expands internal record arrays to individual records for backward compatibility.
 *
 * @param {string} type_filter - Optional DNS record type to filter by
 * @returns {array} Array of cached records
 */
export function get_all(type_filter) {
	const results = [];
	const now = utils.now_ms();

	for (let key, entry in cache) {
		/* Apply type filter if specified */
		if (type_filter && entry.type !== type_filter)
			continue;

		entry_collect(key, entry, null, now, results);
	}

	return results;
};

function entry_matching(entry, iface_name, callback) {
	for (let rec in entry.records) {
		if (rec.iface === iface_name && !rec.is_goodbye && !rec.marked_for_deletion)
			callback(entry, rec);
	}
}

function records_matching(name, type, rclass, iface_name, callback) {
	const canonical = utils.name_normalise(name);

	if (canonical == null)
		return;

	if (type !== 'ANY' && rclass !== 'ANY') {
		const entry = cache[key_build(canonical, type, rclass)];

		if (entry)
			entry_matching(entry, iface_name, callback);

		return;
	}

	for (let key, entry in cache) {
		if (entry.canonical !== canonical)
			continue;
		if ((type !== 'ANY' && entry.type !== type) || (rclass !== 'ANY' && entry.class !== rclass))
			continue;

		entry_matching(entry, iface_name, callback);
	}
}

function known_listed(known, entry, rec) {
	for (let item in known) {
		const record = item.record;

		if (item.canonical !== entry.canonical || record.type !== entry.type || record.class !== entry.class)
			continue;
		if (record.ttl >= rec.ttl / 2.0 && utils.rdata_equal(entry.type, record.rdata, rec.rdata))
			return true;
	}

	return false;
}

function doubt_count(rec, now) {
	if (rec.doubt_deadline != null)
		return;

	if (rec.doubt_since == null || now - rec.doubt_since > c.DOUBT_WINDOW_MS) {
		rec.doubt_since = now;
		rec.doubt_queries = 0;
	}

	if (++rec.doubt_queries >= c.DOUBT_QUERIES)
		rec.doubt_deadline = now + c.DOUBT_WINDOW_MS;
}

/**
 * RFC 6762 Section 10.5: note a query that our cached records should answer
 *
 * A record that another host's multicast question should get as a multicast
 * answer, and that is not in that query's known-answer list, is doubted once
 * per query packet. An NSEC record does not answer an ANY question. Once two
 * such queries were seen, the record is flushed by doubt_expire() unless an
 * answer arrives within ten seconds of the second one.
 *
 * @param {string} iface_name - Interface the query arrived on
 * @param {array} questions - Questions of the received query
 * @param {array} known_answers - Known-answer list of the query
 */
export function doubt_observe(iface_name, questions, known_answers) {
	const now = utils.now_ms();
	const known = map(known_answers ?? [], record => ({ canonical: utils.name_normalise(record.name), record }));
	const doubted = [];

	for (let question in questions) {
		if (question.unicast_response)
			continue;

		records_matching(question.name, question.type, question.class ?? 'IN', iface_name, function(entry, rec) {
			if (question.type === 'ANY' && entry.type === 'NSEC')
				return;
			if (index(doubted, rec) < 0 && !known_listed(known, entry, rec))
				push(doubted, rec);
		});
	}

	for (let rec in doubted)
		doubt_count(rec, now);
};

/**
 * RFC 6762 Section 10.4: ask for cached records to be confirmed
 *
 * The records are flushed by doubt_expire() unless an answer refreshes them
 * within ten seconds. The caller sends the queries.
 *
 * @param {string} name - Record name
 * @param {string} type - Record type, or ANY
 * @param {string} iface_name - Interface name
 * @returns {number} Number of records waiting for confirmation
 */
export function reconfirm(name, type, iface_name) {
	const now = utils.now_ms();
	let count = 0;

	records_matching(name, type, 'ANY', iface_name, function(entry, rec) {
		rec.doubt_since = now;
		rec.doubt_queries = c.DOUBT_QUERIES;
		rec.doubt_deadline = now + c.DOUBT_WINDOW_MS;
		count++;
	});

	return count;
};

/**
 * RFC 6762 Sections 10.4 and 10.5: flush doubted records nobody confirmed
 *
 * @param {number} timestamp - Current monotonic time in ms, defaults to now
 * @returns {number} Number of records flushed
 */
export function doubt_expire(timestamp) {
	const now = timestamp ?? utils.now_ms();
	let flushed = 0;

	for (let key, entry in cache) {
		const removed = [];

		for (let i = length(entry.records) - 1; i >= 0; i--) {
			const deadline = entry.records[i].doubt_deadline;

			if (deadline == null || now < deadline)
				continue;

			push(removed, entry.records[i]);
			splice(entry.records, i, 1);
		}

		flushed += length(removed);
		cleanup_empty_entry(key, entry);
		records_changed(entry, removed);
	}

	return flushed;
};
