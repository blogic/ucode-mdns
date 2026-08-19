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
 *   type: "PTR",
 *   class: "IN",
 *   ttl: 120,
 *   flush_cache: false,
 *   rdata: { ... },
 *   inserted_at: 12345678,  (uloop time)
 *   expires_at: 12345798    (inserted_at + ttl)
 * }
 */

const cache = {};  /* Keyed by "name:type:class" */

/* RFC 6762 Section 5.2: Cache maintenance refresh tracking
 * Tracks which refresh percentage each record has reached
 * {
 *   "cache_key": {
 *     last_refresh_pct: 0,
 *   }
 * }
 */
const refresh_state = {};

let cache_full_logged = 0;


/**
 * Generate cache key from record components
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @returns {string} Cache key in format "name:type:class"
 */
function cache_key(name, type, rclass) {
	return `${utils.name_normalise(name)}:${type}:${rclass || 'IN'}`;
}

/**
 * RFC 6762 Section 5.2: Periodic cache maintenance scan
 *
 * Returns array of records needing refresh queries at 80%, 85%, 90%, 95% of TTL.
 * Tracks refresh for the oldest record in each entry.
 *
 * @returns {array} Array of objects with { cache_key, record, percentage } for records needing refresh
 */
export function maintenance() {
	const now = time();
	const percentages = c.CACHE_REFRESH_PERCENTAGES;
	const records_to_refresh = [];

	for (let key in cache) {
		const entry = cache[key];

		/* Find the oldest valid record in this entry for refresh tracking */
		let oldest_rec = null;
		let oldest_time = null;

		for (let rec in entry.records) {
			/* Skip goodbye packets, marked for deletion, or very short TTLs */
			if (rec.is_goodbye || rec.marked_for_deletion || (rec.ttl || 0) < 10)
				continue;

			if (!oldest_time || rec.inserted_at < oldest_time) {
				oldest_time = rec.inserted_at;
				oldest_rec = rec;
			}
		}

		if (!oldest_rec)
			continue;

		/* Calculate time elapsed and TTL percentage; force float
		 * arithmetic, integer division would always truncate to zero */
		const elapsed = now - oldest_rec.inserted_at;
		const ttl = oldest_rec.ttl || 0;
		const pct_elapsed = elapsed * 100.0 / ttl;

		/* Get current refresh state */
		const state = refresh_state[key] || { last_refresh_pct: 0 };

		/* Check if we've crossed any refresh threshold */
		for (let i = 0; i < length(percentages); i++) {
			const pct = percentages[i];

			/* RFC 6762 Section 5.2: Add ±2% random variation */
			const spread = c.CACHE_REFRESH_VARIATION_PCT * 2;
			const variation = (math.rand() % (spread * 100 + 1)) / 100.0 - c.CACHE_REFRESH_VARIATION_PCT;
			const threshold = pct + variation;

			/* Record needs refresh if we've passed this threshold and haven't queried at it yet */
			if (pct_elapsed >= threshold && state.last_refresh_pct < pct) {
				/* Return one representative record (the oldest) for refresh query */
				push(records_to_refresh, {
					cache_key: key,
					record: {
						name: entry.name,
						type: entry.type,
						class: entry.class,
						ttl: oldest_rec.ttl,
						rdata: oldest_rec.rdata,
						iface: oldest_rec.iface,
						inserted_at: oldest_rec.inserted_at,
						expires_at: oldest_rec.expires_at
					},
					percentage: pct
				});
				state.last_refresh_pct = pct;
				refresh_state[key] = state;
				break;  /* Only one refresh per entry per scan */
			}
		}
	}

	return records_to_refresh;
};

/**
 * Clean up refresh state for a cache entry
 * @param {string} key - Cache key
 */
function cleanup_refresh_state(key) {
	delete refresh_state[key];
}

/**
 * Clean up empty cache entry
 * @param {string} key - Cache key
 * @param {object} entry - Cache entry
 */
function cleanup_empty_entry(key, entry) {
	if (length(entry.records) === 0) {
		cleanup_refresh_state(key);
		delete cache[key];
	}
}

/**
 * Expand internal record structure to full record format
 * @param {object} entry - Cache entry with name, type, class
 * @param {object} rec - Individual record with ttl, rdata, timestamps
 * @returns {object} Full record format for backward compatibility
 */
function expand_record(entry, rec) {
	const result = {
		name: entry.name,
		type: entry.type,
		class: entry.class,
		ttl: rec.ttl,
		rdata: rec.rdata,
		flush_cache: rec.flush_cache,
		inserted_at: rec.inserted_at,
		expires_at: rec.expires_at,
		is_goodbye: rec.is_goodbye || false
	};

	if ('iface' in rec)
		result.iface = rec.iface;

	return result;
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
	const now = time();
	let expired = 0;

	for (let key in cache) {
		const entry = cache[key];

		/* Process each record in the entry */
		for (let i = length(entry.records) - 1; i >= 0; i--) {
			const rec = entry.records[i];

			/* RFC 6762 Section 10.2: Delete records marked for deletion after grace period */
			if (rec.marked_for_deletion && now >= rec.deletion_time) {
				splice(entry.records, i, 1);
				expired++;
				continue;
			}

			/* Standard TTL expiry */
			if (rec.expires_at && now >= rec.expires_at) {
				splice(entry.records, i, 1);
				expired++;
			}
		}

		cleanup_empty_entry(key, entry);
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

	for (let key in cache) {
		const entry = cache[key];
		let oldest = null;

		for (let rec in entry.records) {
			if (oldest === null || rec.inserted_at < oldest)
				oldest = rec.inserted_at;
		}

		push(candidates, { key: key, age: oldest ?? 0 });
	}

	sort(candidates, (a, b) => a.age - b.age);

	let evicted = 0;

	for (let candidate in candidates) {
		if (evicted >= count)
			break;

		cleanup_refresh_state(candidate.key);
		delete cache[candidate.key];
		evicted++;
	}

	return evicted;
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

	const key = cache_key(record.name, record.type, record.class);
	const now = time();
	const existing_entry = cache[key];
	const ttl = min(record.ttl ?? 0, c.MAX_RECEIVED_TTL_SEC);

	/* Check cache size limit for new entries. A full cache is remotely
	 * triggerable, so it is reported once per interval. */
	if (!existing_entry && length(cache) >= c.MAX_CACHE_ENTRIES) {
		if (now - cache_full_logged >= c.CACHE_FULL_LOG_INTERVAL_SEC) {
			log.WARN(`cache: At the limit of ${c.MAX_CACHE_ENTRIES} entries, evicting to make room\n`);
			cache_full_logged = now;
		}

		expire();

		if (length(cache) >= c.MAX_CACHE_ENTRIES)
			evict_lru(c.CACHE_EVICT_BATCH);
	}

	/* RFC 6762 Section 10.1: Goodbye packet handling
	 * When TTL=0 received, set TTL to 1 and delete after 1 second
	 * For goodbye, we mark all matching records in the array */
	if (record.ttl === c.GOODBYE_TTL_SEC) {
		if (!existing_entry) {
			/* No existing entry, create new goodbye entry */
			cache[key] = {
				name: record.name,
				type: record.type,
				class: record.class || 'IN',
				records: [{
					rdata: record.rdata,
					ttl: 1,
					inserted_at: now,
					expires_at: now + 1,
					is_goodbye: true,
					flush_cache: record.flush_cache || false,
					iface: iface
				}]
			};
		} else {
			/* Find and mark matching rdata as goodbye */
			let found = false;
			for (let i = 0; i < length(existing_entry.records); i++) {
				const rec = existing_entry.records[i];
				if (utils.rdata_equal(record.type, rec.rdata, record.rdata)) {
					rec.ttl = 1;
					rec.expires_at = now + 1;
					rec.is_goodbye = true;
					found = true;
					break;
				}
			}
			/* If not found, add as new goodbye record */
			if (!found) {
				if (length(existing_entry.records) >= c.MAX_RECORDS_PER_ENTRY)
					return false;

				push(existing_entry.records, {
					rdata: record.rdata,
					ttl: 1,
					inserted_at: now,
					expires_at: now + 1,
					is_goodbye: true,
					flush_cache: record.flush_cache || false,
					iface: iface
				});
			}
		}
		return true;
	}

	/* RFC 6762 Section 10.2: Cache-flush with 1-second grace period
	 * Mark records for deletion but keep them for 1 second to allow
	 * packets already in flight to be processed */
	if (record.flush_cache && existing_entry) {
		const grace_period = 1; /* 1 second as per RFC */

		for (let rec in existing_entry.records) {
			if (utils.rdata_equal(existing_entry.type, rec.rdata, record.rdata))
				continue;

			/* RFC 6762 Section 10.2: only records received more than a
			 * second ago are invalidated, so a large unique RRSet split
			 * across a burst of packets does not evict itself */
			if (now - rec.inserted_at < grace_period)
				continue;

			rec.marked_for_deletion = true;
			rec.deletion_time = now + grace_period;
		}
	}

	/* Create or update cache entry */
	if (!existing_entry) {
		/* New cache entry */
		cache[key] = {
			name: record.name,
			type: record.type,
			class: record.class || 'IN',
			records: [{
				rdata: record.rdata,
				ttl: ttl,
				inserted_at: now,
				expires_at: now + ttl,
				flush_cache: record.flush_cache || false,
				iface: iface
			}]
		};

		/* RFC 6762 Section 5.2: Reset refresh state for new records */
		if (ttl >= 10) {
			refresh_state[key] = { last_refresh_pct: 0 };
		}

		mdns.info(`cache: Discovered ${record.type} ${record.name} (TTL ${ttl})\n`);
	} else {
		/* Check if we already have this exact rdata */
		let found_index = -1;
		for (let i = 0; i < length(existing_entry.records); i++) {
			const rec = existing_entry.records[i];
			if (utils.rdata_equal(record.type, rec.rdata, record.rdata)) {
				found_index = i;
				break;
			}
		}

		if (found_index >= 0) {
			/* Update existing record */
			const rec = existing_entry.records[found_index];
			rec.ttl = ttl;
			rec.inserted_at = now;
			rec.expires_at = now + ttl;
			rec.flush_cache = record.flush_cache || false;
			rec.iface = iface;
			/* Clear any goodbye/deletion flags */
			delete rec.is_goodbye;
			delete rec.marked_for_deletion;
			delete rec.deletion_time;

			mdns.info(`cache: Updated ${record.type} ${record.name} (TTL ${ttl})\n`);
		} else {
			if (length(existing_entry.records) >= c.MAX_RECORDS_PER_ENTRY) {
				mdns.debug(`cache: Dropping ${record.type} for ${record.name}, entry holds ${c.MAX_RECORDS_PER_ENTRY} records\n`);
				return false;
			}

			/* Add new record to existing entry */
			push(existing_entry.records, {
				rdata: record.rdata,
				ttl: ttl,
				inserted_at: now,
				expires_at: now + ttl,
				flush_cache: record.flush_cache || false,
				iface: iface
			});

			mdns.info(`cache: Added additional ${record.type} for ${record.name} (TTL ${ttl})\n`);
		}

		/* RFC 6762 Section 5.2: Reset refresh state for updated records */
		if (ttl >= 10) {
			refresh_state[key] = { last_refresh_pct: 0 };
		}
	}

	return true;
};

/**
 * Lookup records in cache
 *
 * RFC 6762 Section 10.2: Does not return records marked for deletion.
 *
 * Returns array of all matching records (expanded from internal array structure).
 *
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @returns {array} Array of cached records (empty if not found/expired)
 */
export function lookup(name, type, rclass) {
	const key = cache_key(name, type, rclass || 'IN');
	const entry = cache[key];

	if (!entry)
		return [];

	const now = time();
	const results = [];

	/* Filter out marked/goodbye/expired records without modifying cache */
	for (let rec in entry.records) {
		/* RFC 6762 Section 10.2: Don't return records marked for deletion */
		if (rec.marked_for_deletion)
			continue;

		/* Check expiry - skip but don't remove (expire() will handle cleanup) */
		if (rec.expires_at && now >= rec.expires_at)
			continue;

		push(results, expand_record(entry, rec));
	}

	return results;
};

/**
 * Lookup all records for a name (any type)
 *
 * RFC 6762 Section 10.2: Skips records marked for deletion.
 *
 * @param {string} name - DNS name
 * @param {string} rclass - DNS class (defaults to 'IN')
 * @returns {array} Array of cached records for this name
 */
export function lookup_name(name, rclass) {
	const results = [];
	const now = time();
	const cls = rclass || 'IN';

	for (let key in cache) {
		const entry = cache[key];

		if (entry.name !== name || entry.class !== cls)
			continue;

		/* Process each record in the entry */
		for (let i = length(entry.records) - 1; i >= 0; i--) {
			const rec = entry.records[i];

			/* RFC 6762 Section 10.2: Skip records marked for deletion */
			if (rec.marked_for_deletion)
				continue;

			/* Check expiry */
			if (rec.expires_at && now >= rec.expires_at) {
				splice(entry.records, i, 1);
				continue;
			}

			push(results, expand_record(entry, rec));
		}

		cleanup_empty_entry(key, entry);
	}

	return results;
};

/**
 * Remove all records for a specific name+type+class from cache
 * @param {string} name - DNS name
 * @param {string} type - DNS record type
 * @param {string} rclass - DNS class (defaults to 'IN')
 */
export function remove(name, type, rclass) {
	const key = cache_key(name, type, rclass || 'IN');
	cleanup_refresh_state(key);
	delete cache[key];
};






/**
 * Get cache statistics
 * @returns {object} Object with entries, total records, expired, and active counts
 */
export function stats() {
	let entries = 0;
	let total_records = 0;
	let expired = 0;
	const now = time();

	for (let key in cache) {
		const entry = cache[key];
		entries++;

		for (let rec in entry.records) {
			total_records++;
			if (rec.expires_at && now >= rec.expires_at)
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
 * RFC 6762 Section 10.2: Skips records marked for deletion.
 *
 * Expands internal record arrays to individual records for backward compatibility.
 *
 * @param {string} type_filter - Optional DNS record type to filter by
 * @returns {array} Array of cached records
 */
export function get_all(type_filter) {
	const results = [];
	const now = time();
	let total_entries = 0, total_records = 0, marked = 0, expired = 0, filtered = 0;

	for (let key in cache) {
		const entry = cache[key];
		total_entries++;

		/* Apply type filter if specified */
		if (type_filter && entry.type !== type_filter) {
			filtered++;
			continue;
		}

		/* Process each record in the entry */
		for (let i = length(entry.records) - 1; i >= 0; i--) {
			const rec = entry.records[i];
			total_records++;

			/* RFC 6762 Section 10.2: Skip records marked for deletion */
			if (rec.marked_for_deletion) {
				marked++;
				continue;
			}

			/* Check expiry */
			if (rec.expires_at && now >= rec.expires_at) {
				expired++;
				splice(entry.records, i, 1);
				continue;
			}

			push(results, expand_record(entry, rec));
		}

		cleanup_empty_entry(key, entry);
	}

	return results;
};
