/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * const.uc - mDNS protocol and implementation constants
 *
 * Centralised constants for RFC 6762/6763 compliance and implementation limits.
 */

/* RFC 6762 Section 8.1: Probe interval between queries */
export const PROBE_INTERVAL_MS = 250;

/* RFC 6762 Section 6: Minimum multicast response delay for shared records */
export const RESPONSE_DELAY_MIN_MS = 20;

/* RFC 6762 Section 6: Maximum multicast response delay for shared records */
export const RESPONSE_DELAY_MAX_MS = 120;

/* RFC 6762 Section 6: Response delay for unique records (sole responder) */
export const RESPONSE_DELAY_UNIQUE_MS = 10;

/* RFC 6762 Section 7.2: Minimum delay when TC bit set for known-answer suppression */
export const TC_DELAY_MIN_MS = 400;

/* RFC 6762 Section 7.2: Maximum delay when TC bit set for known-answer suppression */
export const TC_DELAY_MAX_MS = 500;

/* RFC 6762 Section 6: Minimum interval between multicasts of the same
 * record when answering probes */
export const PROBE_DEFENCE_RATE_LIMIT_MS = 250;

/* RFC 6762 Section 6: minimum interval between multicasts of the same record
 * on one interface */
export const MULTICAST_RATE_LIMIT_MS = 1000;

/* Cache expiry check interval (implementation-specific) */
export const CACHE_EXPIRY_INTERVAL_MS = 60000;

/* RFC 6762 Section 5.2: Cache maintenance check interval */
export const CACHE_MAINTENANCE_INTERVAL_MS = 10000;

/* Probe defence timestamp cleanup interval (implementation-specific) */
export const CLEANUP_INTERVAL_MS = 3600000;

/* RFC 6762 Section 8.1: Backoff delay after conflict rate limit */
export const CONFLICT_BACKOFF_MS = 5000;

/* RFC 6762 Section 8.2: the loser of a simultaneous probe tiebreak waits one
 * second and probes again */
export const PROBE_DEFER_MS = 1000;

/* RFC 6762 Section 6: how long a unicast response stays acceptable after the
 * QU question that asked for it */
export const QU_RESPONSE_WINDOW_SEC = 2;

/* RFC 6762 Section 8.1: Conflict history tracking window */
export const CONFLICT_HISTORY_WINDOW_SEC = 10;

/* RFC 6762 Section 8.1: Maximum conflicts before backoff */
export const CONFLICT_RATE_LIMIT = 15;

/* RFC 6762 Section 8.1: Number of probes to send */
export const PROBE_COUNT = 3;

/* RFC 6762 Section 8.3: Maximum number of announcements to send */
export const ANNOUNCEMENT_COUNT_MAX = 8;

/* Retry interval after a probe or announcement could not be sent, usually
 * because the interface has no address yet */
export const ANNOUNCE_RETRY_MS = 5000;

/* RFC 6762 Section 8.4: Maximum record updates per minute */
export const UPDATE_RATE_LIMIT = 10;

/* RFC 6762 Section 10: TTL for records carrying a host name */
export const SERVICE_TTL_SEC = 120;

/* RFC 6762 Section 6.7: Maximum TTL for legacy unicast responses */
export const LEGACY_MAX_TTL_SEC = 10;

/* RFC 6762 Section 10.1: TTL for goodbye packets */
export const GOODBYE_TTL_SEC = 0;

/* Ceiling applied to a TTL taken off the wire. RFC 6762 Section 10 puts the
 * longest recommended TTL at 75 minutes. */
export const MAX_RECEIVED_TTL_SEC = 4500;

/* RFC 6762 Section 5.2: TTL percentages for cache refresh queries */
export const CACHE_REFRESH_PERCENTAGES = [80, 85, 90, 95];

/* RFC 6762 Section 5.2: Random variation for cache refresh timing */
export const CACHE_REFRESH_VARIATION_PCT = 2;

/* RFC 6763 Section 6.1: Conservative limit for TXT record size */
export const MAX_TXT_SIZE = 1300;

/* Conservative packet size limit for MTU (implementation-specific) */
export const MAX_PACKET_SIZE = 1400;

/* Maximum registered services limit for DoS protection (implementation-specific) */
export const MAX_SERVICES = 1000;

/* Maximum cache entries limit for DoS protection (implementation-specific) */
export const MAX_CACHE_ENTRIES = 10000;

/* Maximum records held under one name, type and class. A legitimate RRSet is
 * far smaller; the bound stops a remote host growing one entry without limit
 * and keeps the rdata scan in cache.insert() short */
export const MAX_RECORDS_PER_ENTRY = 32;

/* Entries evicted per sweep once the cache is full, so the scan is amortised */
export const CACHE_EVICT_BATCH = 64;

/* Minimum seconds between "cache full" log lines */
export const CACHE_FULL_LOG_INTERVAL_SEC = 60;

/* Questions answered from one received packet. Names compress to two bytes,
 * so a single maximum sized query can otherwise ask close to 1500 times */
export const MAX_QUESTIONS_PER_PACKET = 32;

/* RFC 6762 Section 6.7: legacy responses go to one address, so they cannot be
 * aggregated. Cap how many one source can draw per second instead. */
export const LEGACY_RESPONSE_LIMIT = 20;

/* Queries the ubus query method may put on the link in one second. Every
 * call multicasts on every interface, so an unbounded caller floods the
 * link the same way a remote host could. */
export const UBUS_QUERY_LIMIT = 10;

/* Maximum value returned by math.rand() */
export const RAND_MAX = 0x7fffffff;

/* RFC 6763 Section 9: the service type enumeration name */
export const SERVICE_ENUM_NAME = '_services._dns-sd._udp.local';

/* DNS record type numbers, as they appear on the wire */
export const TYPE_NUMBERS = {
	'A': 1,
	'NS': 2,
	'CNAME': 5,
	'PTR': 12,
	'TXT': 16,
	'AAAA': 28,
	'SRV': 33,
	'OPT': 41,
	'NSEC': 47,
	'ANY': 255
};

/* DNS class numbers */
export const CLASS_NUMBERS = {
	'IN': 1,
	'ANY': 255
};

/* Maximum discovered service instances held (implementation-specific) */
export const MAX_DISCOVERED_SERVICES = 2000;

/* Resolution queries emitted per second. Every newly discovered instance asks
 * for its SRV, TXT and addresses, so without a ceiling a single response full
 * of unknown targets turns into hundreds of outgoing packets. */
export const MAX_REFRESH_QUERIES_PER_SEC = 20;
