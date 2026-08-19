/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * discovery.uc - Active service discovery and tracking
 *
 * Maintains discovered services indexed by service type per RFC 6762,
 * enabling cascading queries for service enumeration and resolution.
 */

import * as mdns from 'mdns';
import * as utils from 'utils';
import * as c from 'const';
import * as cache from 'cache';
import * as tracker from 'tracker';

/* Services tree: keyed by service type (e.g., "_airplay._tcp.local")
 * Value: array of {
 *   entry: full instance name (e.g., "Wohnzimmer._airplay._tcp.local")
 *   service_type: service type the instance belongs to
 *   host: SRV target (e.g., "Wohnzimmer.local"), null until known
 *   ttl: TTL from PTR record
 *   time: utils.now_ms() when last seen
 *   iface: interface name
 *   host_watched: true while the address queries of host count this service
 *   resolution_pending: true while the refresh budget holds its queries back
 * }
 */
const services = {};

/* "iface\tinstance name" -> service entry, so service_add() does not scan the table */
const by_entry = {};

const browse_types = {};

const host_watch = {};

const INSTANCE_TYPES = [ 'SRV', 'TXT' ];
const HOST_TYPES = [ 'A', 'AAAA' ];
const HOST_SCOPE = 'discovery-host';
const BROWSE_SCOPE = 'discovery-browse';

let total = 0;

/* Query starts in the current second that put a query on the link */
const refresh_budget = {};

function refresh_allowed() {
	return utils.rate_allow(refresh_budget, c.MAX_REFRESH_QUERIES_PER_SEC);
}

function entry_key(iface_name, name) {
	return `${iface_name}\t${utils.name_normalise(name)}`;
}

function service_scope(service) {
	return 'discovery:' + utils.name_normalise(service.entry);
}

function services_each(callback) {
	for (let service_type, group in services) {
		for (let service in group) {
			if (callback(service) === false)
				return;
		}
	}
}

function queries_start(iface_name, name, types, scope) {
	for (let kind in types)
		tracker.start_continuous(iface_name, { name, type: kind, class: 'IN' }, scope);
}

function queries_stop(iface_name, name, types, scope) {
	for (let kind in types)
		tracker.stop_continuous(iface_name, name, kind, scope);
}

function queries_idle(iface_name, name, types) {
	for (let kind in types) {
		if (!tracker.query_active(iface_name, { name, type: kind }))
			return true;
	}

	return false;
}

function host_watch_change(iface_name, host, delta) {
	const key = entry_key(iface_name, host);
	const count = (host_watch[key] ?? 0) + delta;

	if (count <= 0) {
		queries_stop(iface_name, host, HOST_TYPES, HOST_SCOPE);
		delete host_watch[key];
		return;
	}

	if (!host_watch[key])
		queries_start(iface_name, host, HOST_TYPES, HOST_SCOPE);

	host_watch[key] = count;
}

function host_unwatch(service) {
	if (service.host_watched)
		host_watch_change(service.iface, service.host, -1);

	service.host_watched = false;
}

/**
 * Resolve a discovered service with continuous queries
 *
 * Queries SRV and TXT of the instance, and A and AAAA of the SRV target. The
 * address queries are shared by all services on the same target host.
 *
 * @param {object} service - Service entry object
 */
function refresh_service(service) {
	queries_start(service.iface, service.entry, INSTANCE_TYPES, service_scope(service));

	if (service.host && !service.host_watched) {
		host_watch_change(service.iface, service.host, 1);
		service.host_watched = true;
	}
}

function resolution_idle(service) {
	if (service.host && !service.host_watched && queries_idle(service.iface, service.host, HOST_TYPES))
		return true;

	return queries_idle(service.iface, service.entry, INSTANCE_TYPES);
}

function resolution_start(service) {
	if (resolution_idle(service) && !refresh_allowed()) {
		service.resolution_pending = true;
		return false;
	}

	service.resolution_pending = false;
	refresh_service(service);

	return true;
}

function stop_resolution(service) {
	queries_stop(service.iface, service.entry, INSTANCE_TYPES, service_scope(service));
	host_unwatch(service);
}

/**
 * Follow the SRV target of a discovered service
 *
 * @param {object} record - Received SRV record
 * @param {string} iface_name - Interface the record arrived on
 */
export function handle_srv_record(record, iface_name) {
	const service = by_entry[entry_key(iface_name, record.name)];

	if (!service || record.ttl === 0 || !record.rdata?.target)
		return;
	if (utils.name_equal(service.host, record.rdata.target))
		return;

	host_unwatch(service);
	service.host = record.rdata.target;
	resolution_start(service);
};

/**
 * Add or update service entry in discovery table
 *
 * Triggers immediate resolution queries for new services per RFC 6762.
 *
 * @param {string} entry - Full PTR target (instance name)
 * @param {string} service_type - Service type extracted from PTR name or entry
 * @param {number} ttl - TTL from PTR record
 * @param {string} iface_name - Interface name
 * @returns {object|undefined} Service entry object
 */
export function service_add(entry, service_type, ttl, iface_name) {
	ttl = min(ttl ?? 0, c.MAX_RECEIVED_TTL_SEC);

	/* Skip service enumeration meta-query */
	if (utils.name_equal(service_type, c.SERVICE_ENUM_NAME))
		return;

	/* Extract service type from entry if not provided
	 * Finds first occurrence of "._" which marks service type boundary */
	if (!service_type) {
		const dot_underscore = index(entry, '._');
		if (dot_underscore >= 0)
			service_type = substr(entry, dot_underscore + 1); // Skip the dot
		else
			return;
	}

	const scoped = entry_key(iface_name, entry);
	const known = by_entry[scoped];

	if (known) {
		known.time = utils.now_ms();
		known.ttl = ttl;
		return known;
	}

	if (!ttl)
		return;

	if (total >= c.MAX_DISCOVERED_SERVICES) {
		mdns.debug(`discovery: Ignoring ${entry}, table holds ${c.MAX_DISCOVERED_SERVICES} services\n`);
		return;
	}

	if (!services[service_type])
		services[service_type] = [];

	/* Extract hostname */
	const host = cache.lookup(entry, 'SRV', 'IN', iface_name)[0]?.rdata?.target ?? null;

	/* Create new service entry */
	const service = {
		entry: entry,
		service_type: service_type,
		host: host,
		ttl: ttl,
		time: utils.now_ms(),
		iface: iface_name
	};

	push(services[service_type], service);
	by_entry[scoped] = service;
	total++;

	mdns.info(`discovery: Added service: ${service_type} -> ${entry} (host: ${host || "none"})\n`);

	/* Immediately query for service details to populate cache */
	resolution_start(service);

	return service;
};

function browse_start(item) {
	const question = { name: item.name, type: 'PTR', class: 'IN' };

	if (!tracker.query_active(item.iface, question) && !refresh_allowed())
		return false;

	item.pending = false;
	tracker.start_continuous(item.iface, question, BROWSE_SCOPE);

	return true;
}

function browse_change(iface_name, service_type, wanted) {
	const key = entry_key(iface_name, service_type);
	const item = browse_types[key];

	if (!wanted) {
		if (item && !item.pending)
			tracker.stop_continuous(iface_name, service_type, 'PTR', BROWSE_SCOPE);

		delete browse_types[key];
		return;
	}

	if (item || length(browse_types) >= c.MAX_DISCOVERED_SERVICES)
		return;

	browse_types[key] = { iface: iface_name, name: service_type, pending: true };
	browse_start(browse_types[key]);
}

/**
 * Handle PTR record - add service and trigger queries
 *
 * RFC 6762: PTR records with names starting with '_' indicate service types.
 * Triggers cascading queries for service enumeration and instance resolution.
 *
 * @param {string} name - PTR record name (e.g., "_services._dns-sd._udp.local" or "_airplay._tcp.local")
 * @param {string} ptr_target - PTR record target/rdata (e.g., "_airplay._tcp.local" or "Wohnzimmer._airplay._tcp.local")
 * @param {number} ttl - TTL from PTR record
 * @param {string} iface_name - Interface name
 */
export function handle_ptr_record(name, ptr_target, ttl, iface_name) {
	/* Only process PTR records where name starts with _ */
	if (!name || type(name) !== 'string' || length(name) === 0 || substr(name, 0, 1) !== '_')
		return;

	if (!ptr_target || type(ptr_target) !== 'string')
		return;

	/* A target that is itself a service type answers the enumeration query or
	 * names a subtype. Neither is a service instance. */
	if (substr(ptr_target, 0, 1) === '_') {
		if (!utils.name_equal(name, c.SERVICE_ENUM_NAME))
			return;

		browse_change(iface_name, ptr_target, ttl > 0);
		return;
	}

	/* Add service instance to discovery table, extracting service type from PTR target */
	service_add(ptr_target, null, ttl, iface_name);
};

/**
 * Start the resolution of the services of an interface
 *
 * A service whose queries all run already costs no refresh budget. One that
 * the budget holds back is retried by retry_pending().
 *
 * @param {string} iface_name - Interface name
 */
export function refresh_all(iface_name) {
	services_each(function(service) {
		if (service.iface === iface_name)
			resolution_start(service);
	});
};

/**
 * Get all services (for browse)
 */
export function get_all() {
	return services;
};

function service_drop(service) {
	stop_resolution(service);
	delete by_entry[entry_key(service.iface, service.entry)];
	total--;
	mdns.info(`discovery: Expired service: ${service.service_type} -> ${service.entry}\n`);
}

/**
 * Clean up expired services
 */
export function cleanup_expired() {
	const now = utils.now_ms();

	for (let service_type, group in services) {
		const remaining = [];

		for (let service in group) {
			if (now - service.time < service.ttl * 1000)
				push(remaining, service);
			else
				service_drop(service);
		}

		if (length(remaining) > 0)
			services[service_type] = remaining;
		else
			delete services[service_type];
	}
};

/**
 * Trigger service discovery refresh per RFC 6762
 *
 * Queries the service enumeration name (_services._dns-sd._udp.local) once
 * on every interface, and starts the resolution of the known service
 * instances whose queries do not run yet.
 */
export function update() {
	const ifaces = mdns.interface_list();

	for (let iface in ifaces) {
		/* Query for available service types */
		tracker.query_send(iface.name, { name: c.SERVICE_ENUM_NAME, type: 'ANY', class: 'IN' });

		/* Query for service enumeration PTR records */
		tracker.query_send(iface.name, { name: c.SERVICE_ENUM_NAME, type: 'PTR', class: 'IN' });

		/* Refresh all known services */
		refresh_all(iface.name);
	}
};

/**
 * Drop everything discovered on an interface and stop its queries
 *
 * RFC 6762 Section 10.3: the cached records of the interface go too, so they
 * do not suppress the answers to the queries once the link returns.
 *
 * @param {string} iface_name - Interface name
 */
export function interface_remove(iface_name) {
	services_each(function(service) {
		if (service.iface === iface_name)
			service.ttl = 0;
	});

	cleanup_expired();

	for (let key, item in browse_types) {
		if (item.iface === iface_name)
			browse_change(iface_name, item.name, false);
	}

	cache.interface_flush(iface_name);
};

/**
 * Start the queries that the refresh budget held back
 */
export function retry_pending() {
	for (let key, item in browse_types) {
		if (item.pending && !browse_start(item))
			return;
	}

	services_each(function(service) {
		if (!service.resolution_pending)
			return true;

		return resolution_start(service);
	});
};
