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

import * as packet from 'packet';
import * as mdns from 'mdns';
import * as utils from 'utils';
import * as c from 'const';

/* Services tree: keyed by service type (e.g., "_airplay._tcp.local")
 * Value: {
 *   entry: full instance name (e.g., "Wohnzimmer._airplay._tcp.local")
 *   host: hostname (e.g., "Wohnzimmer.local")
 *   ttl: TTL from PTR record
 *   time: when last seen
 *   iface: interface name
 * }
 */
const services = {};

/* Instance name -> service entry, so service_add() does not scan the table */
const by_entry = {};

let total = 0;

/* Refresh queries emitted in the current second */
const refresh_budget = {};

/**
 * Extract hostname from instance name per RFC 6763 naming conventions
 *
 * Strips service type suffix from instance name to derive hostname.
 * Example: "Wohnzimmer._airplay._tcp.local" -> "Wohnzimmer.local"
 *
 * @param {string} instance_name - Full service instance name
 * @param {string} service_type - Service type to strip
 * @returns {string|null} Hostname or null if extraction fails
 */
function extract_hostname(instance_name, service_type) {
	const service_suffix = '.' + service_type;

	if (!match(instance_name, /\._/))
		return null;

	/* Check if instance_name ends with service_type */
	if (substr(instance_name, -length(service_suffix)) !== service_suffix)
		return null;

	/* Extract hostname part */
	const hostname_part = substr(instance_name, 0, length(instance_name) - length(service_suffix));
	if (!hostname_part || length(hostname_part) === 0)
		return null;

	return hostname_part + '.local';
}

function refresh_allowed() {
	return utils.rate_allow(refresh_budget, c.MAX_REFRESH_QUERIES_PER_SEC);
}

/**
 * Refresh service discovery by querying SRV/TXT for the service
 * instance and A/AAAA for hostname resolution
 *
 * @param {object} service - Service entry object
 * @param {string} iface_name - Interface name
 */
function refresh_service(service, iface_name) {
	/* PTR maps service type to instance; the instance itself owns SRV
	 * and TXT records (RFC 6763) */
	const questions = [
		{
			name: service.entry,
			type: 'SRV',
			class: 'IN'
		},
		{
			name: service.entry,
			type: 'TXT',
			class: 'IN'
		}
	];

	if (service.host) {
		push(questions, {
			name: service.host,
			type: 'A',
			class: 'IN'
		});
		push(questions, {
			name: service.host,
			type: 'AAAA',
			class: 'IN'
		});
	}

	packet.send_query(iface_name, questions, false, null);
}

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
	if (service_type === '_services._dns-sd._udp.local' ||
	    service_type === '_services._dns-sd._udp.local.')
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

	const known = by_entry[entry];

	if (known) {
		known.time = time();
		known.ttl = ttl;
		return known;
	}

	if (total >= c.MAX_DISCOVERED_SERVICES) {
		mdns.debug(`discovery: Ignoring ${entry}, table holds ${c.MAX_DISCOVERED_SERVICES} services\n`);
		return;
	}

	if (!services[service_type])
		services[service_type] = [];

	/* Extract hostname */
	const host = extract_hostname(entry, service_type);

	/* Create new service entry */
	const service = {
		entry: entry,
		service_type: service_type,
		host: host,
		ttl: ttl,
		time: time(),
		iface: iface_name
	};

	push(services[service_type], service);
	by_entry[entry] = service;
	total++;

	mdns.info(`discovery: Added service: ${service_type} -> ${entry} (host: ${host || "none"})\n`);

	/* Immediately query for service details to populate cache */
	if (refresh_allowed())
		refresh_service(service, iface_name);

	return service;
};

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
		if (name !== c.SERVICE_ENUM_NAME)
			return;

		if (refresh_allowed())
			packet.send_query(iface_name, [
				{
					name: ptr_target,
					type: 'PTR',
					class: 'IN'
				}
			], false, null);

		return;
	}

	/* Add service instance to discovery table, extracting service type from PTR target */
	service_add(ptr_target, null, ttl, iface_name);
};

/**
 * Refresh all known services
 * Called by update()
 */
export function refresh_all(iface_name) {
	for (let service_type in services) {
		for (let service in services[service_type]) {
			if (!refresh_allowed())
				return;

			refresh_service(service, iface_name);
		}
	}
};

/**
 * Get all services (for browse)
 */
export function get_all() {
	return services;
};

/**
 * Clean up expired services
 */
export function cleanup_expired() {
	const now = time();

	for (let service_type in services) {
		const remaining = [];
		for (let service in services[service_type]) {
			if (now - service.time < service.ttl) {
				push(remaining, service);
			} else {
				delete by_entry[service.entry];
				total--;
				mdns.info(`discovery: Expired service: ${service_type} -> ${service.entry}\n`);
			}
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
 * Queries for service enumeration (_services._dns-sd._udp.local)
 * and refreshes all known service instances.
 */
export function update() {
	const ifaces = mdns.interface_list();

	for (let iface in ifaces) {
		/* Query for available service types */
		packet.send_query(iface.name, [
			{
				name: '_services._dns-sd._udp.local',
				type: 'ANY',
				class: 'IN'
			}
		], false, null);

		/* Query for service enumeration PTR records */
		packet.send_query(iface.name, [
			{
				name: '_services._dns-sd._udp.local',
				type: 'PTR',
				class: 'IN'
			}
		], false, null);

		/* Refresh all known services */
		refresh_all(iface.name);
	}
};
