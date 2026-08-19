/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * service.uc - Service announcement and discovery
 *
 * Handles mDNS service registration, browsing, and resolution.
 * Implements RFC 6763 (DNS-SD) service discovery.
 */

import * as utils from 'utils';
import * as log from 'log';
import * as mdns from 'mdns';
import * as key from 'key';
import * as c from 'const';

/* Registered services
 * {
 *   "My Printer._http._tcp.local.": {
 *     instance: "My Printer",
 *     service_type: "_http._tcp.local.",
 *     port: 8080,
 *     txt: { "path": "/", "papersize": "A4" },
 *     state: "probing|announcing|announced",
 *     hostname: "printer.local."
 *   }
 * }
 */
const services = {};

/* Service indexes for O(1) lookups
 * Maintained automatically by register/unregister operations.
 * Keyed by normalised name: wire-parsed names carry no trailing root
 * dot while registered names always do, and DNS names compare
 * case-insensitively (RFC 6762 Section 16) */
const services_by_type = {};  /* service_type -> [instance_names] */
const services_by_name = {};  /* name -> instance_name (PTR/SRV/TXT lookups) */

function index_key(name) {
	return utils.name_normalise(name);
}

/* Global hostname, set by main.uc via set_hostname(); declared before
 * build_records() because ucode resolves identifiers without hoisting */
let module_hostname;

/**
 * Derive the default instance label from the host name
 *
 * RFC 6763 Section 4.1.1: the instance name defaults to a user friendly name
 * for the host, which is what the OpenWrt umdns daemon uses too.
 *
 * @returns {string|null} Host label without the .local suffix
 */
function host_label() {
	if (!module_hostname)
		return null;

	return replace(module_hostname, /\.local\.?$/, '');
}

/**
 * RFC 6763 Section 7.1: the PTR owner names of the subtypes of a service
 * @param {object} svc - Registered service
 * @returns {array} Names like "_printer._sub._http._tcp.local"
 */
function subtype_names(svc) {
	return map(svc.subtypes ?? [], (subtype) => `${subtype}._sub.${svc.service_type}`);
}

/**
 * The TXT strings of a registered service
 *
 * A publisher that hands over encoded TXT data keeps its exact strings,
 * binary values and repeated keys included; the key/value form of the
 * service files is built into strings.
 *
 * @param {object} svc - Registered service
 * @returns {array} TXT strings
 */
export function txt_strings(svc) {
	return svc.txt_strings ?? utils.txt_build(svc.txt);
};

/**
 * Parse an SRV port
 *
 * The SRV port is one 16 bit field, so anything outside the range would be
 * truncated into a different port. int() answers NaN for anything
 * unparsable, and NaN compares false against every bound.
 *
 * @param {*} value - Port as given by the caller
 * @returns {number|null} Port, or null if out of range
 */
function port_parse(value) {
	const port = int(value);

	if (port != port || port < 1 || port > 65535)
		return null;

	return port;
}

/**
 * RFC 6763 Section 6.1: check the TXT record of a service against our limit
 * @param {object} svc - Service, registered or proposed
 * @returns {boolean} True if the TXT record fits
 */
function txt_fits(svc) {
	const total_size = utils.txt_size(txt_strings(svc));

	if (total_size <= c.MAX_TXT_SIZE)
		return true;

	log.WARN(`service: TXT record size ${total_size} exceeds limit of ${c.MAX_TXT_SIZE} bytes\n`);

	return false;
}

/**
 * Index an instance under PTR owner names
 *
 * A subtype PTR is looked up the way the PTR of the service type is.
 *
 * @param {array} type_names - Service type and subtype names
 * @param {string} instance_name - Full instance name
 */
function type_index_add(type_names, instance_name) {
	for (let type_name in type_names) {
		const type_key = index_key(type_name);

		services_by_type[type_key] ??= [];
		push(services_by_type[type_key], instance_name);
	}
}

/**
 * Remove an instance from PTR owner names
 * @param {array} type_names - Service type and subtype names
 * @param {string} instance_name - Full instance name
 */
function type_index_del(type_names, instance_name) {
	for (let type_name in type_names) {
		const type_key = index_key(type_name);
		const idx = index(services_by_type[type_key] ?? [], instance_name);

		if (idx >= 0)
			splice(services_by_type[type_key], idx, 1);
		if (!length(services_by_type[type_key]))
			delete services_by_type[type_key];
	}
}

/* Register a service for announcement
 * config: {
 *   id: "sshd",  (optional, opaque key for the caller)
 *   instance: "My Printer",  (optional, defaults to the host label)
 *   service: "_http._tcp.local" or "_http" with proto below,
 *   proto: "_tcp",  (or "_udp", omit when service carries the full type)
 *   domain: "local.",  (optional, defaults to "local.")
 *   port: 8080,
 *   txt: { key: "value", ... },  (optional)
 *   txt_strings: [ "key=value", ... ],  (optional, replaces txt)
 *   subtypes: [ "_printer", ... ],  (optional)
 *   hostname: "printer.local.",  (optional, uses system hostname if not specified)
 *   ops: { records, conflict, state }  (optional, announce operations of the owner)
 * }
 */
/**
 * Register a new mDNS service
 *
 * RFC 6762 Section 6: Tracks last multicast time per record type for rate limiting.
 *
 * @param {object} config - Service configuration, see above
 * @returns {string|null} Instance name if successful, null otherwise
 */
export function register(config) {
	if (!config?.service || !config?.port)
		return null;

	const port = port_parse(config.port);

	if (port == null) {
		log.WARN(`service: Cannot register ${config.service}: port ${config.port} out of range\n`);
		return null;
	}

	/* Check service limit */
	if (length(services) >= c.MAX_SERVICES) {
		log.WARN(`service: Cannot register service: maximum limit of ${c.MAX_SERVICES} services reached\n`);
		return null;
	}

	let service_type;

	if (config.proto) {
		service_type = utils.build_service_type(config.service, config.proto, config.domain || 'local.');
	} else {
		const parsed = utils.parse_service_type(config.service);

		if (!parsed) {
			log.WARN(`service: Cannot parse service type ${config.service}\n`);
			return null;
		}

		service_type = utils.build_service_type(parsed.service, parsed.proto, parsed.domain);
	}

	const instance = config.instance || host_label();

	if (!instance)
		return null;

	const instance_name = utils.build_instance_name(instance, service_type);

	/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
	 * ASCII-compatible encoding of it */
	if (utils.name_is_punycode(instance_name)) {
		log.WARN(`service: Cannot register ${instance_name}: punycode is not a legal mDNS encoding\n`);
		return null;
	}

	if (services[instance_name]) {
		log.WARN(`service: Service ${instance_name} already registered\n`);
		return null;
	}

	const svc = {
		id: config.id,
		instance: instance,
		service_type: service_type,
		port: port,
		txt: config.txt || {},
		txt_strings: config.txt_strings,
		subtypes: config.subtypes ?? [],
		ops: config.ops,
		state: 'registered',  /* Will transition to 'probing' when announced */
		hostname: config.hostname ? rtrim(config.hostname, '.') : null,
		last_sent: {},  /* RFC 6762 Section 6: Track last multicast time per record type */
		update_history: []  /* RFC 6762 Section 8.4: Track update times for rate limiting */
	};

	if (!txt_fits(svc))
		return null;

	services[instance_name] = svc;

	type_index_add([ service_type, ...subtype_names(svc) ], instance_name);
	services_by_name[index_key(instance_name)] = instance_name;

	return instance_name;
};

/**
 * Unregister a service
 *
 * Callers wanting a goodbye announcement must send it via
 * announce.goodbye() before unregistering.
 *
 * @param {string} instance_name - Full instance name
 * @returns {boolean} True if unregistered, false if not found
 */
export function unregister(instance_name) {
	const svc = services[instance_name];
	if (!svc)
		return false;

	type_index_del([ svc.service_type, ...subtype_names(svc) ], instance_name);

	delete services_by_name[index_key(instance_name)];
	delete services[instance_name];

	mdns.info(`service: Unregistered ${instance_name}\n`);

	return true;
};

/**
 * Change the records of a registered service in place
 *
 * RFC 6762 Section 8.4: an update keeps the name, so the caller announces the
 * new records without probing again.
 *
 * @param {string} instance_name - Full instance name
 * @param {object} config - New port, txt_strings, subtypes and hostname
 * @returns {boolean} True if the service was updated
 */
export function update(instance_name, config) {
	const svc = services[instance_name];
	const port = port_parse(config.port);

	if (!svc || port == null)
		return false;

	const proposed = {
		...svc,
		port: port,
		txt_strings: config.txt_strings,
		subtypes: config.subtypes ?? [],
		hostname: config.hostname ? rtrim(config.hostname, '.') : null
	};

	if (!txt_fits(proposed))
		return false;

	type_index_del(subtype_names(svc), instance_name);

	svc.port = proposed.port;
	svc.txt_strings = proposed.txt_strings;
	svc.subtypes = proposed.subtypes;
	svc.hostname = proposed.hostname;

	type_index_add(subtype_names(svc), instance_name);

	return true;
};

/**
 * Get service by instance name
 * @param {string} instance_name - Full instance name
 * @returns {object|undefined} Service object or undefined if not found
 */
export function get(instance_name) {
	return services[instance_name];
};

/**
 * Get all registered services
 * @returns {object} Object mapping instance names to service objects
 */
export function list() {
	return services;
};

/**
 * Build DNS records for a service
 *
 * RFC 6762 Section 10: TTL recommendations - host records 120s, service records 4500s.
 *
 * @param {string} instance_name - Full instance name
 * @param {number} ttl - Override TTL (null/undefined uses defaults, 0 for goodbye)
 * @returns {array} Array of DNS records (PTR, SRV, TXT)
 */
export function build_records(instance_name, ttl) {
	const svc = services[instance_name];
	if (!svc)
		return [];

	/* RFC 6762 Section 10: TTL recommendations
	 * Records with a host name in name or rdata (A/AAAA/SRV): 120 seconds
	 * Other resource records (TXT/PTR): 75 minutes (4500 seconds)
	 * Goodbye packets: 0 seconds */
	const ttl_service = ttl != null ? ttl :
	                    (svc.state === 'goodbye' ? c.GOODBYE_TTL_SEC : 4500);
	const ttl_host = ttl != null ? ttl :
	                 (svc.state === 'goodbye' ? c.GOODBYE_TTL_SEC : c.SERVICE_TTL_SEC);

	const records = [];
	const hostname = svc.hostname || module_hostname;

	/* PTR record: service type -> instance name (use service TTL) */
	push(records, {
		name: svc.service_type,
		type: 'PTR',
		class: 'IN',
		ttl: ttl_service,
		flush_cache: false,
		rdata: {
			ptr: instance_name
		}
	});

	/* SRV record: instance name -> host:port; carries the host name in
	 * its rdata, so it uses the short host TTL */
	push(records, {
		name: instance_name,
		type: 'SRV',
		class: 'IN',
		ttl: ttl_host,
		flush_cache: (ttl_host > 0),  /* Flush cache except for goodbye */
		rdata: {
			priority: 0,
			weight: 0,
			port: svc.port,
			target: hostname
		}
	});

	/* TXT record: instance name -> key=value attributes (use service TTL) */
	push(records, {
		name: instance_name,
		type: 'TXT',
		class: 'IN',
		ttl: ttl_service,
		flush_cache: (ttl_service > 0),
		rdata: {
			strings: txt_strings(svc)
		}
	});

	/* RFC 6763 Section 7.1: a subtype is one more shared PTR to the instance */
	for (let subtype_name in subtype_names(svc)) {
		push(records, {
			name: subtype_name,
			type: 'PTR',
			class: 'IN',
			ttl: ttl_service,
			flush_cache: false,
			rdata: {
				ptr: instance_name
			}
		});
	}

	for (let record in key.records(instance_name, ttl_host))
		push(records, record);

	return records;
};

/**
 * Set global hostname for service records
 * @param {string} hostname - Hostname like "myhost.local."
 */
export function set_hostname(hostname) {
	module_hostname = hostname ? rtrim(hostname, '.') : hostname;
};

/**
 * Set service state with validation
 *
 * Validates state transitions and maintains state machine integrity.
 * Single source of truth for all service state changes.
 *
 * Valid state transitions:
 * - registered -> probing
 * - probing -> announcing, registered (on conflict)
 * - announcing -> announced
 * - announced -> goodbye, probing (on conflict)
 * - goodbye -> (terminal state)
 *
 * @param {string} instance_name - Full instance name
 * @param {string} new_state - New state (probing, announcing, announced, goodbye)
 * @returns {boolean} True if transition valid and applied, false otherwise
 */
export function set_state(instance_name, new_state) {
	const svc = services[instance_name];
	if (!svc)
		return false;

	/* Define valid state transitions */
	const valid_transitions = {
		'registered': ['probing'],
		'probing': ['announcing', 'registered'],
		'announcing': ['announced', 'probing', 'goodbye'],
		'announced': ['goodbye', 'probing'],
		'goodbye': []
	};

	const current_state = svc.state || 'registered';
	const allowed = valid_transitions[current_state] || [];

	if (index(allowed, new_state) < 0) {
		log.ERR(`service: Invalid state transition for ${instance_name}: ${current_state} -> ${new_state}\n`);
		return false;
	}

	/* RFC 6762 Section 8.4: SHOULD NOT update records >10 times per minute
	 * Track update history when transitioning announced -> probing (update scenario) */
	if (current_state === 'announced' && new_state === 'probing') {
		const now = time();
		const one_minute_ago = now - 60;

		/* Remove updates older than 1 minute */
		svc.update_history = filter(svc.update_history, (t) => t > one_minute_ago);

		if (length(svc.update_history) >= c.UPDATE_RATE_LIMIT) {
			log.WARN(`service: Update rate limit exceeded for ${instance_name}: max 10 updates per minute (RFC 6762 Section 8.4)\n`);
			return false;
		}

		push(svc.update_history, now);
	}

	svc.state = new_state;

	mdns.debug(`service: State transition for ${instance_name}: ${current_state} -> ${new_state}\n`);

	return true;
};

/**
 * Get service state
 * @param {string} instance_name - Full instance name
 * @returns {string|null} Current state or null if not found
 */
export function get_state(instance_name) {
	const svc = services[instance_name];
	return svc ? (svc.state || 'registered') : null;
};

/**
 * RFC 6762 Section 8.3: whether probing for a service succeeded
 *
 * The name is ours from the first announcement on, so the service is
 * answered and defended while the announcements are still going out.
 *
 * @param {string} instance_name - Full instance name
 * @returns {boolean} True while announcing or announced
 */
export function is_owned(instance_name) {
	const state = get_state(instance_name);

	return state === 'announcing' || state === 'announced';
};

/**
 * The service types this host owns an instance of
 * @returns {array} Service type names
 */
export function types() {
	const found = {};

	for (let instance_name, svc in services) {
		if (is_owned(instance_name))
			found[svc.service_type] = true;
	}

	return keys(found);
};

/**
 * RFC 6763 Section 9: the PTR that answers the service type enumeration
 *
 * @param {string} service_type - Service type like "_http._tcp.local"
 * @returns {object} PTR record
 */
export function enumeration_record(service_type) {
	return {
		name: c.SERVICE_ENUM_NAME,
		type: 'PTR',
		class: 'IN',
		ttl: 4500,
		flush_cache: false,
		rdata: {
			ptr: service_type
		}
	};
};

/**
 * Get services by type (O(1) lookup via index)
 * @param {string} service_type - Service type like "_http._tcp.local."
 * @returns {array} Array of instance names for this type
 */
export function get_by_type(service_type) {
	return services_by_type[index_key(service_type)] || [];
};

/**
 * Find service instance by name (O(1) lookup via index)
 *
 * Handles both instance names and service type names (PTR lookups).
 *
 * @param {string} name - Name to look up (instance or service type)
 * @returns {string|null} Instance name or null if not found
 */
export function find_by_name(name) {
	return services_by_name[index_key(name)] || null;
};
