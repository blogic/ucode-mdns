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

/* Register a service for announcement
 * config: {
 *   id: "sshd",  (optional, opaque key for the caller)
 *   instance: "My Printer",  (optional, defaults to the host label)
 *   service: "_http._tcp.local" or "_http" with proto below,
 *   proto: "_tcp",  (or "_udp", omit when service carries the full type)
 *   domain: "local.",  (optional, defaults to "local.")
 *   port: 8080,
 *   txt: { key: "value", ... },  (optional)
 *   hostname: "printer.local."  (optional, uses system hostname if not specified)
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

	/* The SRV port is one 16 bit field, so anything outside the range
	 * would be truncated into a different port */
	const port = int(config.port);

	/* int() answers NaN for anything unparsable, and NaN compares false
	 * against every bound */
	if (port != port || port < 1 || port > 65535) {
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

	/* Validate TXT record size */
	if (config.txt) {
		const txt_strings = utils.txt_build(config.txt);
		const total_size = utils.txt_size(txt_strings);
		if (total_size > c.MAX_TXT_SIZE) {
			log.WARN(`service: Cannot register service: TXT record size ${total_size} exceeds limit of ${c.MAX_TXT_SIZE} bytes\n`);
			return null;
		}
	}

	services[instance_name] = {
		id: config.id,
		instance: instance,
		service_type: service_type,
		port: port,
		txt: config.txt || {},
		state: 'registered',  /* Will transition to 'probing' when announced */
		hostname: config.hostname ? rtrim(config.hostname, '.') : null,
		last_sent: {},  /* RFC 6762 Section 6: Track last multicast time per record type */
		update_history: []  /* RFC 6762 Section 8.4: Track update times for rate limiting */
	};

	/* Maintain indexes for O(1) lookups */
	const type_key = index_key(service_type);
	if (!services_by_type[type_key])
		services_by_type[type_key] = [];
	push(services_by_type[type_key], instance_name);

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

	const type_key = index_key(svc.service_type);
	if (services_by_type[type_key]) {
		const idx = index(services_by_type[type_key], instance_name);
		if (idx >= 0)
			splice(services_by_type[type_key], idx, 1);
		if (length(services_by_type[type_key]) === 0)
			delete services_by_type[type_key];
	}

	delete services_by_name[index_key(instance_name)];
	delete services[instance_name];

	mdns.info(`service: Unregistered ${instance_name}\n`);

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
			strings: utils.txt_build(svc.txt)
		}
	});

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
 * Check if service is in announced state
 * @param {string} instance_name - Full instance name
 * @returns {boolean} True if announced, false otherwise
 */
export function is_announced(instance_name) {
	return get_state(instance_name) === 'announced';
};

/**
 * The service types this host has an announced instance of
 * @returns {array} Service type names
 */
export function types() {
	const found = {};

	for (let instance_name, svc in services) {
		if (get_state(instance_name) === 'announced')
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
