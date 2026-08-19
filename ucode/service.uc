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
 * @returns {string|null} First label of the host name, without its escapes
 */
function host_label() {
	if (!module_hostname)
		return null;

	return utils.label_first(module_hostname);
}

let reserved_check;

/**
 * reservation_set - install the check for names another publisher holds
 * @check: function taking a name and returning true if it is taken, or null
 *
 * Return: nothing
 */
export function reservation_set(check) {
	reserved_check = check;
};

function type_label_valid(label) {
	const text = substr(label, 1);

	return !!match(label, /^_[A-Za-z0-9-]{1,15}$/) && !!match(text, /[A-Za-z]/) &&
		!match(text, /^-|-$|--/);
}

/**
 * type_parse - check and split a DNS-SD service type
 * @service_name: service label like "_http", or a full type like
 *                "_http._tcp.local" when @proto is null
 * @proto: protocol label "_tcp" or "_udp", or null
 * @domain: domain of a type given as labels, null for "local"
 *
 * Return: { service, proto, domain, name }, or null for a type that breaks
 *         RFC 6335 Section 5.1, RFC 6763 Section 7 or RFC 6762 Section 16
 */
export function type_parse(service_name, proto, domain) {
	if (type(service_name) != 'string')
		return null;

	const parsed = proto ? { service: service_name, proto, domain: domain || 'local' } :
		utils.parse_service_type(service_name);

	if (!parsed || type(parsed.proto) != 'string' || !type_label_valid(parsed.service) ||
	    !match(parsed.proto, /^_(tcp|udp)$/i))
		return null;

	parsed.name = utils.build_service_type(parsed.service, parsed.proto, parsed.domain);

	return utils.name_is_punycode(parsed.name) ? null : parsed;
};

/**
 * port_valid - check the SRV port of a service
 * @port: port number
 *
 * Return: true for an integer from 1 to 65535
 */
export function port_valid(port) {
	return type(port) == 'int' && port >= 1 && port <= c.SRV_FIELD_MAX;
};

/**
 * label_next - number an instance label for the next rename
 * @label: instance label, with or without a " (n)" suffix
 *
 * Return: the label with " (2)" appended or its number incremented,
 *         shortened to stay within 63 bytes
 */
export function label_next(label) {
	const numbered = match(label, / \(([0-9]+)\)$/);
	const base = numbered ? replace(label, / \([0-9]+\)$/, '') : label;
	const number = numbered ? int(numbered[1]) : 1;

	return utils.label_suffix(base, ` (${number + 1})`);
};

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
 * @param {object} config - Service configuration, see above
 * @param {string} replacement - Instance name this registration replaces after
 *   a conflict, which lets it register while the registry is full; null otherwise
 * @returns {string|null} Instance name if successful, null otherwise
 */
export function register(config, replacement) {
	if (!config?.service || !config?.port)
		return null;

	/* The SRV port is one 16 bit field, so anything outside the range
	 * would be truncated into a different port */
	const port = int(config.port);

	if (!port_valid(port)) {
		log.WARN(`service: Cannot register ${config.service}: port ${config.port} out of range\n`);
		return null;
	}

	/* Check service limit */
	if (length(services) >= c.MAX_SERVICES && !services[replacement]) {
		log.WARN(`service: Cannot register service: maximum limit of ${c.MAX_SERVICES} services reached\n`);
		return null;
	}

	const parsed = type_parse(config.service, config.proto, config.domain);

	if (!parsed) {
		log.WARN(`service: Cannot parse service type ${config.service}\n`);
		return null;
	}

	const service_type = parsed.name;
	const hostname = config.hostname ? mdns.name_prepare(config.hostname) : null;

	if (config.hostname && !hostname)
		return null;

	let instance = config.instance || host_label();

	if (!instance)
		return null;

	let instance_name;

	try {
		instance_name = utils.build_instance_name(instance, service_type);

		for (let tries = 0; reserved_check?.(instance_name) && tries < c.SERVICE_RENAME_MAX; tries++) {
			instance = label_next(instance);
			instance_name = utils.build_instance_name(instance, service_type);
		}
	} catch (e) {
		return null;
	}

	if (reserved_check?.(instance_name)) {
		log.WARN(`service: Cannot register ${instance_name}: the name is registered by a DNS-SD client\n`);
		return null;
	}

	/* RFC 6762 Section 16: a name we claim must be UTF-8, never an
	 * ASCII-compatible encoding of it */
	if (utils.name_is_punycode(instance_name)) {
		log.WARN(`service: Cannot register ${instance_name}: punycode is not a legal mDNS encoding\n`);
		return null;
	}

	if (services_by_name[index_key(instance_name)]) {
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
		hostname: hostname
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
 * records_make - build the records of a service instance
 * @instance_name: full instance name
 * @spec: { service_type, target, port, strings } and the optional
 *        { priority, weight, subtypes, ttl_host, ttl_service }
 * @ttl: TTL for every record, null for the TTLs of @spec or the RFC 6762
 *       Section 10 defaults, 0 for a goodbye
 *
 * Return: PTR, SRV and TXT records, then one PTR for each subtype name
 */
export function records_make(instance_name, spec, ttl) {
	const ttl_service = ttl ?? spec.ttl_service ?? c.RECORD_TTL_SEC;
	const ttl_host = ttl ?? spec.ttl_host ?? c.SERVICE_TTL_SEC;
	const browse = (name) => ({ name, type: 'PTR', class: 'IN', ttl: ttl_service,
		flush_cache: false, rdata: { ptr: instance_name } });

	return [
		browse(spec.service_type),
		{
			name: instance_name,
			type: 'SRV',
			class: 'IN',
			ttl: ttl_host,
			flush_cache: ttl_host > 0,
			rdata: {
				priority: spec.priority ?? 0,
				weight: spec.weight ?? 0,
				port: spec.port,
				target: spec.target
			}
		},
		{
			name: instance_name,
			type: 'TXT',
			class: 'IN',
			ttl: ttl_service,
			flush_cache: ttl_service > 0,
			rdata: {
				strings: spec.strings
			}
		},
		...map(spec.subtypes ?? [], browse)
	];
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

	return records_make(instance_name, {
		service_type: svc.service_type,
		target: svc.hostname || module_hostname,
		port: svc.port,
		strings: utils.txt_build(svc.txt)
	}, ttl ?? (svc.state === 'goodbye' ? c.GOODBYE_TTL_SEC : null));
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
 * - probing -> announcing, registered
 * - announcing -> announced, probing (on conflict), goodbye
 * - announced -> announcing (on a refresh or a new link), probing (on
 *   conflict), goodbye
 * - goodbye -> (terminal state)
 *
 * A report of the current state changes nothing and is accepted.
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
		'announced': ['announcing', 'goodbye', 'probing'],
		'goodbye': []
	};

	const current_state = svc.state || 'registered';
	const allowed = valid_transitions[current_state] || [];

	if (new_state === current_state)
		return true;

	if (index(allowed, new_state) < 0) {
		log.ERR(`service: Invalid state transition for ${instance_name}: ${current_state} -> ${new_state}\n`);
		return false;
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
 * Check if service is published on at least one link
 * @param {string} instance_name - Full instance name
 * @returns {boolean} True if announcing or announced, false otherwise
 */
export function is_announced(instance_name) {
	const state = get_state(instance_name);
	return state === 'announcing' || state === 'announced';
};

/**
 * The service types this host has an announced instance of
 * @returns {array} Service type names
 */
export function types() {
	const found = {};

	for (let instance_name, svc in services) {
		if (is_announced(instance_name))
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
		ttl: c.RECORD_TTL_SEC,
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
