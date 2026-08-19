/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * main.uc - mDNS daemon main orchestration
 *
 * Top-level coordination of all mDNS functionality.
 * Handles initialization, event loop integration, and callback routing.
 */

import * as mdns from 'mdns';
import * as cache from 'cache';
import * as service from 'service';
import * as services from 'services';
import * as host from 'host';
import { load as config_load } from 'config';
import * as query from 'query';
import * as tracker from 'tracker';
import * as announce from 'announce';
import * as response from 'response';
import * as discovery from 'discovery';
import * as packet from 'packet';
import * as registry from 'dnssd_registry';
import * as dnssd_api from 'dnssd_ubus';
import * as uloop from 'uloop';
import * as fs from 'fs';
import * as utils from 'utils';
import * as log from 'log';
import * as c from 'const';

/* Configuration */
const config = {
	hostname: null,  /* Will be set from system or config */
	interfaces: [],  /* List of interface names to enable */
	ipv4: true,
	ipv6: true,
	debug: false,
	trace: false
};

/* Global logging flags */
global.cfg_debug = false;
global.cfg_trace = false;

let local_services_enabled = true;
let discovery_enabled = true;
let fixed_config;
let hostname_override;

function config_current() {
	if (fixed_config)
		return fixed_config;

	const cfg = config_load();

	if (hostname_override)
		cfg.hostname = hostname_override;

	return cfg;
}

/* Entry operations for the host names; assigned below because the conflict
 * handler claims the replacement name with them */
let host_ops;

/**
 * RFC 6762 Section 9: another host answers for one of our names
 *
 * @param {string} name - Host name that lost the tiebreak
 * @param {array} ifaces - Interface names the name was claimed on
 * @returns {string|null} Replacement name, or null if none was found
 */
function host_conflict(name, ifaces) {
	const was_primary = (host.hostname() === host.canonical(name));
	const new_name = host.rename(name);

	if (!new_name)
		return;

	log.NOTE(`main: Host name ${name} is taken, claiming ${new_name}\n`);

	if (was_primary) {
		config.hostname = new_name;
		mdns.set_hostname(new_name);
		service.set_hostname(new_name);
	}

	services.host_changed(name, new_name, was_primary);

	if (was_primary)
		registry.primary_changed();

	for (let iface_name in ifaces)
		announce.start_probe(new_name, iface_name, host_ops);
	return new_name;
}

host_ops = {
	records: host.build_records,
	conflict: host_conflict
};

/**
 * Claim every host name on one interface, or on all of them
 *
 * announce.start_probe() ignores a name already claimed on an interface, so
 * this is safe to repeat after every configuration or service reload.
 *
 * @param {string} iface_name - Interface name, null for every interface
 */
function hosts_claim(iface_name) {
	const ifaces = [];

	for (let iface in mdns.interface_list()) {
		if (!iface_name || iface.name === iface_name)
			push(ifaces, iface.name);
	}

	for (let name in host.list()) {
		for (let claim_iface in ifaces)
			announce.start_probe(name, claim_iface, host_ops);
	}
}

/**
 * Drop every claim held on an interface, without sending a goodbye
 *
 * Used when the link changed under us, where the records are already stale and
 * a goodbye would not reach anyone.
 *
 * @param {string} iface_name - Interface name
 */
function interface_release(iface_name) {
	for (let name in host.list())
		announce.iface_remove(name, iface_name);

	for (let instance_name in service.list())
		announce.iface_remove(instance_name, iface_name);

	registry.interface_down(iface_name);
}

/**
 * Reconcile the claimed host names with what the loaded services ask for
 *
 * RFC 6762 Section 10.1: a name we stop claiming gets a goodbye first.
 */
function hosts_sync() {
	const wanted = services.hostnames();

	for (let name in host.extra_stale(wanted)) {
		for (let iface in mdns.interface_list())
			announce.goodbye(name, iface.name, host.build_records);

		announce.cancel(name);
	}

	for (let change in host.extra_set(wanted))
		services.host_changed(change.from, change.to, false);

	hosts_claim(null);
}

function entry_find(name) {
	const instance = service.find_by_name(name);

	if (instance)
		return { name: instance, records: service.build_records };

	const host_name = host.canonical(name);

	if (host_name)
		return { name: host_name, records: host.build_records };

	const claim = registry.claim_find(name);

	return claim ? { name: claim, records: registry.records_get } : null;
}

function enumeration_records(record, iface_name) {
	return map(filter(registry.service_types(iface_name),
		service_type => utils.name_equal(service_type, record.rdata?.ptr)),
		service_type => service.enumeration_record(service_type));
}

function local_lookup(name, iface_name) {
	const entry = entry_find(name);

	return {
		entry: entry,
		records: entry ? entry.records(entry.name, null, iface_name) : []
	};
}

function ptr_records(record, iface_name) {
	const records = [];
	const target = record.rdata?.ptr;
	const instance = service.find_by_name(target);

	if (instance && announce.is_announced(instance, iface_name) &&
	    utils.name_equal(record.name, service.get(instance).service_type))
		push(records, ...filter(service.build_records(instance), our => our.type === 'PTR'));

	if (utils.name_equal(record.name, c.SERVICE_ENUM_NAME))
		push(records, ...enumeration_records(record, iface_name));

	if (announce.is_announced(host.hostname(), iface_name))
		push(records, ...host.reverse_records(record.name, iface_name));

	push(records, ...registry.records_query(iface_name, record.name, 'PTR'));

	return records;
}

function published_records(record, local, iface_name) {
	const records = record.type === 'PTR' ? ptr_records(record, iface_name) : [];

	if (local.entry && announce.is_announced(local.entry.name, iface_name))
		push(records, ...local.records);

	return records;
}

/**
 * RFC 6762 Sections 8.1 and 9: check a received record against a name we claim
 *
 * A conflict is defined by our record being unique, not by any flag the
 * sender chose to set.
 *
 * @param {object} record - Received DNS record
 * @param {string} iface_name - Interface the record arrived on
 * @param {object} local - Our entry and records at the record name
 * @returns {boolean} True if the record started conflict handling
 */
function conflict_check(record, iface_name, local) {
	const entry = local.entry;

	if (record.class !== 'IN' || record.ttl === 0 || !entry || !announce.get_state(entry.name))
		return false;

	const ours = filter(local.records, our => utils.name_equal(our.name, record.name) &&
		our.type === record.type);

	for (let our in ours) {
		if (utils.rdata_equal(record.type, our.rdata, record.rdata))
			return false;
	}

	if (announce.is_announced(entry.name, iface_name) &&
	    !length(filter(ours, our => our.flush_cache)))
		return false;

	announce.handle_conflict(entry.name, record, iface_name);
	return true;
}

/**
 * Process resource records from a received response
 *
 * RFC 6762 Section 9: Performs ongoing conflict detection for announced services.
 *
 * Caches all received records, handles service discovery, and detects
 * conflicts with our announced records.
 *
 * @param {object} packet - Parsed DNS response with answers, authority, additional
 * @param {object} iface - Interface object { name, index, ipv4_addresses, ipv6_addresses }
 * @returns {void}
 */
function records_process(pkt, iface, multicast) {
	const all_records = [
		...(pkt.answers || []),
		...(pkt.authority || []),
		...(pkt.additional || [])
	];
	let locals = {};

	if (multicast)
		response.duplicate_observe(iface.name, all_records);

	for (let record in all_records) {
		/* RFC 6891: Skip EDNS0 OPT pseudo-records (TYPE 41)
		 * OPT records have empty name and are used for capability negotiation,
		 * not actual DNS resource records. */
		if (record.type === 'OPT')
			continue;

		/* RFC 6762 Section 6: a unicast response is only acceptable if it
		 * answers a recent question of ours that asked for one. Without
		 * this any host on the link can seed the cache privately, unseen
		 * by every other responder. */
		if (!multicast && !packet.qu_pending(iface.name, record.name, record.type)) {
			mdns.debug(`main: Ignoring unsolicited unicast ${record.type} for ${record.name}\n`);
			continue;
		}

		cache.insert(record, iface.name);

		locals[record.name] ??= local_lookup(record.name, iface.name);
		const local = locals[record.name];

		response.correct_low_ttl(iface.name, published_records(record, local, iface.name), record);

		/* Service type names (starting with '_') trigger service discovery
		 * per RFC 6762 service enumeration */
		if (discovery_enabled && record.type === 'SRV')
			discovery.handle_srv_record(record, iface.name);
		if (discovery_enabled && record.type === 'PTR')
			discovery.handle_ptr_record(record.name, record.rdata?.ptr,
			                            record.ttl, iface.name);

		/* RFC 6762 Section 9: Ongoing conflict detection, MUST monitor
		 * all received records for conflicts with names we claim */
		if (conflict_check(record, iface.name, local))
			locals = {};
	}
}

/**
 * RFC 6762 Section 8.2: another host is probing for a name we are claiming
 *
 * The proposed records travel in the Authority Section of the probe, which is
 * a query, so this runs off the query path and never reaches the cache.
 *
 * @param {object} packet - Parsed DNS query carrying an authority section
 */
function probes_process(pkt, iface) {
	const proposed = {};

	for (let record in pkt.authority) {
		const name = entry_find(record.name)?.name;

		if (!name || !announce.get_state(name))
			continue;

		proposed[name] ??= [];
		push(proposed[name], record);
	}

	for (let name, records in proposed)
		announce.handle_probe(name, records, iface.name);
}

function on_packet(pkt, from, iface, multicast, is_legacy) {
	/* RFC 6762 Section 7.1: known-answer lists and Section 8.2 probe
	 * proposals carried in queries are not authoritative and MUST NOT
	 * be cached; only records in responses are processed.
	 * RFC 6762 Section 6: questions in responses MUST be ignored. */
	if (pkt.header?.flags?.response) {
		records_process(pkt, iface, multicast);
		return;
	}

	if (length(pkt.authority ?? []) > 0)
		probes_process(pkt, iface);

	/* RFC 6762 Section 7.2: a continuation of a multipacket known-answer list
	 * carries no questions, and its answers still have to suppress ours */
	if (!length(pkt.questions ?? [])) {
		if (length(pkt.answers ?? []) > 0 || pkt.header?.flags?.truncated)
			response.suppress_pending(iface.name, pkt.answers, pkt.header?.flags?.truncated, from.address);

		return;
	}

	if (multicast && !is_legacy && !length(pkt.authority ?? []) && !pkt.header?.flags?.truncated) {
		for (let question in pkt.questions)
			tracker.duplicate_observe(iface.name, question, pkt.answers ?? []);

		cache.doubt_observe(iface.name, pkt.questions, pkt.answers ?? []);
	}

	query.handle(pkt, from, iface, multicast, is_legacy);
}

/**
 * Interface change callback
 *
 * RFC 6762 Section 8: MUST probe on startup, wake from sleep, or link change.
 * Interface state changes require re-probing of all services to detect conflicts.
 *
 * @param {object} iface - Interface object { name, index, ipv4_addresses, ipv6_addresses }
 * @param {string} event - Event type: 'up', 'down', 'addr_add', 'addr_del'
 * @returns {void}
 */
function on_interface_change(iface, event) {
	mdns.info(`main: Interface ${iface.name} event: ${event}\n`);

	switch (event) {
	case 'up':
		/* RFC 6762 Section 8: a link change means probing again. Names
		 * already claimed on this interface are untouched by iface_start,
		 * so drop them first. */
		interface_release(iface.name);
		hosts_claim(iface.name);
		services.iface_start(iface.name);
		registry.interface_up(iface.name);
		tracker.restart(iface.name);
		dnssd_api.interface_changed(iface.name, true);
		break;

	case 'down':
		discovery.interface_remove(iface.name);
		interface_release(iface.name);
		dnssd_api.interface_changed(iface.name, false);
		break;

	case 'addr_add':
	case 'addr_del':
		/* The claim still stands, but the address records we published
		 * for it are stale */
		for (let name in host.list())
			announce.refresh(name, iface.name);
		break;
	}
}


/**
 * Start mDNS operation on a freshly created interface
 *
 * RFC 6762 Section 8: MUST probe before claiming a name on a new link.
 * RFC 6763 Section 9: Enumerate the service types present on the link.
 *
 * @param {string} iface_name - Interface name
 * @returns {void}
 */
function interface_start(iface_name) {
	hosts_claim(iface_name);
	services.iface_start(iface_name);
	dnssd_api.interface_changed(iface_name, true);

	/* RFC 6762 Section 5.2: a continuous query, not a single shot. A
	 * responder that was asleep or busy when the first one went out is
	 * asked again, with the interval doubling up to an hour. */
	if (discovery_enabled)
		tracker.start_continuous(iface_name, {
			name: c.SERVICE_ENUM_NAME,
			type: 'PTR',
			class: 'IN',
			unicast_response: false
		});
}

/**
 * Stop mDNS operation on an interface that is going away
 *
 * RFC 6762 Section 10.1: SHOULD send goodbye packets when records become
 * invalid.
 *
 * @param {string} iface_name - Interface name
 * @returns {void}
 */
function interface_stop(iface_name) {
	discovery.interface_remove(iface_name);
	tracker.stop_continuous(iface_name, c.SERVICE_ENUM_NAME, 'PTR');

	for (let name in host.list()) {
		announce.goodbye(name, iface_name, host.build_records);
		announce.iface_remove(name, iface_name);
	}

	services.iface_stop(iface_name);
	registry.interface_stop(iface_name);
	dnssd_api.interface_changed(iface_name, false);
	response.cancel_pending(iface_name);
}

/**
 * Apply a configuration
 *
 * Reconciles the running interface set with the configured one, so the same
 * path serves both startup and reload. Interfaces that are already up keep
 * their sockets and their announcement state.
 *
 * @param {object} cfg - Configuration object with optional fields:
 *   - hostname: string - Hostname to announce (default: system hostname)
 *   - interfaces: array - Interface names to enable (default: none)
 *   - ipv4: boolean - Enable IPv4 (default: true)
 *   - ipv6: boolean - Enable IPv6 (default: true)
 *   - debug: boolean - Enable debug logging (default: false)
 *   - trace: boolean - Enable packet tracing (default: false)
 * @returns {void}
 */
export function apply(cfg) {
	const previous_hostname = host.hostname();
	const previous_ipv4 = config.ipv4;
	const previous_ipv6 = config.ipv6;
	if (cfg?.hostname)
		config.hostname = cfg.hostname;
	if (cfg?.interfaces)
		config.interfaces = cfg.interfaces;
	if ('ipv4' in cfg)
		config.ipv4 = cfg.ipv4;
	if ('ipv6' in cfg)
		config.ipv6 = cfg.ipv6;
	if ('debug' in cfg) {
		config.debug = cfg.debug;
		global.cfg_debug = cfg.debug;
		mdns.set_debug(cfg.debug);
	}
	if ('trace' in cfg) {
		config.trace = cfg.trace;
		global.cfg_trace = cfg.trace;
		mdns.set_trace(cfg.trace);
	}

	if (!config.hostname)
		config.hostname = rtrim(fs.readfile('/proc/sys/kernel/hostname') || 'localhost', '\n');

	config.hostname = rtrim(config.hostname, '.');

	if (!match(config.hostname, /\.local$/i))
		config.hostname += '.local';
	config.hostname = mdns.name_prepare(host.resolved(config.hostname)) ?? previous_hostname ?? 'localhost.local';
	config.hostname = host.free_name(config.hostname);

	const hostname_changed = previous_hostname && !utils.name_equal(previous_hostname, config.hostname);

	if (previous_hostname && !hostname_changed)
		config.hostname = previous_hostname;

	/* RFC 6762 Section 10.1: withdraw the old name before claiming a new one */
	if (hostname_changed) {
		for (let iface in mdns.interface_list())
			announce.goodbye(previous_hostname, iface.name, host.build_records);

		announce.cancel(previous_hostname);
	}

	mdns.set_hostname(config.hostname);
	service.set_hostname(config.hostname);
	host.set_hostname(config.hostname);

	const running = [];
	const retained = [];
	const family_changed = previous_ipv4 !== config.ipv4 || previous_ipv6 !== config.ipv6;
	for (let iface in mdns.interface_list())
		push(running, iface.name);

	for (let iface_name in running) {
		if (index(config.interfaces, iface_name) < 0 || family_changed) {
			interface_stop(iface_name);
			mdns.flush();
			mdns.interface_destroy(iface_name);
			mdns.info(`main: Removed interface ${iface_name}\n`);
		} else {
			push(retained, iface_name);
		}
	}

	for (let iface_name in config.interfaces) {
		if (index(retained, iface_name) >= 0)
			continue;

		if (!mdns.interface_create({
			name: iface_name,
			ipv4: config.ipv4,
			ipv6: config.ipv6
		})) {
			log.ERR(`main: Failed to create interface ${iface_name}: ${mdns.error()}\n`);
			continue;
		}

		interface_start(iface_name);
	}

	if (hostname_changed) {
		services.primary_changed();
		registry.primary_changed();
	}

	log.NOTE(`main: Serving ${length(config.interfaces)} interface(s) as ${config.hostname}\n`);
};

function maintenance_tick() {
	const fallback = uloop.timer(c.CACHE_MAINTENANCE_INTERVAL_MS, maintenance_tick);

	if (discovery_enabled)
		discovery.retry_pending();

	const doubted = cache.doubt_expire();

	if (doubted > 0)
		mdns.info(`main: Flushed ${doubted} cache records nobody confirmed\n`);

	const scan = cache.maintenance(tracker.has_interest);

	/* Refresh each record on the interface it was learned on; the
	 * record is only reachable there and querying elsewhere would
	 * just add traffic */
	for (let item in scan.due) {
		const record = item.record;

		tracker.query_send(record.iface, {
			name: record.name,
			type: record.type,
			class: record.class || 'IN',
			unicast_response: false
		});
	}

	if (length(scan.due) > 0)
		mdns.debug(`main: Issued ${length(scan.due)} cache maintenance queries\n`);

	fallback.cancel();
	uloop.timer(scan.next, maintenance_tick);
}

/**
 * Initialise mDNS daemon
 *
 * RFC 6762 Section 8: MUST probe on startup before announcing.
 * RFC 6762 Section 5.2: Sets up cache maintenance at 80/85/90/95% TTL.
 * RFC 6762 Section 10.1: Configures goodbye packet sending on shutdown.
 *
 * @param {object} cfg - Configuration object, see apply()
 * @param {object} options - Optional fields:
 *   - local_services: boolean - Load the local service definitions (default: true)
 *   - discovery: boolean - Browse the link for services (default: true)
 *   - fixed: boolean - A reload applies @cfg again instead of the UCI configuration
 *   - hostname: string - Host name that replaces the configured one, also on reload
 * @returns {void}
 */
export function init(cfg, options) {
	local_services_enabled = options?.local_services !== false;
	discovery_enabled = options?.discovery !== false;
	fixed_config = options?.fixed ? cfg : null;
	hostname_override = options?.hostname;
	if (hostname_override)
		cfg.hostname = hostname_override;
	/* Register callbacks */
	mdns.set_callback('packet', on_packet);
	mdns.set_callback('interface_change', on_interface_change);

	/* Start cache expiry interval (every 60 seconds) */
	uloop.interval(c.CACHE_EXPIRY_INTERVAL_MS, function() {
		const expired = cache.expire();
		if (expired > 0)
			mdns.info(`main: Expired ${expired} cache entries\n`);

		discovery.cleanup_expired();
	});

	/* RFC 6762 Section 5.2: cache maintenance, at the refresh points of the
	 * records a continuous query wants */
	uloop.timer(c.CACHE_MAINTENANCE_INTERVAL_MS, maintenance_tick);

	/* Periodic cleanup interval (every hour)
	 * Expires old response history timestamps to prevent memory leaks */
	uloop.interval(c.CLEANUP_INTERVAL_MS, function() {
		response.history_expire(3600);
		announce.history_expire();
		packet.qu_expire();
	});

	apply(cfg);
	if (local_services_enabled)
		services.load();
	hosts_sync();
};

/**
 * Re-read the configuration and the local services
 *
 * The path behind SIGHUP and the ubus reload method.
 *
 * @returns {void}
 */
export function reload() {
	apply(config_current());
	if (local_services_enabled)
		services.load();
	hosts_sync();
};

/**
 * Shutdown mDNS daemon
 *
 * RFC 6762 Section 10.1: SHOULD send goodbye packets (TTL=0) when
 * records become invalid. Sends goodbye for all announced services
 * on all active interfaces before destroying them.
 *
 * @returns {void}
 */
export function shutdown() {
	log.NOTE("main: mDNS daemon shutting down\n");

	/* RFC 6762 Section 10.1: Send goodbye (TTL=0) for all announced services
	 * SHOULD send goodbye packets when records become invalid.
	 *
	 * The goodbyes go out first and the interfaces come down afterwards:
	 * destroying an interface purges the packets queued on it, so they are
	 * flushed before the cleanup. */
	const ifaces = mdns.interface_list();

	for (let iface in ifaces)
		interface_stop(iface.name);

	mdns.flush();
	mdns.cleanup();
};

/**
 * Get current daemon configuration
 *
 * @returns {object} Configuration object with hostname, interfaces, ipv4, ipv6, debug fields
 */
export function get_config() {
	return config;
};
