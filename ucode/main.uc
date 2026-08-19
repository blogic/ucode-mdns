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

/* Track if refresh interface has been set */
let refresh_interface_set = false;

/* Entry operations for the host names; assigned below because the conflict
 * handler claims the replacement name with them */
let host_ops;

/**
 * RFC 6762 Section 9: another host answers for one of our names
 *
 * @param {string} name - Host name that lost the tiebreak
 * @param {array} ifaces - Interface names the name was claimed on
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

		/* Every SRV record targets the old name, so the services have to be
		 * rebuilt before they are announced again */
		services.reload_all();
	}

	for (let iface_name in ifaces)
		announce.start_probe(new_name, iface_name, host_ops);
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
 * Reconcile the claimed host names with what the loaded services ask for
 *
 * RFC 6762 Section 10.1: a name we stop claiming gets a goodbye first.
 */
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
}

function hosts_sync() {
	const wanted = services.hostnames();

	for (let name in host.extra_stale(wanted)) {
		for (let iface in mdns.interface_list())
			announce.goodbye(name, iface.name, host.build_records);

		announce.cancel(name);
	}

	host.extra_set(wanted);
	hosts_claim(null);
}

/**
 * RFC 6762 Section 9: watch received address records for a name we claim
 *
 * A conflict is defined by our record being unique, not by any flag the sender
 * chose to set.
 *
 * @param {object} record - Received DNS record
 * @param {object} iface - Interface the record arrived on
 */
function host_conflict_check(record, iface) {
	if (record.type !== 'A' && record.type !== 'AAAA')
		return;

	const host_name = host.canonical(record.name);

	if (!host_name || !announce.get_state(host_name))
		return;

	for (let our_record in host.build_records(host_name, null, iface.name)) {
		if (our_record.type !== record.type)
			continue;
		if (utils.rdata_equal(record.type, our_record.rdata, record.rdata))
			return;
	}

	announce.handle_conflict(host_name, record);
}

/**
 * Process resource records from a received response
 *
 * RFC 6762 Section 5.2: Notifies query tracker of received answers.
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

		/* RFC 6762 Section 5.2: Notify query tracker of received answers
		 * This resets exponential backoff for continuous queries and
		 * stops cache refresh queries when answers received */
		tracker.answer_received(iface.name, record.name, record.type);

		/* Service type names (starting with '_') trigger service discovery
		 * per RFC 6762 service enumeration */
		if (record.type === 'PTR')
			discovery.handle_ptr_record(record.name, record.rdata?.ptr,
			                            record.ttl, iface.name);

		/* RFC 6762 Section 9: Ongoing conflict detection
		 * MUST monitor all received records for conflicts with announced services
		 * Optimised: Use O(1) name lookup instead of O(n) service iteration */
		const instance_name = service.find_by_name(record.name);
		if (instance_name) {
			/* Every name we are claiming, not only the announced ones:
			 * RFC 6762 Section 8.1 resolves a conflict seen during
			 * probing by renaming */
			if (announce.get_state(instance_name)) {
				/* Build our records for this service */
				const our_records = service.build_records(instance_name);

				/* Check if incoming record conflicts with any of our records */
				for (let our_record in our_records) {
					if (utils.name_equal(our_record.name, record.name) &&
					    our_record.type === record.type &&
					    our_record.class === (record.class || 'IN')) {
						/* Same name/type/class - check if rdata differs */
						if (!utils.rdata_equal(record.type, our_record.rdata, record.rdata)) {
							announce.handle_conflict(instance_name, record);
						}
					}
				}
			}
		}

		host_conflict_check(record, iface);
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
function probes_process(pkt) {
	const proposed = {};

	for (let record in pkt.authority) {
		const name = service.find_by_name(record.name) ?? host.canonical(record.name);

		if (!name || !announce.get_state(name))
			continue;

		proposed[name] ??= [];
		push(proposed[name], record);
	}

	for (let name, records in proposed)
		announce.handle_probe(name, records);
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
		probes_process(pkt);

	/* RFC 6762 Section 7.2: a continuation of a multipacket known-answer list
	 * carries no questions, and its answers still have to suppress ours */
	if (!length(pkt.questions ?? [])) {
		if (length(pkt.answers ?? []) > 0)
			response.suppress_pending(iface.name, pkt.answers);

		return;
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
		break;

	case 'down':
		interface_release(iface.name);
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

	/* RFC 6762 Section 5.2: a continuous query, not a single shot. A
	 * responder that was asleep or busy when the first one went out is
	 * asked again, with the interval doubling up to an hour. */
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
	tracker.stop_continuous(iface_name, c.SERVICE_ENUM_NAME, 'PTR');

	for (let name in host.list()) {
		announce.goodbye(name, iface_name, host.build_records);
		announce.iface_remove(name, iface_name);
	}

	services.iface_stop(iface_name);
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

	/* RFC 6762 Section 10.1: withdraw the old name before claiming a new one */
	if (host.hostname() && host.hostname() !== config.hostname) {
		const previous = host.hostname();

		for (let iface in mdns.interface_list())
			announce.goodbye(previous, iface.name, host.build_records);

		announce.cancel(previous);
	}

	mdns.set_hostname(config.hostname);
	service.set_hostname(config.hostname);
	host.set_hostname(config.hostname);

	const running = [];
	for (let iface in mdns.interface_list())
		push(running, iface.name);

	for (let iface_name in running) {
		if (index(config.interfaces, iface_name) < 0) {
			interface_stop(iface_name);
			mdns.interface_destroy(iface_name);
			mdns.info(`main: Removed interface ${iface_name}\n`);
		}
	}

	for (let iface_name in config.interfaces) {
		if (index(running, iface_name) >= 0)
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

	log.NOTE(`main: Serving ${length(config.interfaces)} interface(s) as ${config.hostname}\n`);
};

/**
 * Initialise mDNS daemon
 *
 * RFC 6762 Section 8: MUST probe on startup before announcing.
 * RFC 6762 Section 5.2: Sets up cache maintenance at 80/85/90/95% TTL.
 * RFC 6762 Section 10.1: Configures goodbye packet sending on shutdown.
 *
 * @param {object} cfg - Configuration object, see apply()
 * @returns {void}
 */
export function init(cfg) {
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

	/* RFC 6762 Section 5.2: Start cache maintenance interval (every 10 seconds)
	 * Checks for records needing refresh at 80%, 85%, 90%, 95% TTL */
	uloop.interval(c.CACHE_MAINTENANCE_INTERVAL_MS, function() {
		const records_to_refresh = cache.maintenance();

		/* Refresh each record on the interface it was learned on; the
		 * record is only reachable there and querying elsewhere would
		 * just add traffic */
		for (let item in records_to_refresh) {
			const record = item.record;

			if (!record.iface)
				continue;

			const question = {
				name: record.name,
				type: record.type,
				class: record.class || 'IN',
				unicast_response: false
			};

			tracker.start_cache_refresh(
				record.iface,
				question,
				item.cache_key,
				[record]  /* RFC 6762 Section 7.1: Include cached record as known-answer */
			);
		}

		if (length(records_to_refresh) > 0)
			mdns.debug(`main: Issued ${length(records_to_refresh)} cache maintenance queries\n`);
	});

	/* Periodic cleanup interval (every hour)
	 * Cleans up old probe defence timestamps to prevent memory leaks */
	uloop.interval(c.CLEANUP_INTERVAL_MS, function() {
		response.cleanup_probe_defence(3600);
		packet.qu_expire();
	});

	apply(cfg);
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
	apply(config_load());
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
	 * destroying an interface purges whatever the C rate limiter queued, so
	 * doing both in one pass dropped part of the burst. */
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
