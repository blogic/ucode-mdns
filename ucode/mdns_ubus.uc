/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * mdns_ubus.uc - ubus interface for the mDNS daemon
 *
 * Publishes the `umdns` object with the method and argument names of the
 * OpenWrt umdns daemon, so the cli module and the LuCI pages keep working.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as ubus from 'ubus';
import * as uloop from 'uloop';
import * as cache from 'cache';
import * as service from 'service';
import * as host from 'host';
import * as discovery from 'discovery';
import * as tracker from 'tracker';
import * as utils from 'utils';
import * as c from 'const';
import * as main from 'main';
import * as log from 'log';
import * as mdns from 'mdns';
import * as dnssd_api from 'dnssd_ubus';

/* Numeric DNS types, as the umdns query and fetch methods take them */
const type_names = {};

for (let name, number in c.TYPE_NUMBERS)
	type_names[number] = name;

/* Queries the query method has put on the link in the current second */
const query_budget = {};

/**
 * Emit a value list the way the caller asked for it
 *
 * The umdns daemon repeats a key for every value unless the caller passes
 * array. A ucode object cannot hold a repeated key, so a non-array request
 * gets the first value.
 *
 * @param {array} list - Values
 * @param {boolean} array - True to return the whole list
 * @returns {*} List or first value, null when empty
 */
function value_emit(list, array) {
	if (!length(list))
		return null;

	return array ? list : list[0];
}

/**
 * Format a cache insertion time the way umdns does
 * @param {number} inserted_at - Seconds since the epoch
 * @returns {string|null} ISO 8601 timestamp
 */
function timestamp_format(inserted_at) {
	if (inserted_at == null)
		return null;

	/* The trailing Z says UTC, so the broken-down time has to be UTC too */
	const t = gmtime(inserted_at);

	return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
	               t.year, t.mon, t.mday, t.hour, t.min, t.sec);
}

function address_add(by_iface, iface_name, record) {
	by_iface[iface_name] ??= {};
	by_iface[iface_name][record.name] ??= { ipv4: [], ipv6: [] };

	const list = by_iface[iface_name][record.name][record.type === 'A' ? 'ipv4' : 'ipv6'];

	if (index(list, record.rdata.address) < 0)
		push(list, record.rdata.address);
}

function own_addresses_add(by_iface, iface_name) {
	for (let name in host.list()) {
		for (let record in host.build_records(name, null, iface_name))
			address_add(by_iface, iface_name, record);
	}
}

/**
 * Address records grouped by interface and name
 * @returns {object} { "br-lan": { "host.local": { ipv4: [...], ipv6: [...] } } }
 */
function addresses_collect() {
	const by_iface = {};

	for (let rec in [ ...cache.get_all('A'), ...cache.get_all('AAAA') ])
		address_add(by_iface, rec.iface, rec);

	/* Our own names never reach the cache, we answer for them */
	for (let iface in mdns.interface_list())
		own_addresses_add(by_iface, iface.name);

	return by_iface;
}

function scoped_entry_add(instances, label, entry, array) {
	const existing = instances[label];

	if (!existing)
		instances[label] = entry;
	else if (array && type(existing) == 'array')
		push(existing, entry);
	else if (array)
		instances[label] = [ existing, entry ];
}

function addresses_emit(entry, addresses, array) {
	const ipv4 = value_emit(addresses.ipv4, array);
	const ipv6 = value_emit(addresses.ipv6, array);

	if (ipv4 != null)
		entry.ipv4 = ipv4;
	if (ipv6 != null)
		entry.ipv6 = ipv6;
}

function hosts_iface_add(hosts, iface_name, addresses_by_host, array) {
	for (let name, addresses in addresses_by_host) {
		const entry = { iface: iface_name };

		addresses_emit(entry, addresses, array);

		if (entry.ipv4 != null || entry.ipv6 != null)
			scoped_entry_add(hosts, name, entry, array);
	}
}

/**
 * Get all discovered hosts with their addresses
 *
 * Each entry holds the addresses of one interface. With array set, a name
 * seen on several interfaces maps to a list of entries; without it, to the
 * first one.
 *
 * @param {boolean} array - True to report addresses and repeated names as arrays
 * @returns {object} Hostname to { iface, ipv4, ipv6 }
 */
export function get_hosts(array) {
	const hosts = {};
	const by_iface = addresses_collect();

	for (let iface in mdns.interface_list())
		hosts_iface_add(hosts, iface.name, by_iface[iface.name], array);

	return hosts;
};

function addresses_by_name(addresses_by_host) {
	const addresses = {};

	for (let name, found in addresses_by_host)
		addresses[utils.name_normalise(name)] = found;

	return addresses;
}

/**
 * Get all discovered services grouped by type and instance label
 *
 * @param {string} filter - Optional service type, with or without .local
 * @param {boolean} array - True to report TXT and addresses as arrays
 * @param {boolean} address - False to leave the addresses out
 * @returns {object} { "_http._tcp": { "Instance": { host, port, txt, ... } } }
 */
export function get_services(filter, array, address) {
	const services_by_type = {};
	const host_ips = {};
	const by_iface = address ? addresses_collect() : {};

	/* Build service index from SRV records (instance -> SRV data) */
	const srv_index = {};
	for (let srv in cache.get_all('SRV')) {
		srv_index[`${srv.iface}\t${utils.name_normalise(srv.name)}`] = {
			hostname: srv.rdata.target,
			port: srv.rdata.port,
			priority: srv.rdata.priority,
			weight: srv.rdata.weight,
			ttl: srv.ttl,
			inserted_at: srv.inserted_at,
			iface: srv.iface
		};
	}

	/* Build TXT index (instance -> TXT data) */
	const txt_index = {};
	for (let txt in cache.get_all('TXT'))
		txt_index[`${txt.iface}\t${utils.name_normalise(txt.name)}`] = map(txt.rdata.strings, utils.utf8_escape);

	const discovered = discovery.get_all();

	for (let service_type in discovered) {
		/* Strip .local suffix for output */
		const output_service_type = replace(service_type, /\.local\.?$/, '');

		if (filter && output_service_type !== replace(filter, /\.local\.?$/, ''))
			continue;

		for (let svc in discovered[service_type]) {
			const full_instance = svc.entry;

			/* Extract instance label from full instance name
			 * e.g., "Wohnzimmer._airplay._tcp.local" -> "Wohnzimmer" */
			const instance_label = utils.label_first(full_instance);
			const scoped = `${svc.iface}\t${utils.name_normalise(full_instance)}`;
			const srv_data = srv_index[scoped];

			host_ips[svc.iface] ??= addresses_by_name(by_iface[svc.iface]);

			const addresses = host_ips[svc.iface][utils.name_normalise(srv_data?.hostname)];

			/* Build service entry with only non-null fields */
			const entry = {
				iface: svc.iface,
				domain: "local"
			};

			if (srv_data) {
				if (srv_data.hostname !== null)
					entry.host = srv_data.hostname;
				if (srv_data.port !== null)
					entry.port = srv_data.port;
				if (srv_data.ttl !== null)
					entry.ttl = srv_data.ttl;
				if (srv_data.inserted_at !== null)
					entry.last_update = timestamp_format(srv_data.inserted_at);
				if (srv_data.priority !== null)
					entry.priority = srv_data.priority;
				if (srv_data.weight !== null)
					entry.weight = srv_data.weight;
			}

			if (txt_index[scoped])
				entry.txt = value_emit(txt_index[scoped], array);

			if (address && addresses)
				addresses_emit(entry, addresses, array);

			services_by_type[output_service_type] ??= {};
			scoped_entry_add(services_by_type[output_service_type], instance_label, entry, array);
		}
	}

	return services_by_type;
};

/**
 * The services this host announces
 * @returns {object} { "_http._tcp.local.": { "Instance": { port, txt, ... } } }
 */
function get_announcements() {
	const announced = {};
	const registered = service.list();

	for (let instance_name, svc in registered) {
		const service_type = svc.service_type;

		/* Keyed by the service id, as umdns_announcements() does; the
		 * instance label is carried as a field */
		announced[service_type] ??= {};
		announced[service_type][svc.id ?? svc.instance] = {
			instance: svc.instance,
			hostname: svc.hostname || host.hostname(),
			port: svc.port,
			state: svc.state,
			txt: utils.txt_build(svc.txt)
		};
	}

	return announced;
}

/**
 * Flatten one cached record the way the C daemon's cache_dump_recursive() does
 *
 * The fields sit at the top level rather than under rdata, and the TTL is what
 * remains rather than what was received.
 *
 * @param {object} rec - Cached record
 * @returns {object|null} Flattened record, or null once it has expired
 */
function fetch_record(rec) {
	const remaining = int(((rec.expires_at ?? 0) - utils.now_ms()) / 1000);

	if (remaining <= 0)
		return null;

	const out = {
		name: rec.name,
		type: rec.type,
		ttl: remaining
	};

	switch (rec.type) {
	case 'A':
	case 'AAAA':
		out.target = rec.rdata.address;
		break;

	case 'PTR':
		out.target = rec.rdata.ptr;
		break;

	case 'CNAME':
		out.target = rec.rdata.cname;
		break;

	case 'SRV':
		out.priority = rec.rdata.priority;
		out.weight = rec.rdata.weight;
		out.port = rec.rdata.port;
		out.target = rec.rdata.target;
		break;

	case 'TXT':
		out.data = map(rec.rdata.strings ?? [], utils.utf8_escape);
		break;
	}

	return out;
}

/**
 * Collect the cached records for a question, expanding as the C daemon does
 *
 * A PTR pulls in the SRV and TXT of its target, and an SRV pulls in the
 * addresses of its own, so one call answers a whole service. Each step stays
 * on the link the record was learned on.
 *
 * @param {string} name - Question name
 * @param {string} record_type - Record type, or ANY
 * @param {string} iface_name - Interface filter, may be null
 * @param {array} out - Accumulated records
 * @param {object} seen - Names already expanded, to stop a PTR loop
 * @returns {array} Flattened records
 */
export function fetch_records(name, record_type, iface_name, out, seen) {
	out ??= [];
	seen ??= {};

	const key = `${iface_name ?? ''}:${utils.name_normalise(name)}:${record_type}`;

	if (seen[key])
		return out;

	seen[key] = true;

	const found = record_type === 'ANY' ? cache.lookup_name(name, 'IN')
	                                    : cache.lookup(name, record_type, 'IN');

	for (let rec in found) {
		if (iface_name && rec.iface !== iface_name)
			continue;

		const flat = fetch_record(rec);

		if (!flat)
			continue;

		push(out, flat);

		if (rec.type === 'PTR') {
			fetch_records(rec.rdata.ptr, 'SRV', rec.iface, out, seen);
			fetch_records(rec.rdata.ptr, 'TXT', rec.iface, out, seen);
		} else if (rec.type === 'SRV') {
			fetch_records(rec.rdata.target, 'A', rec.iface, out, seen);
			fetch_records(rec.rdata.target, 'AAAA', rec.iface, out, seen);
		}
	}

	return out;
};

function ifaces_select(iface_name) {
	const ifaces = [];

	for (let iface in mdns.interface_list()) {
		if (!iface_name || iface.name === iface_name)
			push(ifaces, iface.name);
	}

	return ifaces;
}

/**
 * Send a query, or return what the cache holds for it
 *
 * @param {object} args - ubus arguments with question, interface, type
 * @param {boolean} fetch - True to read the cache instead of asking
 * @returns {object|null} Records for fetch, status for query
 */
function query_handle(args, fetch) {
	const question = args.question || c.SERVICE_ENUM_NAME;
	let record_type = 'ANY';

	if (args.type != null) {
		record_type = type_names[args.type];

		if (!record_type)
			return null;
	}

	if (fetch)
		return { records: fetch_records(question, record_type, args.interface) };

	if (!utils.rate_allow(query_budget, c.UBUS_QUERY_LIMIT)) {
		log.WARN(`ubus: Query rate limit reached, dropped query for ${question}\n`);
		return { status: 'rate limited' };
	}

	const ifaces = ifaces_select(args.interface);

	if (!length(ifaces))
		return null;

	for (let iface_name in ifaces)
		tracker.query_send(iface_name, { name: question, type: record_type, class: 'IN' });

	return { status: 'ok' };
}

function reconfirm_queries(iface_name, question) {
	tracker.query_send(iface_name, question);
	uloop.timer(c.RECONFIRM_REPEAT_MS, () => tracker.query_send(iface_name, question));
}

/**
 * RFC 6762 Section 10.4: reconfirm cached records a client believes stale
 *
 * The records are queried twice, one second apart, and flushed if no answer
 * refreshes them within ten seconds.
 *
 * @param {object} args - { question, interface, type }
 * @returns {object|number} { status, records }, or ubus.STATUS_INVALID_ARGUMENT
 *   for invalid arguments and ubus.STATUS_NOT_FOUND for an unknown interface
 */
export function reconfirm_handle(args) {
	const record_type = args.type != null ? type_names[args.type] : 'ANY';
	const question = { name: args.question, type: record_type, class: 'IN' };
	let records = 0;

	if (!args.question || !record_type)
		return ubus.STATUS_INVALID_ARGUMENT;

	const ifaces = ifaces_select(args.interface);

	if (!length(ifaces))
		return ubus.STATUS_NOT_FOUND;

	if (!utils.rate_allow(query_budget, c.UBUS_QUERY_LIMIT))
		return { status: 'rate limited' };

	for (let iface_name in ifaces) {
		const found = cache.reconfirm(args.question, record_type, iface_name);

		if (!found)
			continue;

		records += found;
		reconfirm_queries(iface_name, question);
	}

	return { status: 'ok', records };
};

let conn = null;
let ubus_obj = null;

/**
 * Initialise the ubus interface
 *
 * Must be called after uloop.init().
 *
 * @param {string} socket_path - ubus socket path, null for the default
 * @returns {boolean} True if initialised successfully, false on error
 */
export function init(socket_path) {
	/* Keep the event loop alive when a method handler throws */
	ubus.guard(function(e) {
		log.ERR(`ubus: Exception in handler: ${e}\n${e.stacktrace?.[0]?.context ?? ""}\n`);
	});

	conn = ubus.connect(socket_path);
	if (!conn) {
		log.ERR(`ubus: Failed to connect to ubus: ${ubus.error()}\n`);
		return false;
	}
	if (!dnssd_api.init(conn))
		log.ERR(`ubus: Failed to publish the dynamic DNS-SD interface: ${ubus.error()}\n`);

	ubus_obj = conn.publish('umdns', {
		hosts: {
			call: function(req) {
				return get_hosts(req.args.array);
			},
			args: {
				array: true
			}
		},
		browse: {
			call: function(req) {
				return get_services(req.args.service ?? req.args.service_type,
				                    req.args.array,
				                    req.args.address ?? true);
			},
			args: {
				service: "",
				service_type: "",  /* accepted for the older ucode-mdns name */
				array: true,
				address: true
			}
		},
		query: {
			call: function(req) {
				const result = query_handle(req.args, false);

				if (!result) {
					req.error(ubus.STATUS_NOT_FOUND);
					return;
				}

				return result;
			},
			args: {
				question: "",
				interface: "",
				type: 32
			}
		},
		fetch: {
			call: function(req) {
				const result = query_handle(req.args, true);

				if (!result) {
					req.error(ubus.STATUS_NOT_FOUND);
					return;
				}

				return result;
			},
			args: {
				question: "",
				interface: "",
				type: 32
			}
		},
		reconfirm: {
			call: function(req) {
				const result = reconfirm_handle(req.args);

				if (type(result) === 'int') {
					req.error(result);
					return;
				}

				return result;
			},
			args: {
				question: "",
				interface: "",
				type: 32
			}
		},
		announcements: {
			call: function(req) {
				return get_announcements();
			},
			args: {}
		},
		update: {
			call: function(req) {
				discovery.update();
				return { status: 'ok' };
			},
			args: {}
		},
		reload: {
			call: function(req) {
				main.reload();
				return { status: 'ok' };
			},
			args: {}
		},
		set_config: {
			call: function(req) {
				const wanted = req.args.interfaces;

				if (type(wanted) !== 'array') {
					req.error(ubus.STATUS_INVALID_ARGUMENT);
					return;
				}

				const interfaces = req.args.keep ? [ ...main.get_config().interfaces ] : [];

				for (let name in wanted) {
					if (type(name) !== 'string' || !length(name)) {
						req.error(ubus.STATUS_INVALID_ARGUMENT);
						return;
					}

					if (index(interfaces, name) < 0)
						push(interfaces, name);
				}

				main.apply({ interfaces: interfaces });

				return { status: 'ok' };
			},
			args: {
				interfaces: [],
				keep: true
			}
		},
		stats: {
			call: function(req) {
				return cache.stats();
			},
			args: {}
		}
	});

	if (!ubus_obj) {
		log.ERR(`ubus: Failed to publish ubus object: ${conn.error()}\n`);
		return false;
	}

	return true;
};

/**
 * Shutdown ubus interface
 *
 * Removes published object and disconnects from ubus daemon.
 *
 * @returns {void}
 */
export function shutdown() {
	dnssd_api.shutdown();
	if (ubus_obj) {
		ubus_obj.remove();
		ubus_obj = null;
	}
	if (conn) {
		conn.disconnect();
		conn = null;
	}
};
