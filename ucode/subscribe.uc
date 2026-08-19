/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * subscribe.uc - Browse and resolve subscriptions for ubus clients
 *
 * A subscription names a service type to browse, one service instance to
 * resolve, or a host whose addresses to follow. It keeps a continuous query
 * running (RFC 6762 Section 5.2) and reports each change of its result as a
 * ubus notification: a new or changed instance or host, and one that went
 * away. Our own announced services and host names count as results too.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as cache from 'cache';
import * as service from 'service';
import * as host from 'host';
import * as tracker from 'tracker';
import * as packet from 'packet';
import * as utils from 'utils';
import * as uloop from 'uloop';
import * as mdns from 'mdns';
import * as c from 'const';

/* Subscription key -> {
 *   kind: "browse" | "instance" | "host",
 *   name: queried name, e.g. "_srv._udp.local" or "node.local",
 *   service_type: for browse and instance,
 *   owners: { owner: true },
 *   emitted: { result key: signature },
 *   identity: { result key: data of a removal notification }
 * } */
const subscriptions = {};

/* Instance name -> time its resolution was last asked for */
const resolve_asked = {};

/* Resolution queries emitted in the current second */
const resolve_budget = {};

let notifier;
let debounce_timer;
let refresh_interval;

/**
 * Set the function that delivers notifications
 * @param {function} fn - Called with (type, data)
 */
export function set_notifier(fn) {
	notifier = fn;
};

function notify(type, data) {
	if (notifier)
		notifier(type, data);
}

function iface_index(iface_name) {
	for (let iface in mdns.interface_list()) {
		if (iface.name === iface_name)
			return iface.index;
	}

	return 0;
}

/**
 * The interface our own records are reported on
 *
 * Our own records were not received on any interface, but a client needs a
 * valid one to tell results apart.
 *
 * @returns {string|null} First interface served, or null
 */
function iface_default() {
	return mdns.interface_list()[0]?.name;
}

function strip_local(name) {
	return replace(rtrim(name, '.'), /\.local$/i, '');
}

/**
 * RFC 6763 Section 6: encode TXT strings as TXT RDATA
 * @param {array} strings - TXT strings
 * @returns {string} RDATA as a hex string
 */
function txt_encode(strings) {
	return join('', map(strings, (str) => hexenc(chr(length(str)) + str)));
}

/**
 * The questions that keep a subscription current
 * @param {object} sub - Subscription
 * @returns {array} DNS questions
 */
function questions(sub) {
	let types = [ 'PTR' ];

	if (sub.kind === 'instance')
		types = [ 'SRV', 'TXT' ];
	else if (sub.kind === 'host')
		types = [ 'AAAA', 'A' ];

	return map(types, (record_type) => ({
		name: sub.name,
		type: record_type,
		class: 'IN',
		unicast_response: false
	}));
}

function question_key(question) {
	return `${utils.name_normalise(question.name)}\t${question.type}`;
}

/**
 * The questions the subscriptions need, other than the one given
 * @param {string} skip - Subscription key to leave out, may be null
 * @returns {object} Question key -> true
 */
function questions_wanted(skip) {
	const wanted = {};

	for (let sub_key, sub in subscriptions) {
		if (sub_key === skip)
			continue;

		for (let question in questions(sub))
			wanted[question_key(question)] = true;
	}

	return wanted;
}

/**
 * Start the continuous queries of a subscription that no other one runs
 * @param {object} sub - Subscription
 * @param {object} running - Question keys already running
 * @param {array} ifaces - Interface names
 */
function queries_start(sub, running, ifaces) {
	for (let question in questions(sub)) {
		if (running[question_key(question)])
			continue;

		for (let iface_name in ifaces)
			tracker.start_continuous(iface_name, question);
	}
}

/**
 * Stop the continuous queries no other subscription needs
 * @param {object} sub - Subscription being removed
 * @param {string} sub_key - Its key
 */
function queries_stop(sub, sub_key) {
	const wanted = questions_wanted(sub_key);

	for (let question in questions(sub)) {
		if (wanted[question_key(question)])
			continue;

		for (let iface in mdns.interface_list())
			tracker.stop_continuous(iface.name, question.name, question.type);
	}
}

/**
 * Ask for the SRV and TXT of an instance once, and for its addresses
 *
 * A browse learns instance names from PTR records; their details come from
 * separate questions. The budget stops one large response from turning into
 * a burst of queries.
 *
 * @param {string} instance_name - Full instance name
 * @param {string} target - SRV target if known
 * @param {string} iface_name - Interface the instance was seen on, may be null
 */
function resolve_ask(instance_name, target, iface_name) {
	const now = time();
	const key = utils.name_normalise(instance_name);

	if (resolve_asked[key] && now - resolve_asked[key] < c.SUBSCRIBE_REFRESH_MS / 1000)
		return;

	if (!utils.rate_allow(resolve_budget, c.MAX_REFRESH_QUERIES_PER_SEC))
		return;

	resolve_asked[key] = now;

	const asked = [
		{ name: instance_name, type: 'SRV', class: 'IN' },
		{ name: instance_name, type: 'TXT', class: 'IN' }
	];

	if (target) {
		push(asked, { name: target, type: 'AAAA', class: 'IN' });
		push(asked, { name: target, type: 'A', class: 'IN' });
	}

	for (let iface in mdns.interface_list()) {
		if (!iface_name || iface.name === iface_name)
			packet.send_query(iface.name, asked, false, null);
	}
}

/**
 * The addresses of a host name, from our own records and from the cache
 * @param {string} name - Host name
 * @returns {object} { ipv6, ipv4, iface, ttl }
 */
function addresses_get(name) {
	const result = { ipv6: [], ipv4: [], iface: null, ttl: 0 };
	const records = [ ...host.build_records(name, null, null),
	                  ...cache.lookup(name, 'AAAA'), ...cache.lookup(name, 'A') ];

	for (let record in records) {
		if (record.type !== 'AAAA' && record.type !== 'A')
			continue;

		const list = record.type === 'AAAA' ? result.ipv6 : result.ipv4;

		if (index(list, record.rdata.address) < 0)
			push(list, record.rdata.address);

		result.iface ??= record.iface;
		result.ttl = max(result.ttl, record.ttl ?? 0);
	}

	return result;
}

/**
 * The SRV and TXT of an instance, from our own records or from the cache
 * @param {string} instance_name - Full instance name
 * @returns {object|null} { srv, txt } records, or null if the SRV is unknown
 */
function instance_records(instance_name) {
	const own = service.find_by_name(instance_name);

	if (own && service.is_owned(own)) {
		const records = service.build_records(own);

		return {
			srv: filter(records, (record) => record.type === 'SRV')[0],
			txt: filter(records, (record) => record.type === 'TXT')[0]
		};
	}

	const srv = cache.lookup(instance_name, 'SRV')[0];

	if (!srv)
		return null;

	return { srv: srv, txt: cache.lookup(instance_name, 'TXT')[0] };
}

/**
 * Resolve one instance into the data of a notification
 * @param {string} instance_name - Full instance name
 * @param {string} service_type - Service type with .local
 * @param {string} iface_name - Interface the instance was seen on, may be null
 * @returns {object|null} Notification data, or null if not resolved yet
 */
function instance_info(instance_name, service_type, iface_name) {
	const found = instance_records(instance_name);

	if (!found?.txt) {
		resolve_ask(instance_name, found?.srv?.rdata?.target, iface_name);
		return null;
	}

	const srv = found.srv;
	const target = srv.rdata.target;
	const addresses = addresses_get(target);
	const strings = found.txt.rdata.strings ?? [];
	const iface = srv.iface ?? addresses.iface ?? iface_default();
	const full_name = rtrim(instance_name, '.');
	const type_name = rtrim(service_type, '.');

	if (!length(addresses.ipv6) && !length(addresses.ipv4))
		resolve_ask(instance_name, target, iface_name);

	return {
		service: strip_local(service_type),
		instance: substr(full_name, 0, length(full_name) - length(type_name) - 1),
		host: rtrim(target, '.'),
		port: srv.rdata.port,
		priority: srv.rdata.priority,
		weight: srv.rdata.weight,
		txt: map(strings, utils.utf8_escape),
		txt_hex: txt_encode(strings),
		addresses: addresses.ipv6,
		ipv4: addresses.ipv4,
		ttl: srv.ttl,
		iface: iface,
		ifindex: iface ? iface_index(iface) : 0
	};
}

/**
 * The instance names a service subscription covers
 * @param {object} sub - Browse or instance subscription
 * @returns {object} Full instance name -> interface it was seen on
 */
function instances_get(sub) {
	const found = {};

	if (sub.kind === 'instance') {
		found[sub.name] = null;
		return found;
	}

	for (let record in cache.lookup(sub.name, 'PTR'))
		found[record.rdata.ptr] = record.iface;

	for (let instance_name in service.get_by_type(sub.name)) {
		if (service.is_owned(instance_name))
			found[instance_name] = null;
	}

	return found;
}

/**
 * The current results of a subscription
 * @param {object} sub - Subscription
 * @returns {object} Result key -> { data, gone } where gone is the removal data
 */
function results_get(sub) {
	const results = {};

	if (sub.kind === 'host') {
		const addresses = addresses_get(sub.name);
		const iface = addresses.iface ?? iface_default();

		if (!length(addresses.ipv6) && !length(addresses.ipv4))
			return results;

		results[utils.name_normalise(sub.name)] = {
			data: {
				host: strip_local(sub.name),
				addresses: addresses.ipv6,
				ipv4: addresses.ipv4,
				ttl: addresses.ttl,
				iface: iface,
				ifindex: iface ? iface_index(iface) : 0
			},
			gone: { host: strip_local(sub.name), ifindex: iface ? iface_index(iface) : 0 }
		};

		return results;
	}

	for (let instance_name, iface_name in instances_get(sub)) {
		const info = instance_info(instance_name, sub.service_type, iface_name);

		if (!info)
			continue;

		results[utils.name_normalise(instance_name)] = {
			data: info,
			gone: { service: info.service, instance: info.instance, ifindex: info.ifindex }
		};
	}

	return results;
}

/**
 * Notify the changes of one subscription since its last evaluation
 *
 * The TTL is left out of the comparison, so a refreshed record that is
 * otherwise the same does not notify.
 *
 * @param {object} sub - Subscription
 */
function evaluate(sub) {
	const kind = sub.kind === 'host' ? 'host' : 'service';
	const results = results_get(sub);

	for (let result_key, result in results) {
		const signature = sprintf('%J', { ...result.data, ttl: null });

		if (sub.emitted[result_key] === signature)
			continue;

		sub.emitted[result_key] = signature;
		sub.identity[result_key] = result.gone;
		notify(kind, { ...result.data, removed: false });
	}

	for (let result_key in keys(sub.emitted)) {
		if (results[result_key])
			continue;

		notify(kind, { ...sub.identity[result_key], removed: true });
		delete sub.emitted[result_key];
		delete sub.identity[result_key];
	}
}

function evaluate_all() {
	debounce_timer = null;

	for (let sub_key, sub in subscriptions)
		evaluate(sub);
}

/**
 * Evaluate the subscriptions soon, once for a burst of triggers
 * @param {number} delay_ms - Delay, null for the default
 */
export function schedule(delay_ms) {
	if (debounce_timer || !length(subscriptions))
		return;

	debounce_timer = uloop.timer(delay_ms ?? c.SUBSCRIBE_DEBOUNCE_MS, evaluate_all);
};

/**
 * A received record may change a result
 *
 * RFC 6762 Section 10.1: a goodbye keeps the record for one second, so a
 * second evaluation follows once it is gone.
 *
 * @param {object} record - Received record
 */
export function record_seen(record) {
	if (!length(subscriptions))
		return;

	schedule();

	if (record.ttl === c.GOODBYE_TTL_SEC)
		uloop.timer(c.SUBSCRIBE_GOODBYE_MS, () => schedule());
};

/**
 * Parse a subscription request
 * @param {object} args - ubus arguments with owner and service, instance or host
 * @returns {object|null} { key, sub }, or null if malformed
 */
function request_parse(args) {
	if (type(args.owner) !== 'string' || !length(args.owner))
		return null;

	if (args.host) {
		const name = `${strip_local(args.host)}.local`;

		return {
			key: `host\t${utils.name_normalise(name)}`,
			sub: { kind: 'host', name: name }
		};
	}

	const service_type = `${strip_local(args.service ?? '')}.local`;

	if (!utils.parse_service_type(service_type))
		return null;

	if (args.instance) {
		const name = utils.build_instance_name(args.instance, service_type);

		return {
			key: `instance\t${utils.name_normalise(name)}`,
			sub: { kind: 'instance', name: name, service_type: service_type }
		};
	}

	return {
		key: `browse\t${utils.name_normalise(service_type)}`,
		sub: { kind: 'browse', name: service_type, service_type: service_type }
	};
}

/**
 * Add an owner to a subscription, creating it if needed
 *
 * A second owner of the same subscription gets the current results too, so
 * they are notified again.
 *
 * @param {object} args - ubus arguments
 * @returns {string} Result
 */
export function add(args) {
	const req = request_parse(args);

	if (!req)
		return 'invalid';

	let sub = subscriptions[req.key];

	if (!sub) {
		if (length(subscriptions) >= c.MAX_SUBSCRIPTIONS)
			return 'invalid';

		const running = questions_wanted(null);

		sub = { ...req.sub, owners: {}, emitted: {}, identity: {} };
		subscriptions[req.key] = sub;

		queries_start(sub, running, map(mdns.interface_list(), (iface) => iface.name));
	}

	sub.owners[args.owner] = true;
	sub.emitted = {};

	refresh_interval ??= uloop.interval(c.SUBSCRIBE_REFRESH_MS, evaluate_all);
	schedule();

	return 'ok';
};

/**
 * Remove one subscription after its last owner left
 * @param {string} sub_key - Subscription key
 */
function remove(sub_key) {
	queries_stop(subscriptions[sub_key], sub_key);
	delete subscriptions[sub_key];

	if (length(subscriptions) || !refresh_interval)
		return;

	refresh_interval.cancel();
	refresh_interval = null;
}

/**
 * Remove an owner from a subscription
 * @param {object} args - ubus arguments
 * @returns {string} Result
 */
export function del(args) {
	const req = request_parse(args);

	if (!req)
		return 'invalid';

	const sub = subscriptions[req.key];

	if (!sub?.owners[args.owner])
		return 'not_found';

	delete sub.owners[args.owner];

	if (!length(sub.owners))
		remove(req.key);

	return 'ok';
};

/**
 * Remove an owner from every subscription
 * @param {string} owner - Owner string
 * @returns {number} Number of subscriptions the owner left
 */
export function owner_flush(owner) {
	let count = 0;

	for (let sub_key in keys(subscriptions)) {
		const sub = subscriptions[sub_key];

		if (!sub.owners[owner])
			continue;

		delete sub.owners[owner];
		count++;

		if (!length(sub.owners))
			remove(sub_key);
	}

	return count;
};

/**
 * Run the queries of every subscription on an interface that came up
 * @param {string} iface_name - Interface name
 */
export function iface_start(iface_name) {
	const running = {};

	for (let sub_key, sub in subscriptions) {
		queries_start(sub, running, [ iface_name ]);

		for (let question in questions(sub))
			running[question_key(question)] = true;
	}
};

/**
 * Stop the queries of every subscription on an interface going away
 * @param {string} iface_name - Interface name
 */
export function iface_stop(iface_name) {
	for (let sub_key, sub in subscriptions) {
		for (let question in questions(sub))
			tracker.stop_continuous(iface_name, question.name, question.type);
	}

	schedule();
};
