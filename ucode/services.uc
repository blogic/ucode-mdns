/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * services.uc - Local service sources
 *
 * Collects the services this host announces from the two places the OpenWrt
 * umdns daemon reads them from: the JSON files in /etc/umdns and the "mdns"
 * blob in the data section of a running procd service instance.
 *
 * Functions are declared in dependency order because ucode resolves
 * identifiers at compile time without hoisting.
 */

import * as fs from 'fs';
import * as ubus from 'ubus';
import * as service from 'service';
import * as announce from 'announce';
import * as utils from 'utils';
import * as mdns from 'mdns';
import * as log from 'log';

const SERVICE_DIR = '/etc/umdns';

/* Services currently registered from these sources
 * { "<id>": { instance_name: "...", signature: "..." } } */
const loaded = {};

/* Extra host names the loaded services ask us to answer for */
let extra_hostnames = [];

/* Entry operations handed to announce.start_probe(); assigned below because
 * the conflict handler re-registers and therefore refers to them */
let ops;

/**
 * Normalise one service blob
 *
 * Shape as defined by service_policy in the OpenWrt umdns daemon:
 * { "service": "_http._tcp.local", "port": 80, "txt": [ "path=/" ],
 *   "instance": "...", "hostname": "..." }
 *
 * @param {string} id - Service id, the key the blob was found under
 * @param {object} blob - Service blob
 * @returns {object|null} Normalised entry or null if unusable
 */
function entry_normalise(id, blob) {
	if (type(blob) !== 'object')
		return null;

	if (!blob.service || !blob.port)
		return null;

	return {
		id: id,
		service: blob.service,
		port: int(blob.port),
		instance: blob.instance,
		hostname: blob.hostname,
		txt: utils.txt_parse(blob.txt || [])
	};
}

/**
 * Collect the service blobs from /etc/umdns
 * @param {object} wanted - Result object, keyed by service id
 */
function sources_files(wanted) {
	for (let path in fs.glob(`${SERVICE_DIR}/*`)) {
		const data = fs.readfile(path);

		if (!data) {
			log.WARN(`services: Cannot read ${path}: ${fs.error()}\n`);
			continue;
		}

		let parsed;

		try {
			parsed = json(data);
		} catch (e) {
			log.WARN(`services: Cannot parse ${path}: ${e}\n`);
			continue;
		}

		if (type(parsed) !== 'object')
			continue;

		for (let id, blob in parsed) {
			const entry = entry_normalise(id, blob);
			if (entry)
				wanted[id] = entry;
		}
	}
}

/**
 * Collect the service blobs advertised through procd service data
 *
 * procd runs in its own process, so the synchronous call cannot deadlock
 * against our own ubus object.
 *
 * @param {object} wanted - Result object, keyed by service id
 */
function sources_procd(wanted) {
	const list = ubus.call({ object: 'service', method: 'list' });

	if (!list) {
		log.WARN(`services: Cannot list procd services: ${ubus.error()}\n`);
		return;
	}

	for (let package_name, package_data in list) {
		for (let instance_name, instance in (package_data?.instances || {})) {
			if (!instance.running)
				continue;

			const blobs = instance.data?.mdns;

			if (type(blobs) !== 'object')
				continue;

			for (let id, blob in blobs) {
				const entry = entry_normalise(id, blob);
				if (entry)
					wanted[id] = entry;
			}
		}
	}
}

/**
 * Register one entry and start claiming its name on every interface
 * @param {string} id - Service id
 * @param {object} entry - Normalised entry
 */
function entry_add(id, entry) {
	const instance_name = service.register({
		id: id,
		instance: entry.instance,
		service: entry.service,
		port: entry.port,
		txt: entry.txt,
		hostname: entry.hostname
	});

	if (!instance_name) {
		log.WARN(`services: Cannot register ${id} (${entry.service})\n`);
		return;
	}

	loaded[id] = {
		instance_name: instance_name,
		signature: sprintf('%J', entry)
	};

	for (let iface in mdns.interface_list())
		announce.start_probe(instance_name, iface.name, ops);

	mdns.info(`services: Registered ${id} as ${instance_name}\n`);
}

/**
 * Withdraw one entry
 *
 * RFC 6762 Section 10.1: SHOULD send goodbye packets when records become
 * invalid.
 *
 * @param {string} id - Service id
 */
function entry_del(id) {
	const info = loaded[id];
	if (!info)
		return;

	const instance_name = info.instance_name;

	if (announce.get_state(instance_name)?.state === 'announced') {
		for (let iface in mdns.interface_list())
			announce.goodbye(instance_name, iface.name, service.build_records);
	}

	announce.cancel(instance_name);
	service.unregister(instance_name);

	delete loaded[id];

	mdns.info(`services: Withdrew ${id} (${instance_name})\n`);
}

/**
 * RFC 6762 Section 9: claim a different name after losing a probe tiebreak
 *
 * Appends " (2)" to the instance label, or increments an existing number,
 * and probes again on the interfaces the old name was claimed on.
 *
 * @param {string} instance_name - Full instance name that lost
 * @param {array} ifaces - Interface names the name was claimed on
 */
function entry_conflict(instance_name, ifaces) {
	const svc = service.get(instance_name);
	if (!svc)
		return;

	let new_instance = svc.instance + ' (2)';
	const numbered = match(svc.instance, / \((\d+)\)$/);

	if (numbered)
		new_instance = replace(svc.instance, / \(\d+\)$/, ` (${int(numbered[1]) + 1})`);

	const new_name = service.register({
		id: svc.id,
		instance: new_instance,
		service: svc.service_type,
		port: svc.port,
		txt: svc.txt,
		hostname: svc.hostname
	});

	if (!new_name) {
		log.ERR(`services: Failed to re-register ${instance_name} as ${new_instance}\n`);
		return;
	}

	service.unregister(instance_name);

	if (svc.id && loaded[svc.id])
		loaded[svc.id].instance_name = new_name;

	for (let iface_name in ifaces)
		announce.start_probe(new_name, iface_name, ops);

	mdns.info(`services: Renamed ${instance_name} to ${new_name}\n`);
}

ops = {
	records: service.build_records,
	conflict: entry_conflict,
	state: service.set_state
};

/**
 * Claim every registered service on an interface that just came up
 * @param {string} iface_name - Interface name
 */
export function iface_start(iface_name) {
	const registered = service.list();

	for (let instance_name in registered)
		announce.start_probe(instance_name, iface_name, ops);
};

/**
 * Release every registered service on an interface that is going away
 * @param {string} iface_name - Interface name
 */
export function iface_stop(iface_name) {
	const registered = service.list();

	for (let instance_name in registered) {
		if (announce.get_state(instance_name)?.state === 'announced')
			announce.goodbye(instance_name, iface_name, service.build_records);

		announce.iface_remove(instance_name, iface_name);
	}
};

/**
 * Reload the local services from all sources
 *
 * Registers what appeared, withdraws what vanished, and re-registers an entry
 * whose definition changed. Untouched entries keep their announcement state.
 *
 * @returns {number} Number of services registered afterwards
 */
export function load() {
	const wanted = {};

	sources_files(wanted);
	sources_procd(wanted);

	const names = {};
	for (let id, entry in wanted) {
		if (entry.hostname)
			names[entry.hostname] = true;
	}
	extra_hostnames = keys(names);

	for (let id in keys(loaded)) {
		if (wanted[id] && sprintf('%J', wanted[id]) === loaded[id].signature)
			continue;

		entry_del(id);
	}

	for (let id, entry in wanted) {
		if (loaded[id])
			continue;

		entry_add(id, entry);
	}

	return length(loaded);
};

/**
 * Extra host names asked for by the loaded services
 *
 * The hostname field of a service definition names a further host name this
 * host answers address queries for.
 *
 * @returns {array} Host names
 */
export function hostnames() {
	return extra_hostnames;
};

/**
 * Withdraw and re-register every service
 *
 * Needed when the host name changes, because every SRV record targets it.
 *
 * @returns {number} Number of services registered afterwards
 */
export function reload_all() {
	for (let id in keys(loaded))
		entry_del(id);

	return load();
};
