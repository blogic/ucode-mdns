/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * config.uc - UCI configuration
 *
 * Reads /etc/config/umdns and resolves the configured UCI networks to the
 * devices the daemon binds to.
 */

import * as uci from 'uci';
import * as ubus from 'ubus';
import * as log from 'log';

const CONFIG_NAME = 'umdns';

function option_list(section, option) {
	const value = section[option];

	if (value == null)
		return [];

	if (type(value) === 'array')
		return value;

	return filter(split(value, /[ \t]+/), (entry) => length(entry) > 0);
}

/* The UCI boolean spellings, as libuci and the shell helpers accept them */
const FALSE_WORDS = [ '0', 'off', 'false', 'no', 'disabled' ];
const TRUE_WORDS = [ '1', 'on', 'true', 'yes', 'enabled' ];

function option_bool(section, option, fallback) {
	const value = section[option];

	if (value == null)
		return fallback;

	const word = lc(trim(`${value}`));

	if (index(FALSE_WORDS, word) >= 0)
		return false;

	if (index(TRUE_WORDS, word) >= 0)
		return true;

	log.WARN(`config: Ignoring unrecognised value for ${option}: ${value}\n`);

	return fallback;
}

/**
 * Resolve a UCI network to the device carrying its layer 3 addresses
 *
 * netifd runs in its own process, so the synchronous call cannot deadlock
 * against our own ubus object.
 *
 * A network that is down has no layer 3 device to bind to. It is skipped
 * here and picked up by the reload that the netifd interface trigger fires
 * once it comes up.
 *
 * @param {string} network - UCI network name like "lan"
 * @returns {string|null} Device name, or null if the network is not up
 */
export function network_resolve(network) {
	const status = ubus.call({
		object: `network.interface.${network}`,
		method: 'status'
	});

	if (!status?.up)
		return null;

	return status.l3_device;
};

/**
 * The system host name
 *
 * Asked of ubus rather than read from /proc/sys/kernel/hostname, which reports
 * "localhost" inside the procd jail: it runs in its own UTS namespace.
 *
 * @returns {string|null} Host name, or null if ubus cannot answer
 */
function hostname_get() {
	const board = ubus.call({ object: 'system', method: 'board' });

	return board?.hostname;
}

/**
 * Read the daemon configuration
 *
 * Uses the last umdns section, matching the @umdns[-1] addressing that the
 * OpenWrt umdns init script used.
 *
 * @returns {object} Configuration for main.init() and main.apply() with
 *   hostname, interfaces, ipv4, ipv6, debug and trace fields
 */
export function load() {
	const cursor = uci.cursor();
	let section;

	if (cursor)
		cursor.foreach(CONFIG_NAME, CONFIG_NAME, function(s) {
			section = s;
		});

	if (!section) {
		log.WARN(`config: No ${CONFIG_NAME} section in /etc/config/${CONFIG_NAME}\n`);
		section = {};
	}

	const interfaces = [];

	for (let network in option_list(section, 'network')) {
		const device = network_resolve(network);

		if (!device) {
			log.WARN(`config: Cannot resolve network ${network}\n`);
			continue;
		}

		if (index(interfaces, device) < 0)
			push(interfaces, device);
	}

	for (let device in option_list(section, 'device')) {
		if (index(interfaces, device) < 0)
			push(interfaces, device);
	}

	return {
		hostname: section.hostname ?? hostname_get(),
		interfaces: interfaces,
		ipv4: option_bool(section, 'ipv4', true),
		ipv6: option_bool(section, 'ipv6', true),
		debug: option_bool(section, 'debug', false),
		trace: option_bool(section, 'trace', false)
	};
};
