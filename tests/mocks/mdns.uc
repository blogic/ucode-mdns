// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as native from 'native_mdns';

export const sent = [];
export const callbacks = {};
export const state = { first_binder: true };
export const transport = { fail: {}, results: {}, attempts: {} };
export const interfaces = [
	{ name: 'lan', ipv4_addresses: [ '192.0.2.1', '192.0.2.2' ], ipv6_addresses: [ 'fe80::1' ] }
];

export function packet_send(iface, packet, dest, immediate) {
	const queue = transport.results[iface] ?? [];
	let result = iface in transport.fail ? transport.fail[iface] : true;

	transport.attempts[iface] = (transport.attempts[iface] ?? 0) + 1;

	if (length(queue))
		result = shift(queue);

	if (result !== true)
		return result;

	push(sent, { iface, packet, dest, immediate });
	return true;
};

export function transport_fail(iface, count, result) {
	transport.results[iface] = [];

	for (let i = 1; i < count; i++)
		push(transport.results[iface], true);

	push(transport.results[iface], result);
};

export function flush() {
	return true;
};

export function interface_list() {
	return interfaces;
};

export function rdata_encode(record) {
	return native.rdata_encode(record);
};

export function first_binder() {
	return state.first_binder;
};

export function rdata_canonical(record) {
	return native.rdata_canonical(record);
};

export function name_canonical(name) {
	return native.name_canonical(name);
};

export function name_prepare(name) {
	return native.name_prepare(name);
};

export function packet_build(packet) {
	return native.packet_build(packet);
};

export function packet_parse(packet) {
	return native.packet_parse(packet);
};

export function error() {
	return native.error();
};

export function debug() {};

export function info() {};

export function set_callback(event, callback) {
	callbacks[event] = callback;
	return true;
};

export function set_hostname(name) {};

export function set_debug(value) {};

export function set_trace(value) {};

export function interface_destroy(name) {
	for (let i = length(interfaces) - 1; i >= 0; i--) {
		if (interfaces[i].name == name)
			splice(interfaces, i, 1);
	}

	return true;
};

export function interface_create(options) {
	push(interfaces, { ...options, enabled: true,
		ipv4_addresses: options.ipv4 ? [ '192.0.2.1' ] : [],
		ipv6_addresses: options.ipv6 ? [ 'fe80::1' ] : [] });
	return true;
};
