#!/usr/bin/env ucode

/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * ucode-mdns.uc - mDNS daemon entry point
 *
 * Main script that initialises the daemon and runs the event loop.
 */

import * as uloop from 'uloop';
import { init, reload, shutdown } from 'main';
import * as config from 'config';
import * as ubus from 'mdns_ubus';
import * as log from 'log';

const USAGE = 'Usage: ucode-mdns.uc [--hostname LABEL] [--interface DEVICE [--socket PATH]]\n';
const options = {};

for (let pos = 0; pos < length(ARGV); pos += 2) {
	const option = ARGV[pos];
	const value = ARGV[pos + 1];

	if (index([ '--socket', '--interface', '--hostname' ], option) < 0)
		die(USAGE);
	if (!length(value))
		die(`Missing value for ${option}\n`);

	options[substr(option, 2)] = value;
}

if (options.socket && !options.interface)
	die(USAGE);
if (options.interface && !options.hostname)
	die('--interface needs --hostname\n');
if (options.interface && (length(options.interface) > 15 || index(options.interface, '/') >= 0))
	die('Invalid interface name\n');
if (options.hostname && (length(options.hostname) > 63 ||
    !match(options.hostname, /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/)))
	die('Invalid hostname label\n');

// Syslog only: procd forwards our stderr to syslog as well, so ULOG_STDIO
// would put every line in there twice
log.ulog_open(log.ULOG_SYSLOG, log.LOG_DAEMON, "umdnsd");
log.NOTE("mDNS daemon starting\n");

// Initialise uloop
uloop.init();

// Keep the daemon alive when a callback throws; without a guard any
// exception in a timer or socket callback terminates the event loop
uloop.guard(function(e) {
	log.ERR(`Exception in callback: ${e}\n${e.stacktrace?.[0]?.context ?? ""}\n`);
});

// Initialise ubus interface (must be after uloop.init())
if (!ubus.init(options.socket))
	log.WARN("Failed to initialise ubus interface\n");

// Set up signal handlers for graceful shutdown
let shutdown_requested = false;

uloop.signal('SIGINT', function() {
	if (shutdown_requested) {
		log.NOTE("Forcing immediate shutdown\n");
		ubus.shutdown();
		shutdown();
		uloop.done();
	} else {
		log.NOTE("Graceful shutdown requested\n");
		shutdown_requested = true;
		ubus.shutdown();
		shutdown();
		uloop.end();
	}
});

uloop.signal('SIGTERM', function() {
	log.NOTE("Received SIGTERM, shutting down\n");
	ubus.shutdown();
	shutdown();
	uloop.end();
});

uloop.signal('SIGHUP', function() {
	log.NOTE("Received SIGHUP, reloading configuration\n");
	reload();
});

if (options.interface)
	init({ hostname: options.hostname, interfaces: [ options.interface ], ipv4: true, ipv6: true },
		{ local_services: false, discovery: false, fixed: true });
else
	init(config.load(), { hostname: options.hostname });

// Enter event loop
log.NOTE("mDNS daemon initialised, entering event loop\n");
uloop.run();

log.NOTE("Event loop exited\n");
