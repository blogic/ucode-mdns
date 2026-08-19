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
if (!ubus.init())
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

init(config.load());

// Enter event loop
log.NOTE("mDNS daemon initialised, entering event loop\n");
uloop.run();

log.NOTE("Event loop exited\n");
