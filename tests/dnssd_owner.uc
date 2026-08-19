// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import { stdout } from 'fs';

const EVENT_ARGS = { owner: '', watch: 0, interface: '', name: '', type: '', records: [], error: 0, ready: false };

function event_print(req) {
	printf('%J\n', { type: req.info.method, data: req.args });
	stdout.flush();

	return {};
}

uloop.init();
const connection = ubus.connect(ARGV[0]);
const object = connection.publish(ARGV[1], {
	records: { call: event_print, args: EVENT_ARGS },
	registration: { call: event_print, args: EVENT_ARGS },
	interface: { call: event_print, args: EVENT_ARGS }
});
if (!object)
	die('owner publication failed');
uloop.signal('SIGTERM', function() {
	object.remove();
	connection.disconnect();
	uloop.end();
});
uloop.run();
