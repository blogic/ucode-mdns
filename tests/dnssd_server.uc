// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as main from 'main';
import * as dnssd_api from 'dnssd_ubus';

uloop.init();
const connection = ubus.connect(ARGV[0]);
if (!connection || !dnssd_api.init(connection))
	die('DNS-SD test server could not publish');
main.init({ hostname: ARGV[2] + '.local', interfaces: [ARGV[1]], ipv4: true, ipv6: true, debug: true },
	{ local_services: false, discovery: false });
uloop.signal('SIGTERM', function() {
	dnssd_api.shutdown();
	main.shutdown();
	connection.disconnect();
	uloop.end();
});
uloop.run();
