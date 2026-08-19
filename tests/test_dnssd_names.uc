// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as uloop from 'uloop';
import * as registry from 'dnssd_registry';
import * as service from 'service';
import * as services from 'services';
import * as host from 'host';
import * as main from 'main';

let checks = 0;

function check(value, message) {
	if (!value)
		die(message);
	checks++;
}

main.init({ hostname: 'router.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true },
	{ local_services: false, discovery: false });
registry.configure({ available: () => true });

function register(owner, kind, definition) {
	const result = { error: null };

	registry.registration_set(owner, 'lan', kind, definition, (error, name) => { result.error = error; });

	return result;
}

function local_names_refused() {
	check(register('one', 'host', { name: 'Router', addresses: [ 'fd00::1' ] }).error === registry.ERROR_DUPLICATED,
		'a registration cannot take the local host name');

	const local = service.register({ instance: 'Printer', service: '_ipp._tcp.local', port: 631 });

	check(register('one', 'service', { instance: 'printer', service_type: '_ipp._tcp', port: 1 }).error ===
		registry.ERROR_DUPLICATED, 'a registration cannot take a local service instance');
	service.unregister(local);
}

function primary_yields() {
	register('one', 'host', { name: 'taken', addresses: [ 'fd00::2' ] });
	uloop.advance(1100);
	main.apply({ hostname: 'taken.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true });
	check(host.hostname() == 'taken-2.local', 'a local host name that a client registered moves to a free name');
	check(!host.owns('taken.local'), 'the registered name is not claimed twice');
}

function rename_skips() {
	register('one', 'host', { name: 'taken-3', addresses: [ 'fd00::3' ] });
	uloop.advance(1100);
	check(host.rename('taken-2.local') == 'taken-4.local', 'a rename skips names that clients registered');
}

function extra_yields() {
	register('one', 'host', { name: 'extra', addresses: [ 'fd00::4' ] });
	uloop.advance(1100);

	const local = service.register({ instance: 'Explicit', service: '_ssh._tcp.local', port: 22,
		hostname: 'extra.local' });
	const replaced = host.extra_set([ 'extra.local' ]);

	check(length(replaced) == 1 && replaced[0].to == 'extra-2.local' && !host.owns('extra.local') &&
		host.owns('extra-2.local'), 'an extra host name that a client registered moves to a free name');
	services.host_changed(replaced[0].from, replaced[0].to, false);
	check(service.build_records(local)[1].rdata.target == 'extra-2.local',
		'the services of the extra host name follow the new name');
	service.unregister(local);
}

function instance_yields() {
	register('one', 'service', { instance: 'Media', service_type: '_media._tcp', port: 5 });
	uloop.advance(1100);

	const local = service.register({ instance: 'Media', service: '_media._tcp.local', port: 6 });

	check(local == 'Media (2)._media._tcp.local', 'a local instance that a client registered gets a number');
	service.unregister(local);
}

local_names_refused();
primary_yields();
rename_skips();
extra_yields();
instance_yields();
printf('DNS-SD names: %d checks passed\n', checks);
