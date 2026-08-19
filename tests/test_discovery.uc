// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as discovery from 'discovery';
import * as tracker from 'tracker';
import * as cache from 'cache';
import * as utils from 'utils';
import * as c from 'const';

function check(value, message) {
	if (!value)
		die(message);
}

function queries_since(start, iface) {
	return filter(slice(mdns.sent, start), item => item.iface == iface && !item.packet.header.flags.response);
}

const wants = (link, name, kind) => tracker.has_interest(link, utils.name_normalise(name), kind);

let start = length(mdns.sent);
cache.insert({ name: 'Box._http._tcp.local', type: 'SRV', class: 'IN', ttl: 120,
	rdata: { target: 'box.local', port: 80, priority: 0, weight: 0 } }, 'dl');
discovery.service_add('Box._http._tcp.local', '_http._tcp.local', 120, 'dl');
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
let sent = queries_since(start, 'dl');
check(length(sent) == 1 && length(sent[0].packet.questions) == 4,
	'the resolution queries of a new service share one packet');
uloop.advance(119000);
discovery.cleanup_expired();
check(discovery.get_all()['_http._tcp.local'], 'a service lives for its TTL on the monotonic clock');
uloop.advance(1000);
discovery.cleanup_expired();
check(!discovery.get_all()['_http._tcp.local'] && !wants('dl', 'Box._http._tcp.local', 'SRV'),
	'a service expires after its TTL on the monotonic clock');

discovery.service_add('Keep._ipp._tcp.local', '_ipp._tcp.local', 120, 'budget');
for (let i = 0; i < c.MAX_REFRESH_QUERIES_PER_SEC * 2; i++)
	discovery.refresh_all('budget');
discovery.service_add('Fresh._ipp._tcp.local', '_ipp._tcp.local', 120, 'budget');
check(wants('budget', 'Fresh._ipp._tcp.local', 'SRV'), 'a refresh that starts nothing costs no budget');

let filler = 0;
while (filler < c.MAX_REFRESH_QUERIES_PER_SEC * 2 &&
       !discovery.service_add(`Filler${filler}._fill._tcp.local`, '_fill._tcp.local', 120, 'fill').resolution_pending)
	filler++;
discovery.handle_ptr_record(c.SERVICE_ENUM_NAME, '_late._tcp.local', 120, 'fill');
check(!wants('fill', '_late._tcp.local', 'PTR'), 'a browse the budget refuses waits');
uloop.advance(1000);
discovery.retry_pending();
check(wants('fill', '_late._tcp.local', 'PTR'), 'a refused browse is retried');

const enumeration = { name: c.SERVICE_ENUM_NAME, type: 'PTR', class: 'IN', ttl: 4500,
	rdata: { ptr: '_gone._tcp.local' } };
cache.insert(enumeration, 'down');
cache.insert(enumeration, 'up');
discovery.interface_remove('down');
check(!length(cache.lookup(c.SERVICE_ENUM_NAME, 'PTR', 'IN', 'down')) &&
	length(cache.lookup(c.SERVICE_ENUM_NAME, 'PTR', 'IN', 'up')) == 1,
	'removing an interface drops the records cached on it');
start = length(mdns.sent);
tracker.query_send('down', { name: c.SERVICE_ENUM_NAME, type: 'PTR', class: 'IN' });
uloop.advance(0);
sent = queries_since(start, 'down');
check(length(sent) == 1 && !length(sent[0].packet.answers),
	'the enumeration query after a link returns carries no stale known answers');

print('discovery: passed\n');
