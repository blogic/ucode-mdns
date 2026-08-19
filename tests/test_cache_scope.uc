// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as cache from '../ucode/cache.uc';

function check(value, message) {
	if (!value)
		die(message);
}

const name = 'host.local';
const first = { name, type: 'AAAA', class: 'IN', ttl: 120, flush_cache: true,
	rdata: { address: 'fd00::1' } };
const second = { ...first, rdata: { address: 'fd00::2' } };
check(cache.insert(first, 'lan-a'), 'insert first interface');
check(cache.insert(second, 'lan-b'), 'insert second interface');
check(cache.lookup(name, 'AAAA', 'IN', 'lan-a')[0].rdata.address == 'fd00::1', 'first interface retained');
check(cache.lookup(name, 'AAAA', 'IN', 'lan-b')[0].rdata.address == 'fd00::2', 'second interface retained');
check(length(cache.lookup(name, 'AAAA')) == 2, 'legacy aggregate lookup');
check(length(cache.lookup_name('HOST.local.', 'IN', 'lan-b')) == 1, 'scoped name lookup');
cache.remove(name, 'AAAA', 'IN', 'lan-a');
check(length(cache.lookup(name, 'AAAA', 'IN', 'lan-a')) == 0, 'scoped removal');
check(length(cache.lookup(name, 'AAAA', 'IN', 'lan-b')) == 1, 'other interface survives removal');
cache.remove(name, 'AAAA');
check(length(cache.lookup(name, 'AAAA')) == 0, 'aggregate removal');
check(!cache.insert({ name: 'bad..local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.1' } }, 'lan-a') &&
	!length(cache.get_all('A')), 'a record with an invalid name is rejected');
cache.insert(first, 'lan-a');
cache.insert(second, 'lan-b');
cache.insert({ name: '_svc._tcp.local', type: 'PTR', class: 'IN', ttl: 4500, rdata: { ptr: 'One._svc._tcp.local' } }, 'lan-a');
check(cache.interface_flush('lan-a') == 2 && !length(cache.lookup_name('_svc._tcp.local', 'IN')) &&
	length(cache.lookup(name, 'AAAA')) == 1 && cache.lookup(name, 'AAAA')[0].iface == 'lan-b',
	'an interface flush drops only the records of that interface');
print('cache: interface isolation passed\n');
