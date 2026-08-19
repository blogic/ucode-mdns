// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as cache from '../ucode/cache.uc';
import * as utils from '../ucode/utils.uc';
import * as c from '../ucode/const.uc';

function check(value, message) {
	if (!value)
		die(message);
}

const record = { name: 'Refresh.local', type: 'AAAA', class: 'IN', ttl: 100,
	rdata: { address: 'fd00::1' } };
const canonical = utils.name_normalise(record.name);
const lan_a = (iface, name, type) => iface == 'lan-a' && name == canonical && type == 'AAAA';

cache.insert(record, 'lan-a');
cache.insert({ ...record, rdata: { address: 'fd00::2' } }, 'lan-b');
const origin = utils.now_ms();

check(!length(cache.maintenance(() => false, origin + 99000).due), 'uninterested records are not refreshed');
check(!length(cache.maintenance(() => true, origin + 79000).due), 'no refresh before eighty percent');

let scan = cache.maintenance(lan_a, origin + 1000);
check(scan.next == c.CACHE_MAINTENANCE_INTERVAL_MS, 'a far deadline waits the maximum interval');
scan = cache.maintenance(lan_a, origin + 79500);
check(scan.next >= c.CACHE_MAINTENANCE_MIN_MS && scan.next <= 3000, 'the scan wakes up near the next deadline');

for (let deadline in [82100, 87100, 92100, 97100]) {
	const due = cache.maintenance(lan_a, origin + deadline).due;
	check(length(due) == 1 && due[0].record.iface == 'lan-a', 'one query at each interested TTL threshold');
	check(!length(cache.maintenance(lan_a, origin + deadline).due), 'no duplicate threshold query');
}

check(length(cache.maintenance((iface) => iface == 'lan-b', origin + 82100).due) == 1,
	'other interface has independent refresh deadlines');

scan = cache.maintenance(() => true, origin + 100001);
check(!length(scan.due) && scan.next == c.CACHE_MAINTENANCE_INTERVAL_MS,
	'expired data neither refreshes nor keeps the scan busy');

cache.insert({ ...record, name: 'short.local', ttl: 5 }, 'lan-a');
check(!length(cache.maintenance(() => true, origin + 4500).due), 'very short TTLs are not refreshed');
print('cache refresh: passed\n');
