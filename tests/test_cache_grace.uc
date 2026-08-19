// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as cache from '../ucode/cache.uc';
import * as nsec from '../ucode/nsec.uc';
import * as utils from '../ucode/utils.uc';
import * as c from '../ucode/const.uc';
import * as uloop from 'uloop';

function check(value, message) {
	if (!value)
		die(message);
}

const first = { name: 'grace.local', type: 'A', class: 'IN', ttl: 120,
	flush_cache: true, rdata: { address: '192.0.2.1' } };
const second = { ...first, rdata: { address: '192.0.2.2' } };
uloop.init();
cache.insert(first, 'lan');

const poof = { name: 'poof.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.40' } };
const any = { name: 'poof.local', type: 'ANY', class: 'IN' };
cache.insert(poof, 'lan');
cache.insert(nsec.build('poof.local', [ 'A' ]), 'lan');
const first_query = utils.now_ms();
cache.doubt_observe('lan', [ any, { name: 'poof.local', type: 'A', class: 'IN' } ], []);
check(cache.doubt_expire(first_query + 60000) == 0, 'one query packet with two questions counts once');
uloop.timer(300, function() {
	cache.doubt_observe('lan', [ any ], []);
	const second_query = utils.now_ms();
	check(cache.doubt_expire(first_query + c.DOUBT_WINDOW_MS + 100) == 0,
		'the ten second POOF window starts at the second query');
	check(cache.doubt_expire(second_query + c.DOUBT_WINDOW_MS) == 1 &&
		!length(cache.lookup('poof.local', 'A', 'IN', 'lan')), 'an unanswered address is flushed');
	check(length(cache.lookup('poof.local', 'NSEC', 'IN', 'lan')) == 1, 'an ANY question raises no doubt about NSEC');
});
uloop.timer(1100, function() {
	cache.insert(second, 'lan');
	check(length(cache.lookup(first.name, 'A', 'IN', 'lan')) == 2,
		'old address remains usable during the flush grace period');
	check(length(cache.lookup_name(first.name, 'IN', 'lan')) == 2, 'name lookup grace');
	check(length(cache.get_all('A')) == 2, 'aggregate lookup grace');
	uloop.timer(1100, function() {
		check(length(cache.lookup(first.name, 'A', 'IN', 'lan')) == 1,
			'old address expires after grace without requiring a periodic sweep');
		cache.insert(second, 'lan');
		check(length(cache.lookup(first.name, 'A', 'IN', 'lan')) == 1,
			'a later cache-flush packet does not make a flushed record visible again');
		cache.insert(first, 'lan');
		cache.insert(second, 'lan');
		check(length(cache.lookup(first.name, 'A', 'IN', 'lan')) == 2,
			'received RRSet members rescue each other in a burst');
		const goodbye = { name: 'bye.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.9' } };
		cache.insert(goodbye, 'lan');
		cache.insert({ ...goodbye, ttl: 0 }, 'lan');
		uloop.timer(800, function() {
			check(length(cache.lookup(goodbye.name, 'A', 'IN', 'lan')) == 1,
				'a goodbye keeps the record for one second');
			uloop.timer(300, function() {
				check(!length(cache.lookup(goodbye.name, 'A', 'IN', 'lan')),
					'a goodbye removes the record after one second');
				print('cache grace: passed\n');
				uloop.end();
			});
		});
	});
});
uloop.run();
