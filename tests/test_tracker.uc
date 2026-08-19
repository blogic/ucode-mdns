// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as tracker from 'tracker';
import * as cache from 'cache';
import * as packet from 'packet';
import * as c from 'const';

function check(value, message) {
	if (!value)
		die(message);
}

function queries_since(start, iface) {
	return filter(slice(mdns.sent, start), item => item.iface == iface && !item.packet.header.flags.response);
}

const question = (name, kind) => ({ name, type: kind ?? 'A', class: 'IN' });

let start = length(mdns.sent);
cache.insert({ name: 'one.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.10' } }, 'agg');
for (let name in [ 'one.local', 'two.local', 'three.local' ])
	tracker.start_continuous('agg', question(name));
uloop.advance(c.RESPONSE_DELAY_MIN_MS - 1);
check(!length(queries_since(start, 'agg')), 'no query goes out before the initial delay');
uloop.advance(c.RESPONSE_DELAY_MAX_MS - c.RESPONSE_DELAY_MIN_MS + 1);
let sent = queries_since(start, 'agg');
check(length(sent) == 1 && length(sent[0].packet.questions) == 3,
	'continuous queries started together share one query packet');
check(length(sent[0].packet.answers) == 1 && sent[0].packet.answers[0].name == 'one.local',
	'the shared query carries the known answers of its questions');
uloop.advance(2019 - 120);
check(length(queries_since(start, 'agg')) == 1, 'the second query waits two seconds');
uloop.advance(101);
sent = queries_since(start, 'agg');
check(length(sent) == 2 && length(sent[1].packet.questions) == 3, 'the questions stay together after a send');
uloop.advance(6019 - 2120);
check(length(queries_since(start, 'agg')) == 2, 'the interval doubles');
uloop.advance(101);
check(length(queries_since(start, 'agg')) == 3, 'the third query follows four seconds later');
uloop.advance(4094000 - 6120);
check(length(queries_since(start, 'agg')) == 11, 'the backoff keeps doubling up to 2048 seconds');
uloop.advance(120);
check(length(queries_since(start, 'agg')) == 12, 'the twelfth query follows 2048 seconds later');
uloop.advance(3600000 - 101);
check(length(queries_since(start, 'agg')) == 12, 'the interval is capped at one hour');
uloop.advance(101);
check(length(queries_since(start, 'agg')) == 13, 'the capped query follows one hour later');
for (let name in [ 'one.local', 'two.local', 'three.local' ])
	tracker.stop_continuous('agg', name, 'A');

start = length(mdns.sent);
tracker.query_send('once', question('x.local'));
tracker.query_send('once', question('y.local', 'AAAA'));
tracker.query_send('once', question('X.local'));
uloop.advance(0);
sent = queries_since(start, 'once');
check(length(sent) == 1 && length(sent[0].packet.questions) == 2,
	'queries sent once in one tick share a packet without duplicate questions');

tracker.start_continuous('rs', question('a.local'));
tracker.start_continuous('rs', question('b.local', 'TXT'));
uloop.advance(600000);
start = length(mdns.sent);
tracker.restart('rs');
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
sent = queries_since(start, 'rs');
check(length(sent) == 1 && length(sent[0].packet.questions) == 2, 'a restart sends the queries of a link in one packet');
tracker.stop_continuous('rs', 'a.local', 'A');
tracker.stop_continuous('rs', 'b.local', 'TXT');

start = length(mdns.sent);
check(tracker.start_continuous('sc', question('shared.local'), 'first') === true, 'the first scope starts a query');
check(tracker.start_continuous('sc', question('Shared.local'), 'second') === false, 'a second scope joins the query');
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
sent = queries_since(start, 'sc');
check(length(sent) == 1 && length(sent[0].packet.questions) == 1, 'two scopes share one question stream');
tracker.stop_continuous('sc', 'shared.local', 'A', 'first');
check(tracker.has_interest('sc', 'shared.local', 'A'), 'the query runs on while one scope wants it');
tracker.stop_continuous('sc', 'shared.local', 'A', 'second');
check(!tracker.has_interest('sc', 'shared.local', 'A'), 'the last scope stops the query');
uloop.advance(10000);
check(length(queries_since(start, 'sc')) == 1, 'a stopped query sends nothing more');

const stale = { name: 'stale.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.20' } };
cache.insert(stale, 'dup');
uloop.advance(70000);
start = length(mdns.sent);
tracker.start_continuous('dup', question('stale.local'));
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
check(!length(queries_since(start, 'dup')[0].packet.answers), 'an answer below half its TTL is no known answer');
uloop.advance(1000);
tracker.duplicate_observe('dup', question('stale.local'), [ { ...stale, ttl: 50 } ]);
uloop.advance(1000);
check(length(queries_since(start, 'dup')) == 2,
	'a duplicate question listing an answer we would not send does not count as ours');
tracker.stop_continuous('dup', 'stale.local', 'A');

start = length(mdns.sent);
mdns.transport.fail.fail = false;
tracker.start_continuous('fail', question('retry.local'));
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
check(!length(queries_since(start, 'fail')), 'a refused query is not on the link');
delete mdns.transport.fail.fail;
uloop.advance(1000);
check(length(queries_since(start, 'fail')) == 1, 'a refused query is retried after the same interval');
tracker.stop_continuous('fail', 'retry.local', 'A');

start = length(mdns.sent);
mdns.transport.fail.never = null;
tracker.start_continuous('never', question('never.local'));
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
delete mdns.transport.fail.never;
uloop.advance(1000);
check(!length(queries_since(start, 'never')), 'a query that cannot be sent keeps its backoff');
uloop.advance(1000);
check(length(queries_since(start, 'never')) == 1, 'the next attempt follows the doubled interval');
tracker.stop_continuous('never', 'never.local', 'A');

const qu = { name: 'qu.local', type: 'A', class: 'IN', unicast_response: true };
mdns.transport.fail.qu = false;
check(packet.send_query('qu', [ qu ], false, []) === false, 'a query the socket refuses for now returns false');
mdns.transport.fail.qu = null;
check(packet.send_query('qu', [ qu ], false, []) === null, 'a query that can never be sent returns null');
check(!packet.qu_pending('qu', 'qu.local', 'A'), 'a refused QU question opens no unicast window');
delete mdns.transport.fail.qu;
check(packet.send_query('qu', [ qu ], false, []) === true && packet.qu_pending('qu', 'qu.local', 'A'),
	'a sent QU question opens the unicast window');
uloop.advance(c.QU_RESPONSE_WINDOW_SEC * 1000 + 1);
check(!packet.qu_pending('qu', 'qu.local', 'A') && packet.qu_expire() == 1,
	'the unicast window closes on the monotonic clock');

start = length(mdns.sent);
for (let i = 0; i < 60; i++)
	tracker.start_continuous('big', question(`host-${i}-with-a-rather-long-label-to-fill-packets.local`));
uloop.advance(c.RESPONSE_DELAY_MAX_MS);
sent = queries_since(start, 'big');
let asked = 0;
for (let item in sent) {
	asked += length(item.packet.questions);
	check(packet.size_estimate(item.packet.questions, item.packet.answers) <= c.MAX_PACKET_SIZE,
		'an aggregated query stays within the packet size limit');
}
check(length(sent) > 1 && asked == 60, 'questions that do not fit one packet are split across several');

print('tracker: passed\n');
