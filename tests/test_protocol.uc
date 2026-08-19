// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';
import * as uloop from 'uloop';
import * as query from 'query';
import * as service from 'service';
import * as response from 'response';
import * as tracker from 'tracker';
import * as cache from 'cache';
import * as packet from 'packet';
import * as host from 'host';
import * as announce from 'announce';
import * as discovery from 'discovery';
import * as legacy from 'mdns_ubus';
import * as services from 'services';
import * as main from 'main';
import * as utils from 'utils';
import * as nsec from 'nsec';

function check(value, message) {
	if (!value)
		die(message);
}

const asks = (item, question_name, kind) => length(filter(item.packet.questions ?? [],
	question => question.name == question_name && (kind == null || question.type == kind))) > 0;
const iface = { name: 'lan', index: 1 };
const from = { address: '192.0.2.100', port: 5353, family: 'inet', local: true };
function ask(name, type, extra) {
	query.handle({ header: { flags: {} }, questions: [{ name, type, class: 'IN', ...(extra ?? {}) }],
		answers: [], authority: [] }, from, iface, true, false);
	uloop.advance(150);
}
service.set_hostname('router.local');
const name = service.register({ instance: 'Ready', service: '_http._tcp.local', port: 80 });
ask(name, 'SRV');
check(!length(mdns.sent), 'unprobed service must not answer');
announce.start_probe(name, 'lan', { records: service.build_records, state: service.set_state });
ask(name, 'SRV');
check(!length(filter(mdns.sent, item => item.packet.header.flags.response)), 'probing service must not answer');
uloop.advance(1000);
ask(name, 'SRV', { unicast_response: true });
check(mdns.sent[-1].packet.answers[0].type == 'SRV' && mdns.sent[-1].dest != null,
	'published service must answer during announcement repetitions');
check(length(service.types()) == 1, 'published type is enumerable');
announce.cancel(name);
const addresses = map(['192.0.2.1', '192.0.2.2'], address => ({
	name: 'defence.local', type: 'A', class: 'IN', ttl: 120, flush_cache: true, rdata: { address }
}));
check(length(response.suppress_known_answers(addresses, [addresses[0]])) == 2,
	'partial known-answer suppression must retain a complete unique RRSet');
check(!length(response.suppress_known_answers(addresses, addresses)),
	'a completely known unique RRSet may be suppressed');
const shared = map(addresses, record => ({ ...record, flush_cache: false }));
check(length(response.suppress_known_answers(shared, [shared[0]])) == 1,
	'shared records remain independently suppressible');
let before_tc = length(mdns.sent);
response.schedule('tc-link', addresses, [], null, false, true, false, null, from.address);
response.schedule('tc-link', addresses, [], null, true, true, false, null, from.address);
uloop.advance(150);
check(length(mdns.sent) == before_tc, 'TC query postpones an existing fast response');
uloop.advance(150);
response.suppress_pending('tc-link', [], true, from.address);
uloop.advance(250);
check(length(mdns.sent) == before_tc, 'TC continuation restarts the waiting interval');
uloop.advance(300);
check(length(mdns.sent) == before_tc + 1, 'response follows the final continuation wait');
const peer = { address: '192.0.2.101', port: 5353, family: 'inet', local: true };
const tc_records = map(addresses, record => ({ ...record, name: 'tc.local' }));
before_tc = length(mdns.sent);
response.schedule('tc-link', tc_records, [], null, true, true, false, null, from.address);
response.schedule('tc-link', tc_records, [], peer, true, true, false, null, peer.address);
response.suppress_pending('tc-link', tc_records, true, from.address);
uloop.advance(600);
check(length(mdns.sent) == before_tc + 1 && mdns.sent[-1].dest?.address == peer.address,
	'a continuation suppresses only the responses its own sender waits for');
before_tc = length(mdns.sent);
response.schedule('tc-link', tc_records, [], null, true, true, false, null, from.address);
response.schedule('tc-link', tc_records, [], from, true, true, false, null, from.address);
response.suppress_pending('tc-link', [], true, from.address);
uloop.advance(600);
check(length(mdns.sent) == before_tc + 2, 'every postponed response keeps its own timer');
const dup_shared = { name: '_dup._tcp.local', type: 'PTR', class: 'IN', ttl: 4500, flush_cache: false,
	rdata: { ptr: 'One._dup._tcp.local' } };
before_tc = length(mdns.sent);
response.schedule('dup-link', [ dup_shared ], [], null, false, false, false, null, from.address);
response.duplicate_observe('dup-link', [ { ...dup_shared, ttl: 4500 } ]);
uloop.advance(150);
check(length(mdns.sent) == before_tc, 'an answer another host just multicast is not sent again');
response.schedule('dup-link', [ dup_shared ], [], null, false, false, false, null, from.address);
response.duplicate_observe('dup-link', [ { ...dup_shared, ttl: 100 } ]);
uloop.advance(150);
check(length(mdns.sent) == before_tc + 1, 'a copy with a lower TTL does not suppress our answer');
const dup_unique = map([ '192.0.2.31', '192.0.2.32' ], address => ({ name: 'dupu.local', type: 'A', class: 'IN',
	ttl: 120, flush_cache: true, rdata: { address } }));
before_tc = length(mdns.sent);
response.schedule('dup-link', dup_unique, [], null, false, true, false, null, from.address);
response.duplicate_observe('dup-link', [ dup_unique[0] ]);
uloop.advance(150);
check(length(mdns.sent) == before_tc + 1 && length(mdns.sent[-1].packet.answers) == 2,
	'a partly seen unique RRSet still goes out whole');
response.schedule('lan', addresses, [], null, false, true, true, null);
check(length(mdns.sent[-1].packet.answers) == 2, 'probe defence must send the full address RRSet');
let defended = length(mdns.sent);
response.schedule('lan', addresses, [], null, false, true, true, null);
check(length(mdns.sent) == defended, 'repeat defence is rate limited as one RRSet');
uloop.advance(300);
check(length(mdns.sent) == defended + 1 && length(mdns.sent[-1].packet.answers) == 2,
	'a rate limited defence goes out once 250 ms have passed');
const prober_a = { address: '192.0.2.201', port: 5353, family: 'inet', local: true };
const prober_b = { address: '192.0.2.202', port: 5353, family: 'inet', local: true };
const unicast_record = [ { ...addresses[0], name: 'unicast-defence.local' } ];
response.schedule('lan', unicast_record, [], prober_a, false, true, true, null);
response.schedule('lan', unicast_record, [], prober_b, false, true, true, null);
check(mdns.sent[-2].dest?.address == prober_a.address && mdns.sent[-1].dest?.address == prober_b.address,
	'a unicast probe defence to one host does not hold back the defence to another');
defended = length(mdns.sent);
response.schedule('lan', addresses, [], null, false, true, false, null);
uloop.advance(150);
check(length(mdns.sent) == defended, 'normal reply respects a recent multicast probe defence');
const extra = { ...addresses[0], name: 'limited-extra.local' };
response.schedule('extra-link', [{ ...addresses[0], name: 'first.local' }], [extra], null, false, true, false, null);
uloop.advance(150);
check(length(mdns.sent[-1].packet.additional) == 1, 'first additional RRSet is sent');
response.schedule('extra-link', [{ ...addresses[0], name: 'second.local' }], [extra], null, false, true, false, null);
uloop.advance(150);
check(!length(mdns.sent[-1].packet.additional), 'recent additional RRSet is independently rate limited');
const delayed = { ...addresses[0], name: 'delayed.local' };
const delayed_count = () => length(filter(mdns.sent, item => item.packet.header.flags.response &&
	item.packet.answers?.[0]?.name == delayed.name));
announce.start_probe(delayed.name, 'lan', { records: () => [delayed] });
uloop.advance(1250);
const announced_once = delayed_count();
response.multicast_stamp('lan', [delayed]);
uloop.advance(2000);
check(announced_once == 1 && delayed_count() == 2,
	'an announcement held back by the rate limit goes out as soon as the limit allows');
announce.cancel(delayed.name);
let previous = length(mdns.sent);
check(!response.correct_low_ttl('repair-link', addresses, { ...addresses[0], ttl: 60 }),
	'half-life copies do not require correction');
check(response.correct_low_ttl('repair-link', addresses, { ...addresses[0], ttl: 0 }),
	'matching goodbye must be rescued by the active owner');
uloop.advance(150);
check(length(mdns.sent) == previous + 1 && length(mdns.sent[-1].packet.answers) == 2 &&
	mdns.sent[-1].packet.answers[0].ttl == 120, 'rescue advertises the complete authoritative RRSet');
previous = length(mdns.sent);
check(response.correct_low_ttl('repair-link', addresses, { ...addresses[0], ttl: 0 }),
	'a goodbye right after our multicast still needs a rescue');
uloop.advance(150);
check(length(mdns.sent) == previous, 'the rescue waits for the multicast rate limit');
uloop.advance(1000);
check(length(mdns.sent) == previous + 1, 'the rescue goes out once the rate limit allows');
const cached = { ...addresses[0], name: 'known.local' };
cache.insert(cached, 'lan');
tracker.start_continuous('lan', { name: cached.name, type: 'A', class: 'IN' });
uloop.advance(150);
const known = mdns.packet_parse(mdns.packet_build(mdns.sent[-1].packet));
check(length(known.answers) == 1 && !known.answers[0].flush_cache,
	'known answers must clear cache-flush on the wire');
cache.remove(cached.name, 'A', 'IN', 'lan');
uloop.advance(2000);
check(!length(mdns.sent[-1].packet.answers), 'retries must not advertise removed cache records');
check(tracker.has_interest('lan', mdns.name_canonical(cached.name), 'A') &&
	!tracker.has_interest('other', mdns.name_canonical(cached.name), 'A'),
	'a continuous query registers interest on its interface');
tracker.stop_continuous('lan', cached.name, 'A');
check(!tracker.has_interest('lan', mdns.name_canonical(cached.name), 'A'), 'stopping a query drops its interest');
const dup_question = { name: 'dup.local', type: 'A', class: 'IN' };
const dup_sends = () => length(filter(mdns.sent, item => item.packet.questions?.[0]?.name == 'dup.local'));
tracker.start_continuous('lan', dup_question);
uloop.advance(150);
let dup_before = dup_sends();
uloop.advance(1000);
tracker.duplicate_observe('lan', dup_question, []);
uloop.advance(1500);
check(dup_sends() == dup_before, 'a duplicate question from another host counts as our query');
uloop.advance(3000);
check(dup_sends() == dup_before + 1, 'the next query follows the advanced backoff');
dup_before = dup_sends();
tracker.duplicate_observe('lan', dup_question, [ { name: 'dup.local', type: 'A', class: 'IN', ttl: 120,
	rdata: { address: '198.51.100.77' } } ]);
uloop.advance(8100);
check(dup_sends() == dup_before + 1, 'a duplicate with known answers we lack does not count');
const poof = { name: 'poof.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.41' } };
const poof_question = { name: 'poof.local', type: 'A', class: 'IN', unicast_response: false };
cache.insert(poof, 'lan');
cache.doubt_observe('lan', [ poof_question ], []);
cache.doubt_observe('lan', [ poof_question ], [ poof ]);
uloop.advance(11000);
check(cache.doubt_expire() == 0, 'a query listing the record as known answer raises no doubt');
cache.doubt_observe('lan', [ poof_question ], []);
cache.doubt_observe('lan', [ poof_question ], []);
cache.insert(poof, 'lan');
uloop.advance(11000);
check(cache.doubt_expire() == 0 && length(cache.lookup('poof.local', 'A', 'IN', 'lan')) == 1,
	'an answer within ten seconds clears the doubt');
cache.doubt_observe('lan', [ poof_question ], []);
cache.doubt_observe('lan', [ poof_question ], []);
uloop.advance(5000);
check(cache.doubt_expire() == 0, 'a doubted record waits ten seconds for an answer');
uloop.advance(6000);
check(cache.doubt_expire() == 1 && !length(cache.lookup('poof.local', 'A', 'IN', 'lan')),
	'two unanswered queries flush the record after ten seconds');
cache.insert(nsec.build('neg.local', [ 'A' ]), 'lan');
const neg_sends = (kind) => length(filter(mdns.sent, item => item.packet.questions?.[0]?.name == 'neg.local' &&
	item.packet.questions[0].type == kind));
tracker.start_continuous('lan', { name: 'neg.local', type: 'AAAA', class: 'IN' });
tracker.start_continuous('lan', { name: 'neg.local', type: 'A', class: 'IN' });
uloop.advance(3000);
check(!neg_sends('AAAA') && neg_sends('A') > 0, 'a cached NSEC stops queries for the types it denies');
tracker.stop_continuous('lan', 'neg.local', 'AAAA');
tracker.stop_continuous('lan', 'neg.local', 'A');
const stale = { name: 'stale.local', type: 'A', class: 'IN', ttl: 120, rdata: { address: '192.0.2.42' } };
cache.insert(stale, 'lan');
const stale_queries = () => filter(mdns.sent, item => asks(item, 'stale.local'));
check(legacy.reconfirm_handle({ question: 'stale.local', type: 1, interface: 'lan' }).records == 1,
	'reconfirm marks the cached record');
uloop.advance(0);
check(length(stale_queries()) == 1 && !length(stale_queries()[0].packet.answers),
	'a reconfirm query leaves the doubted record out of its known answers');
uloop.advance(1100);
check(length(stale_queries()) == 2, 'reconfirm sends a second query');
uloop.advance(9000);
check(cache.doubt_expire() == 1, 'an unconfirmed record is flushed ten seconds after reconfirm');
tracker.stop_continuous('lan', 'dup.local', 'A');
packet.send_query('lan', [], false, [
	{ ...cached, expires_at: utils.now_ms() + 60000 },
	{ ...cached, expires_at: utils.now_ms() + 59000 },
	{ ...cached, expires_at: utils.now_ms() - 1000 }
]);
check(length(mdns.sent[-1].packet.answers) == 1 && mdns.sent[-1].packet.answers[0].ttl == 60,
	'known answers use remaining TTL and omit answers below half-life');
host.set_hostname('gated.local');
previous = length(mdns.sent);
ask('gated.local', 'A');
ask('gated.local', 'TXT');
check(length(mdns.sent) == previous, 'unprobed host must send neither addresses nor NSEC');
announce.start_probe('gated.local', 'lan', { records: host.build_records });
ask('gated.local', 'AAAA');
check(!length(filter(slice(mdns.sent, previous), item => item.packet.header.flags.response)),
	'host must not answer during probing');
uloop.advance(1000);
check(announce.is_announced('gated.local', 'lan'), 'host completes probing on its interface');
check(!announce.is_announced('gated.local', 'other'), 'host ownership does not cover an unclaimed interface');
previous = length(mdns.sent);
ask('gated.local', 'A', { unicast_response: true });
check(length(mdns.sent) == previous + 1 && mdns.sent[-1].packet.answers[0].type == 'A',
	'host answers after probing');
query.handle({ header: { flags: {} }, questions: [{ name: 'gated.local', type: 'A', class: 'IN' }],
	answers: [], authority: [] }, from, iface, false, false);
uloop.advance(150);
check(mdns.sent[-1].dest?.address == from.address, 'direct unicast QM query follows QU response rules');
check(!response.multicast_recent('unknown-link', addresses[0]), 'unseen records require multicast fallback');
previous = length(mdns.sent);
ask('gated.local', 'A', { class: 'UNKNOWN' });
check(length(mdns.sent) == previous, 'unsupported question class is ignored');
const questions = map(['A', 'AAAA'], type => ({ name: 'gated.local', type, class: 'IN' }));
query.handle({ header: { id: 42, flags: {} }, questions, answers: [], authority: [] },
	{ ...from, port: 12345 }, iface, true, true);
check(length(mdns.sent) == previous + 1 && length(mdns.sent[-1].packet.questions) == 2 &&
	mdns.sent[-1].packet.header.id == 42 && length(mdns.sent[-1].packet.answers) == 3,
	'legacy multiquestion query gets one coherent reply with all questions and answers');
check(mdns.sent[-1].packet.answers[0].ttl == 10 && !mdns.sent[-1].packet.answers[0].flush_cache,
	'legacy reply retains TTL and cache-flush adaptation');
const many = [];
for (let i = 0; i < 32; i++) push(many, { name: `absent${i}.local`, type: 'A', class: 'IN' });
push(many, { name: 'gated.local', type: 'TXT', class: 'ANY', unicast_response: true });
previous = length(mdns.sent);
query.handle({ header: { flags: {} }, questions: many, answers: [], authority: [] }, from, iface, true, false);
uloop.advance(1500);
check(length(filter(slice(mdns.sent, previous), item => item.iface == 'lan' &&
	length(filter(item.packet.answers, record => record.name == 'gated.local' && record.type == 'NSEC')))),
	'legitimate questions beyond the former 32-question cutoff are processed');
previous = length(mdns.sent);
query.handle({ header: { flags: {} }, questions: [{ name: 'gated.local', type: 'A', class: 'IN',
	unicast_response: true }], answers: [], authority: [] }, from, iface, true, false);
uloop.advance(1500);
const a_reply = filter(slice(mdns.sent, previous), item => item.dest?.address == from.address)[-1];
check(a_reply && length(filter(a_reply.packet.additional, record => record.type == 'AAAA')) == 1,
	'A answer includes complementary IPv6 addresses');
const remote = { address: '203.0.113.7', port: 5353, family: 'inet', local: false };
previous = length(mdns.sent);
query.handle({ header: { flags: {} }, questions: [{ name: 'gated.local', type: 'A', class: 'IN',
	unicast_response: true }], answers: [], authority: [] }, remote, iface, true, false);
uloop.advance(1500);
check(!length(filter(slice(mdns.sent, previous), item => item.dest?.address == remote.address)),
	'a QU question from an off-link source gets no unicast reply');
push(mdns.interfaces, { name: 'other', ipv4_addresses: ['198.51.100.1'], ipv6_addresses: [] });
previous = length(mdns.sent);
announce.start_probe('gated.local', 'other', { records: host.build_records });
check(length(mdns.sent) == previous, 'new interface does not get an immediate announcement');
check(announce.is_announced('gated.local', 'lan'), 'existing link keeps answering while a new link probes');
check(!announce.is_announced('gated.local', 'other'), 'new interface must verify ownership');
uloop.advance(1000);
const new_link = filter(slice(mdns.sent, previous), item => item.iface == 'other');
check(length(filter(new_link, item => !item.packet.header.flags.response)) == 3,
	'new interface sends all three probes before publication');
check(new_link[-1].packet.header.flags.response && announce.is_announced('gated.local', 'other'),
	'new interface announces only after probing');
query.handle({ header: { flags: {} }, questions: [{ name: 'gated.local', type: 'A', class: 'IN',
	unicast_response: true }], answers: [], authority: [] }, from, { name: 'other', index: 2 }, true, false);
uloop.advance(150);
const hinted = filter(mdns.sent, item => item.iface == 'other' && item.dest?.address == from.address)[-1];
check(length(hinted.packet.additional) == 1 && hinted.packet.additional[0].type == 'NSEC',
	'IPv4-only host includes an authoritative absence hint for IPv6');
check(new_link[0].immediate, 'probes require actual transmission instead of queue acceptance');
announce.iface_remove('gated.local', 'other');
mdns.transport.fail.other = false;
announce.start_probe('gated.local', 'other', { records: host.build_records });
uloop.advance(1000);
check(!announce.is_announced('gated.local', 'other'), 'failed interface cannot inherit success from another');
delete mdns.transport.fail.other;
uloop.advance(6000);
check(announce.is_announced('gated.local', 'other'), 'failed interface retries a complete probe sequence');
check(announce.is_announced('gated.local', 'lan'), 'a failing link does not hold back the others');
announce.handle_conflict('gated.local', { name: 'gated.local', type: 'A', class: 'IN', ttl: 120,
	rdata: { address: '198.51.100.9' } }, 'other');
check(!announce.is_announced('gated.local', 'other') && announce.is_announced('gated.local', 'lan'),
	'a conflict resets only the link it was seen on');
uloop.advance(1000);
check(announce.is_announced('gated.local', 'other'), 'the reset link probes again on its own');
push(mdns.interfaces, { name: 'empty', ipv4_addresses: [], ipv6_addresses: [] });
announce.start_probe('gated.local', 'empty', { records: host.build_records });
uloop.advance(1000);
check(!announce.is_announced('gated.local', 'empty') && announce.is_announced('gated.local', 'other'),
	'a link without addresses does not block the name on other links');
announce.iface_remove('gated.local', 'empty');
query.handle({ header: { flags: {} }, questions: [{ name: 'gated.local', type: 'A', class: 'IN',
	unicast_response: true }], answers: [], authority: [] }, from, iface, true, false);
previous = length(mdns.sent);
announce.cancel('gated.local');
uloop.advance(150);
check(length(mdns.sent) == previous, 'withdrawal cancels a delayed answer built before the claim ended');
ask('gated.local', 'A');
check(length(mdns.sent) == previous, 'cancelled host claim must stop answering');
const reset_record = { ...addresses[0], name: 'reset.local', flush_cache: false };
announce.start_probe(reset_record.name, 'lan', { records: () => [reset_record] });
uloop.advance(12000);
response.schedule('lan', [reset_record], [], null, false, false, false, null, from.address);
previous = length(mdns.sent);
announce.handle_conflict(reset_record.name, { ...reset_record, rdata: { address: '192.0.2.250' } }, 'lan');
uloop.advance(150);
check(!length(filter(slice(mdns.sent, previous), item => item.packet.header.flags.response &&
	item.packet.answers?.[0]?.name == reset_record.name)),
	'a conflict that resets a link also cancels its delayed answers');
announce.cancel(reset_record.name);
const budget_record = { ...addresses[0], name: 'budget.local' };
announce.start_probe(budget_record.name, 'lan', { records: () => [budget_record] });
uloop.advance(250);
const lan_probes = () => length(filter(mdns.sent, item => item.iface == 'lan' &&
	!item.packet.header.flags.response && item.packet.questions?.[0]?.name == budget_record.name));
for (let i = 0; i < 15; i++) {
	announce.handle_probe(budget_record.name, [{ ...budget_record, rdata: { address: '192.0.2.255' } }], 'lan');
	uloop.advance(100);
}
check(length(announce.get_state(budget_record.name).conflict_history) == 15, 'conflict history survives deferrals');
for (let i = 0; i < 5; i++)
	announce.handle_probe(budget_record.name, [{ ...budget_record, rdata: { address: '192.0.2.255' } }], 'lan');
check(length(announce.get_state(budget_record.name).conflict_history) == 15,
	'the conflict history holds no more entries than the rate limit');
previous = lan_probes();
announce.start_probe(budget_record.name, 'other', { records: () => [budget_record] });
uloop.advance(4500);
check(lan_probes() == previous, 'conflict threshold imposes a five-second backoff that a new link does not cancel');
uloop.advance(1000);
check(lan_probes() > previous, 'probing resumes after the backoff');
previous = length(mdns.sent);
announce.cancel(budget_record.name);
uloop.advance(10000);
check(!announce.get_state(budget_record.name) && length(mdns.sent) == previous,
	'cancelling stops every pending retry');
for (let item in [{ iface: 'lan-a', port: 1001, address: '192.0.2.1' },
	{ iface: 'lan-b', port: 1002, address: '198.51.100.1' }]) {
	discovery.service_add('Twin._http._tcp.local', '_http._tcp.local', 120, item.iface);
	cache.insert({ name: 'Twin._http._tcp.local', type: 'SRV', class: 'IN', ttl: 120,
		rdata: { target: 'twin.local', port: item.port, priority: 0, weight: 0 } }, item.iface);
	cache.insert({ name: 'Twin._http._tcp.local', type: 'TXT', class: 'IN', ttl: 120,
		rdata: { strings: [item.iface] } }, item.iface);
	cache.insert({ name: 'twin.local', type: 'A', class: 'IN', ttl: 120,
		rdata: { address: item.address } }, item.iface);
}
check(length(discovery.get_all()['_http._tcp.local']) == 2, 'same service name remains distinct on two links');
const twins = legacy.get_services('_http._tcp', true, true)['_http._tcp'].Twin;
check(length(twins) == 2 && twins[0].port == 1001 && twins[0].ipv4[0] == '192.0.2.1' &&
	twins[1].port == 1002 && twins[1].ipv4[0] == '198.51.100.1' && twins[1].txt[0] == 'lan-b',
	'browse joins SRV, TXT and addresses only within the same link');
cache.insert({ name: '_cross._tcp.local', type: 'PTR', class: 'IN', ttl: 4500,
	rdata: { ptr: 'Twin._http._tcp.local' } }, 'lan-a');
const fetched_a = filter(legacy.fetch_records('_cross._tcp.local', 'PTR', null), item => item.type == 'A');
check(length(fetched_a) == 1 && fetched_a[0].target == '192.0.2.1',
	'a record fetch follows a PTR only on the link it was learned on');
push(mdns.interfaces, { name: 'lan-a', ipv4_addresses: [], ipv6_addresses: [] },
	{ name: 'lan-b', ipv4_addresses: [], ipv6_addresses: [] });
const twin_hosts = legacy.get_hosts(true)['twin.local'];
check(length(twin_hosts) == 2 && twin_hosts[0].iface == 'lan-a' && twin_hosts[0].ipv4[0] == '192.0.2.1' &&
	twin_hosts[1].iface == 'lan-b' && twin_hosts[1].ipv4[0] == '198.51.100.1',
	'hosts keeps the addresses of each link apart');
cache.insert({ name: 'alias.local', type: 'CNAME', class: 'IN', ttl: 120, rdata: { cname: 'twin.local' } }, 'lan-a');
check(legacy.fetch_records('alias.local', 'CNAME', null)[0]?.target == 'twin.local',
	'a fetched CNAME reports its target');
splice(mdns.interfaces, -2, 2);
discovery.service_add('Hall\\.Printer._ipp._tcp.local', '_ipp._tcp.local', 120, 'lan-a');
check(legacy.get_services('_ipp._tcp', false, false)['_ipp._tcp']['Hall.Printer'],
	'browse shows an instance label with its literal dot');
const wants = (link, name, kind) => tracker.has_interest(link, mdns.name_canonical(name), kind);
check(wants('lan-a', 'Twin._http._tcp.local', 'SRV'), 'service details use sustained queries');
discovery.handle_srv_record({ name: 'Twin._http._tcp.local', type: 'SRV', ttl: 120,
	rdata: { target: 'actual-target.local' } }, 'lan-a');
check(wants('lan-a', 'actual-target.local', 'AAAA') && !wants('lan-a', 'Twin.local', 'AAAA'),
	'address resolution follows the SRV target, not the instance label');
for (let instance in [ 'One._ipp._tcp.local', 'Two._ipp._tcp.local' ]) {
	discovery.service_add(instance, '_ipp._tcp.local', 120, 'lan-a');
	discovery.handle_srv_record({ name: instance, type: 'SRV', ttl: 120, rdata: { target: 'printer.local' } }, 'lan-a');
}
uloop.advance(150);
check(length(filter(mdns.sent, item => item.iface == 'lan-a' && asks(item, 'printer.local', 'A'))) == 1,
	'services on one host share their address queries');
discovery.handle_ptr_record('_ipp._tcp.local', 'Gone._ipp._tcp.local', 0, 'lan-a');
check(!wants('lan-a', 'Gone._ipp._tcp.local', 'SRV'), 'a goodbye for an unknown instance starts no queries');
discovery.handle_ptr_record('_services._dns-sd._udp.local', '_ssh._tcp.local', 120, 'lan-a');
check(wants('lan-a', '_ssh._tcp.local', 'PTR'), 'enumerated service type receives a continuous browse');
discovery.handle_ptr_record('_services._dns-sd._udp.local', '_ssh._tcp.local', 0, 'lan-a');
check(!wants('lan-a', '_ssh._tcp.local', 'PTR'), 'a withdrawn service type is no longer browsed');
discovery.handle_ptr_record('_Services._DNS-SD._udp.local', '_sftp._tcp.local', 120, 'lan-a');
check(wants('lan-a', '_sftp._tcp.local', 'PTR'), 'the enumeration name matches in any letter case');
discovery.handle_ptr_record('_services._dns-sd._udp.local', '_sftp._tcp.local', 0, 'lan-a');
cache.insert({ name: '_services._dns-sd._udp.local', type: 'PTR', class: 'IN', ttl: 4500,
	rdata: { ptr: '_known._tcp.local' } }, 'lan');
previous = length(mdns.sent);
discovery.update();
uloop.advance(0);
const enum_query = filter(slice(mdns.sent, previous), item => item.iface == 'lan' &&
	asks(item, '_services._dns-sd._udp.local', 'PTR'))[0];
check(enum_query && length(filter(enum_query.packet.answers, record => record.rdata?.ptr == '_known._tcp.local')),
	'a query sent once carries the cached known answers');
uloop.advance(600000);
previous = length(mdns.sent);
tracker.restart('lan-a');
uloop.advance(150);
const twin_queries = filter(slice(mdns.sent, previous), item => item.iface == 'lan-a' &&
	asks(item, 'Twin._http._tcp.local'));
check(length(twin_queries) == 1 && asks(twin_queries[0], 'Twin._http._tcp.local', 'SRV') &&
	asks(twin_queries[0], 'Twin._http._tcp.local', 'TXT'),
	'a link change sends the continuous queries of that link again at once');
discovery.service_add('Twin._http._tcp.local', '_http._tcp.local', 120, 'lan-b');
discovery.interface_remove('lan-a');
check(!wants('lan-a', 'Twin._http._tcp.local', 'SRV') && !wants('lan-a', 'printer.local', 'A') &&
	wants('lan-b', 'Twin._http._tcp.local', 'SRV'), 'interface removal cancels only its own discovery queries');
const explicit = service.register({ instance: 'Explicit', service: '_ssh._tcp.local', port: 22, hostname: 'extra.local' });
host.extra_set(['extra.local']);
const renamed_host = host.rename('extra.local');
services.host_changed('extra.local', renamed_host, false);
check(service.build_records(explicit)[1].rdata.target == renamed_host && host.resolved('extra.local') == renamed_host,
	'extra-host renaming retargets dependent SRV records and survives source reload');
main.init({ hostname: 'reload.local', interfaces: ['lan'], ipv4: true, ipv6: false },
	{ local_services: false, discovery: false });
check(!length(mdns.interfaces[0].ipv6_addresses) && mdns.interfaces[0].ipv6 === false,
	'family configuration changes recreate existing interface sockets');
check(service.build_records(name)[1].rdata.target == 'reload.local', 'hostname reload updates default service targets');
let long_instance = '';
while (length(long_instance) < 59)
	long_instance += 'x';
long_instance += ' (9)';
const long_victim = service.register({ instance: long_instance, service: '_rename._tcp.local', port: 1 });
const clash = service.register({ instance: 'Clash', service: '_rename._tcp.local', port: 2 });
service.register({ instance: 'Clash (2)', service: '_rename._tcp.local', port: 3 });
services.iface_start('lan');
uloop.advance(300);
for (let victim in [ long_victim, clash ])
	announce.handle_conflict(victim, { name: victim, type: 'TXT', class: 'IN', ttl: 4500,
		rdata: { strings: [ 'other' ] } }, 'lan');
const registered = keys(service.list());
check(index(registered, substr(long_instance, 0, 58) + ' (10)._rename._tcp.local') >= 0 &&
	index(registered, long_victim) < 0, 'a renamed service keeps its label within 63 bytes');
check(index(registered, 'Clash (3)._rename._tcp.local') >= 0 && index(registered, clash) < 0,
	'a rename skips a number that another local service holds');
main.apply({ hostname: 'conf.local', interfaces: [ 'lan' ], ipv4: true, ipv6: true });
uloop.advance(300);
const response_with = (record) => ({ header: { flags: { response: true } }, questions: [],
	answers: [ record ], authority: [], additional: [] });
mdns.callbacks.packet(response_with({ name: 'conf.local', type: 'TXT', class: 'IN', ttl: 120,
	rdata: { strings: [ 'other host' ] } }), from, iface, true, false);
check(host.hostname() == 'conf-2.local',
	'while probing, a record of any type at our name is a conflict');
uloop.advance(2000);
mdns.callbacks.packet(response_with({ name: 'conf-2.local', type: 'TXT', class: 'IN', ttl: 120,
	rdata: { strings: [ 'other host' ] } }), from, iface, true, false);
check(host.hostname() == 'conf-2.local' && announce.is_announced('conf-2.local', 'lan'),
	'once announced, a record of a type we do not hold is no conflict');
const reverse_reply = (name, kind) => {
	const before = length(mdns.sent);

	query.handle({ header: { flags: {} }, questions: [ { name, type: kind, class: 'IN', unicast_response: true } ],
		answers: [], authority: [] }, from, iface, true, false);
	uloop.advance(1500);
	return filter(slice(mdns.sent, before), item => item.packet.header.flags.response &&
		item.packet.answers?.[0]?.name == name)[-1]?.packet.answers ?? [];
};
let reverse_answers = reverse_reply('1.2.0.192.in-addr.arpa', 'PTR');
check(reverse_answers[0]?.type == 'PTR' && reverse_answers[0].rdata.ptr == 'conf-2.local',
	'an IPv4 reverse-mapping question gets our host name');
let v6_reverse = '';
for (let nibble in reverse(split('fe800000000000000000000000000001', '')))
	v6_reverse += nibble + '.';
reverse_answers = reverse_reply(v6_reverse + 'ip6.arpa', 'PTR');
check(reverse_answers[0]?.rdata?.ptr == 'conf-2.local', 'an IPv6 reverse-mapping question gets our host name');
reverse_answers = reverse_reply('1.2.0.192.in-addr.arpa', 'TXT');
check(reverse_answers[0]?.type == 'NSEC', 'other types at a reverse-mapping name are denied with NSEC');
check(!length(reverse_reply('9.2.0.192.in-addr.arpa', 'PTR')), 'addresses that are not ours get no answer');
mdns.state.first_binder = false;
previous = length(mdns.sent);
packet.send_query('lan', [ { name: 'qm-only.local', type: 'A', class: 'IN', unicast_response: true } ], false, []);
check(!mdns.sent[-1].packet.questions[0].unicast_response && !packet.qu_pending('lan', 'qm-only.local', 'A'),
	'without port 5353 to ourselves queries ask for multicast replies');
mdns.state.first_binder = true;
const named = (iface_name, record_name) => filter(mdns.sent, item => item.iface == iface_name &&
	item.packet.header.flags.response && length(filter(item.packet.answers, record => record.name == record_name)));
const owned = (record_name, list) => map(list, address => ({ name: record_name, type: 'A', class: 'IN', ttl: 120,
	flush_cache: true, rdata: { address } }));
const kept_defence = owned('kept-defence.local', [ '192.0.2.51' ]);
response.schedule('ka-link', kept_defence, [], null, false, true, true, null);
response.schedule('ka-link', kept_defence, [], null, false, true, true, null);
response.suppress_pending('ka-link', kept_defence, false, from.address);
uloop.advance(300);
check(length(named('ka-link', 'kept-defence.local')) == 2, 'known answers do not suppress a probe defence');
const merge_a = owned('merge-a.local', [ '192.0.2.52' ]);
const merge_b = owned('merge-b.local', [ '192.0.2.53' ]);
response.schedule('merge-link', merge_a, [], null, false, true, true, null);
previous = length(mdns.sent);
response.schedule('merge-link', merge_a, [], null, false, true, true, null);
response.schedule('merge-link', merge_b, [], null, false, true, true, null);
check(length(mdns.sent) == previous, 'a defence joining a delayed one waits with it');
uloop.advance(300);
check(length(mdns.sent) == previous + 1 && length(mdns.sent[-1].packet.answers) == 2,
	'a later defence to the same destination keeps the records of the delayed one');
mdns.transport_fail('merge-link', 1, false);
response.schedule('merge-link', owned('refused-defence.local', [ '192.0.2.54' ]), [], null, false, true, true, null);
check(!length(named('merge-link', 'refused-defence.local')), 'a refused defence is not recorded as sent');
uloop.advance(100);
check(length(named('merge-link', 'refused-defence.local')) == 1, 'a refused defence is retried well within 250 ms');
mdns.transport_fail('retry-link', 1, false);
response.schedule('retry-link', owned('retry.local', [ '192.0.2.55' ]), [], null, false, true, false, null, from.address);
uloop.advance(20);
check(!length(named('retry-link', 'retry.local')), 'a refused response is not recorded as sent');
uloop.advance(100);
check(length(named('retry-link', 'retry.local')) == 1, 'a refused response goes out on a quick retry');
mdns.transport_fail('retry-link', 1, null);
response.schedule('retry-link', owned('never.local', [ '192.0.2.56' ]), [], null, false, true, false, null, from.address);
uloop.advance(2000);
check(mdns.transport.attempts['retry-link'] == 3 && !length(named('retry-link', 'never.local')),
	'a response that can never be sent is dropped without a retry');
const legacy_dest = { address: '192.0.2.150', port: 12345, family: 'inet', local: true };
const legacy_answer = owned('legacy.local', [ '192.0.2.57' ]);
const legacy_info = { query_id: 7, questions: [ { name: 'legacy.local', type: 'A', class: 'IN' } ], dest: legacy_dest };
for (let i = 0; i < 25; i++) {
	mdns.transport_fail('legacy-link', 1, null);
	response.schedule('legacy-link', legacy_answer, [], null, false, false, false, legacy_info);
}
previous = length(mdns.sent);
response.schedule('legacy-link', legacy_answer, [], null, false, false, false, legacy_info);
check(length(mdns.sent) == previous + 1, 'failed legacy sends do not use up the legacy budget');
mdns.transport_fail('legacy-link', 1, false);
response.schedule('legacy-link', legacy_answer, [], null, false, false, false, legacy_info);
check(length(mdns.sent) == previous + 1, 'a refused legacy response is not recorded as sent');
uloop.advance(100);
check(length(mdns.sent) == previous + 2 && mdns.sent[-1].packet.header.id == 7,
	'a refused legacy response goes out on a quick retry');
const tc_fix = owned('tcfix.local', [ '192.0.2.61', '192.0.2.62' ]);
response.multicast_stamp('fix-link', tc_fix);
uloop.advance(900);
response.schedule('fix-link', owned('tcother.local', [ '192.0.2.63' ]), [], null, true, true, false, null, from.address);
check(response.correct_low_ttl('fix-link', tc_fix, { ...tc_fix[0], ttl: 0 }), 'a goodbye of our record is corrected');
uloop.advance(390);
check(!length(named('fix-link', 'tcother.local')), 'a correction does not fire a response held for a TC query early');
uloop.advance(120);
check(length(named('fix-link', 'tcother.local')) == 1 && length(named('fix-link', 'tcother.local')[0].packet.answers) == 3,
	'the correction goes out with the response held for the TC query');
const late_fix = owned('latefix.local', [ '192.0.2.64', '192.0.2.65' ]);
response.multicast_stamp('late-link', late_fix);
uloop.advance(300);
response.schedule('late-link', owned('fast.local', [ '192.0.2.66' ]), [], null, false, true, false, null, from.address);
response.correct_low_ttl('late-link', late_fix, { ...late_fix[0], ttl: 0 });
uloop.advance(50);
check(length(named('late-link', 'fast.local')) == 1 && !length(named('late-link', 'latefix.local')),
	'a correction never delays a response that is due earlier');
uloop.advance(800);
check(length(named('late-link', 'latefix.local')) == 1 &&
	length(named('late-link', 'latefix.local')[0].packet.answers) == 2,
	'a correction held back by the rate limit goes out once the limit allows');
check(nsec.build('empty.local', []) == null && nsec.build('empty.local', [ 'NSEC', 'ANY' ]) == null,
	'no NSEC is built without a type to list');
check(nsec.build('one.local', [ 'A' ]).rdata.raw == '036f6e65056c6f63616c00000140',
	'an NSEC lists its types in one window 0 block');
check(!nsec.denies({ rdata: { raw: '05656d70747900' } }, 'A'), 'an NSEC without a bitmap block denies nothing');
const legacy_query = (count, source) => {
	const asked = [];

	for (let i = 1; i < count; i++)
		push(asked, { name: `absent${i}.local`, type: 'A', class: 'IN' });
	push(asked, { name: 'conf-2.local', type: 'A', class: 'IN' });

	const before = length(mdns.sent);
	query.handle({ header: { id: 11, flags: {} }, questions: asked, answers: [], authority: [] },
		source, iface, true, true);
	return length(mdns.sent) - before;
};
check(legacy_query(1, { ...legacy_dest, address: '192.0.2.151' }) == 1, 'an on-link legacy query is answered');
check(!legacy_query(1, { ...remote, port: 12345 }), 'a legacy query from an off-link source gets no reply');
check(legacy_query(64, { ...legacy_dest, address: '192.0.2.152' }) == 1, 'a query is answered up to the question cap');
check(!legacy_query(65, { ...legacy_dest, address: '192.0.2.153' }), 'questions beyond the cap are ignored');
const update_record = owned('update.local', [ '192.0.2.67' ]);
announce.start_probe('update.local', 'lan', { records: () => update_record });
uloop.advance(1100);
for (let i = 0; i < 12; i++)
	check(announce.refresh('update.local', 'lan'), 'an address change on an announced link is accepted');
const update_link = announce.get_state('update.local').links.lan;
check(length(update_link.updates) == 10 && update_link.update_timer,
	'more than ten updates a minute wait instead of restarting the announcements');
uloop.advance(60000);
check(length(update_link.updates) == 1 && !update_link.update_timer,
	'a waiting update is announced once the minute has passed');
announce.cancel('update.local');
const goodbye_record = (iface_name) => owned('moving.local', [ iface_name == 'lan' ? '192.0.2.68' : '198.51.100.68' ]);
let renamed;
const moving_ops = { records: (record_name, ttl, iface_name) => map(goodbye_record(iface_name),
	record => ({ ...record, ttl: ttl ?? record.ttl })), conflict: (record_name, ifaces) => { renamed = ifaces; } };
announce.start_probe('moving.local', 'lan', moving_ops);
uloop.advance(1100);
announce.start_probe('moving.local', 'other', moving_ops);
uloop.advance(260);
previous = length(mdns.sent);
announce.handle_conflict('moving.local', { ...goodbye_record('other')[0], rdata: { address: '198.51.100.99' } }, 'other');
const farewell = filter(slice(mdns.sent, previous), item => item.iface == 'lan');
check(length(farewell) == 1 && farewell[0].packet.answers[0].ttl == 0 && !farewell[0].immediate &&
	!length(filter(slice(mdns.sent, previous), item => item.iface == 'other')),
	'a conflict while probing sends a goodbye on the links that announced the name');
check(length(renamed) == 2 && !announce.get_state('moving.local'), 'the conflict handler gets every link of the name');
const refused_ops = { records: (record_name) => owned(record_name, [ '192.0.2.69' ]) };
mdns.transport_fail('refuse-link', 1, false);
announce.start_probe('refused-probe.local', 'refuse-link', refused_ops);
uloop.advance(1100);
check(mdns.transport.attempts['refuse-link'] == 5 && announce.is_announced('refused-probe.local', 'refuse-link'),
	'a refused probe is retried soon');
announce.cancel('refused-probe.local');
mdns.transport_fail('refuse-link', 4, false);
announce.start_probe('refused-announce.local', 'refuse-link', refused_ops);
uloop.advance(1100);
check(length(named('refuse-link', 'refused-announce.local')) == 1, 'a refused announcement is retried soon');
announce.cancel('refused-announce.local');
mdns.transport_fail('null-link', 4, null);
announce.start_probe('stopped-announce.local', 'null-link', refused_ops);
uloop.advance(20000);
check(mdns.transport.attempts['null-link'] == 4 && announce.is_announced('stopped-announce.local', 'null-link'),
	'an announcement that can never be sent stops');
announce.cancel('stopped-announce.local');
mdns.transport_fail('null-probe-link', 1, null);
announce.start_probe('stopped-probe.local', 'null-probe-link', refused_ops);
uloop.advance(20000);
check(mdns.transport.attempts['null-probe-link'] == 1 && !announce.is_announced('stopped-probe.local', 'null-probe-link'),
	'a probe that can never be sent stops');
announce.cancel('stopped-probe.local');
print('protocol: passed\n');
