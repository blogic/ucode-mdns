// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as utils from '../ucode/utils.uc';
import * as cache from '../ucode/cache.uc';
import * as mdns from 'mdns';
import * as service from '../ucode/service.uc';
import * as nsec from '../ucode/nsec.uc';
import * as host from '../ucode/host.uc';
import * as c from '../ucode/const.uc';
import * as main from '../ucode/main.uc';
import * as mdns_ubus from '../ucode/mdns_ubus.uc';
import * as ubus from 'ubus';

function check(value, message) {
	if (!value)
		die(message);
}

check(!utils.rdata_equal('CNAME', { cname: 'one.local' }, { cname: 'two.local' }),
	'different CNAME targets must differ');
check(utils.rdata_equal('CNAME', { cname: 'One.local.' }, { cname: 'one.LOCAL' }),
	'CNAME targets use DNS name equality');
const first = { name: 'alias.local', type: 'CNAME', class: 'IN', ttl: 120,
	rdata: { cname: 'one.local' } };
cache.insert(first, 'lan');
cache.insert({ ...first, rdata: { cname: 'two.local' } }, 'lan');
check(length(cache.lookup(first.name, 'CNAME', 'IN', 'lan')) == 2,
	'cache must retain distinct CNAME data');
check(utils.rdata_equal('PTR', { ptr: 'Printer.local.' }, { ptr: 'printer.LOCAL' }),
	'PTR targets use DNS name equality');
const srv = { priority: 0, weight: 0, port: 80, target: 'Host.local.' };
check(utils.rdata_equal('SRV', srv, { ...srv, target: 'host.LOCAL' }), 'SRV target equality');
check(!utils.rdata_equal('SRV', srv, { ...srv, port: 81 }), 'SRV ports remain significant');
check(utils.rdata_equal('AAAA', { address: 'fd00:0:0:0:0:0:0:1' }, { address: 'fd00::1' }),
	'IPv6 comparison uses address bytes');
check(!utils.rdata_equal('AAAA', { address: 'fd00::1' }, { address: 'fd00::2' }),
	'different IPv6 addresses');
check(!utils.rdata_equal('AAAA', { address: 'invalid' }, { address: 'invalid' }),
	'invalid addresses do not compare equal');
check(utils.name_equal('Café.local', 'Caf\\195\\169.LOCAL.'), 'literal and escaped UTF-8 names match');
check(!utils.name_equal('A\\.B.local', 'A.B.local'), 'literal dots do not become label boundaries');
const dotted = service.register({ instance: 'A.B', service: '_http._tcp.local', port: 80 });
check(dotted == 'A\\.B._http._tcp.local', 'ordinary services escape instance labels');
const denial = nsec.build(dotted, ['TXT', 'SRV']);
const owner = hexenc(mdns.rdata_encode({ type: 'PTR', rdata: { ptr: dotted } }));
check(substr(denial.rdata.raw, 0, length(owner)) == owner, 'NSEC next name preserves literal label dots');
const with_unknown = nsec.build('typed.local', [ 'A', 'UNKNOWN_99' ]);
check(substr(with_unknown.rdata.raw, -30) == '000d40000000000000000000000010',
	'NSEC lists a type known only by its number');
check(nsec.build('typed.local', [ 'A', 'UNKNOWN_300' ]) == null,
	'no NSEC is built when a type cannot be listed in block 0');
for (let label in ['Café', 'A.B', 'Back\\slash', join('', map([1,2,3], () => 'é'))]) {
	const name = utils.label_encode(label) + '.local';
	const parsed = mdns.packet_parse(mdns.packet_build({ questions: [{ name, type: 'A', class: 'IN' }] }));
	check(parsed.questions[0].name == name, 'portable Unicode and punctuation round trip');
}
let long_label = '';
for (let i = 0; i < 63; i++) long_label += '(';
const long_name = utils.label_encode(long_label) + '.' + utils.label_encode(long_label) + '.local';
const long_packet = mdns.packet_parse(mdns.packet_build({ questions: [{ name: long_name, type: 'ANY' }] }));
check(long_packet.questions[0].name == long_name, 'long escaped presentation fits a legal wire name');
const spaced = mdns.packet_parse(mdns.packet_build({ questions: [{ name: 'My Printer._ipp._tcp.local', type: 'SRV' }] }));
check(spaced.questions[0].name == 'My Printer._ipp._tcp.local', 'spaces stay literal in parsed names');
check(utils.name_equal('My\\032Printer.local', 'my printer.local'), 'decimal escapes compare by their byte');
check(!utils.name_equal('bad..local', 'other..local'), 'invalid names never compare equal');
const compressed = mdns.packet_parse(mdns.packet_build({ header: { flags: { response: true } },
	answers: [
		{ name: '_ipp._tcp.local', type: 'PTR', class: 'IN', ttl: 120, rdata: { ptr: 'One._ipp._tcp.local' } },
		{ name: '_ipp._tcp.local', type: 'PTR', class: 'IN', ttl: 120, rdata: { ptr: 'Two._ipp._TCP.local' } }
	] }));
check(compressed.answers[1].rdata.ptr == 'Two._ipp._tcp.local', 'names compress against earlier names');
const bad_rdata = '\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x00' +
	'\x01a\x05local\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x05\x01b\x00\x00\x00' +
	'\x01c\xc0\x0e\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x01';
const skipped = mdns.packet_parse(bad_rdata);
check(length(skipped.answers) == 1 && skipped.answers[0].type == 'A',
	'a record with invalid rdata is skipped without losing the records after it');
const maximum_label = replace(long_label, /\(/g, 'x');
host.set_hostname(maximum_label + '.local');
const renamed = host.rename(maximum_label + '.local');
check(length(split(renamed, '.')[0]) == 63 && match(renamed, /-2\.local$/),
	'host renaming preserves the maximum label length');
let dotted_label = '';
while (length(dotted_label) < 62)
	dotted_label += 'a.';
host.set_hostname(utils.label_encode(substr(dotted_label, 0, 62)) + '.local');
const renamed_dotted = host.rename(host.hostname());
check(renamed_dotted != null && length(utils.label_first(renamed_dotted)) == 63 &&
	utils.label_first(renamed_dotted) == substr(dotted_label, 0, 61) + '-2' &&
	match(renamed_dotted, /\.local$/), 'host renaming counts the label bytes, not their escapes');
check(utils.name_equal('same.local', 'same.local') && !utils.name_equal('', '') && !utils.name_equal(null, null),
	'identical names match at once, empty names never match');
check(utils.rdata_equal('A', { address: '192.0.2.1' }, { address: '192.0.2.1' }) &&
	!utils.rdata_equal('A', { address: '192.0.2.1' }, { address: '192.0.2.2' }),
	'IPv4 comparison');
const label_rejected = (label) => {
	try {
		utils.label_encode(label);
	} catch (e) {
		return true;
	}

	return false;
};
check(label_rejected('bad\xc2\x85') && label_rejected('bad\xff') && label_rejected(maximum_label + 'x'),
	'labels with C1 controls, invalid UTF-8 or more than 63 bytes are rejected');
check(utils.label_encode(maximum_label) == maximum_label, 'a 63 byte label is accepted');
check(utils.label_encode('Cafe\xcc\x81') == 'Cafe\xcc\x81', 'a decomposed label keeps its bytes');
service.set_hostname('a\\.b.local');
check(service.register({ service: '_label._tcp.local', port: 1 }) == 'a\\.b._label._tcp.local',
	'the default instance label is the unescaped first label of the host name');
check(service.register({ instance: 'Printer', service: '_case._tcp.local', port: 1 }) != null &&
	service.register({ instance: 'printer', service: '_case._tcp.local', port: 2 }) == null,
	'instance names that differ in ASCII case only are one name');
const flapping = service.register({ instance: 'Flapping', service: '_state._tcp.local', port: 1 });
let transitions = service.set_state(flapping, 'probing') && service.set_state(flapping, 'probing');
for (let i = 0; i < 24; i++)
	transitions = transitions && service.set_state(flapping, 'announcing') &&
		service.set_state(flapping, 'announced') && service.set_state(flapping, i % 2 ? 'probing' : 'announcing');
check(transitions && service.get_state(flapping) == 'probing',
	'every state announce.uc reports is accepted, without a limit on its rate');
main.apply({ hostname: 'old.local', interfaces: [] });
const pinned = service.register({ instance: 'Pinned', service: '_pin._tcp.local', port: 1, hostname: 'old.local' });
const follower = service.register({ instance: 'Follower', service: '_pin._tcp.local', port: 2 });
main.apply({ hostname: 'new.local', interfaces: [] });
check(service.build_records(pinned)[1].rdata.target == 'old.local' &&
	service.build_records(follower)[1].rdata.target == 'new.local',
	'a configured host name change keeps an explicit service host name');
main.apply({ hostname: 'NEW.local', interfaces: [] });
check(host.hostname() == 'new.local' && main.get_config().hostname == 'new.local',
	'a change in letter case only keeps the claimed name');
check(mdns_ubus.reconfirm_handle({ question: 'stale.local', type: 1, interface: 'missing' }) == ubus.STATUS_NOT_FOUND &&
	mdns_ubus.reconfirm_handle({ type: 1 }) == ubus.STATUS_INVALID_ARGUMENT,
	'reconfirm reports an unknown interface and a missing question');
while (length(service.list()) < c.MAX_SERVICES) {
	const count = length(service.list());
	check(service.register({ instance: `Capacity${count}`, service: '_http._tcp.local', port: 80 }), 'fill registry');
}
const replacement = service.register({ instance: 'Replacement', service: '_http._tcp.local', port: 80 }, dotted);
check(replacement != null, 'conflict replacement can register at capacity');
service.unregister(dotted);
check(length(service.list()) == c.MAX_SERVICES, 'replacement preserves the registry bound');
const mx_upper = { raw: '000a' + '044d41494c056c6f63616c00' };
const mx_lower = { raw: '000a' + '046d61696c056c6f63616c00' };
check(utils.rdata_equal('MX', mx_upper, mx_lower), 'names inside MX rdata compare case-insensitively');
check(!utils.rdata_equal('MX', mx_upper, { raw: '0014' + '046d61696c056c6f63616c00' }),
	'other MX fields stay significant');
check(!utils.rdata_equal('NSEC', {}, {}), 'NSEC data that cannot be encoded never compares equal');
check(utils.rdata_equal('KEY', { raw: 'ABCD' }, { raw: 'abcd' }), 'opaque data compares by its bytes');
const only_a = nsec.build('neg.local', [ 'A' ]);
check(nsec.denies(only_a, 'AAAA') && !nsec.denies(only_a, 'A') && !nsec.denies(only_a, 'ANY'),
	'a received NSEC denies exactly the types it does not list');
check(!nsec.denies({ rdata: { raw: '036e656700' + '0005' } }, 'AAAA'), 'a malformed NSEC denies nothing');
print('record equality: passed\n');
