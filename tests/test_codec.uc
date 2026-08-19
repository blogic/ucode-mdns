// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

import * as mdns from 'mdns';

let checks = 0;

function check(condition, description) {
	if (!condition)
		die(description);
	checks++;
}

function roundtrip(records) {
	const wire = mdns.packet_build({
		header: { id: 0, flags: { response: true, authoritative: true } },
		questions: [], answers: records, authority: [], additional: []
	});

	check(type(wire) == 'string', `packet build: ${mdns.error()}`);
	const parsed = mdns.packet_parse(wire);
	check(type(parsed) == 'object', `packet parse: ${mdns.error()}`);
	return parsed.answers;
}

const samples = [ 'id=\x00\x01\xff', '', '\x00', 'plain=text', 'key=\xc3\xa4', 'zero=\x00tail' ];
const txt = { name: 'test._meshcop._udp.local', type: 'TXT', class: 'IN', ttl: 120,
	flush_cache: true, rdata: { strings: samples } };
const answer = roundtrip([txt])[0];
check(length(answer.rdata.strings) == length(samples), 'TXT entry count');
for (let index = 0; index < length(samples); index++) {
	check(length(answer.rdata.strings[index]) == length(samples[index]), `TXT length ${index}`);
	check(answer.rdata.strings[index] == samples[index], `TXT bytes ${index}`);
}

const bytes = [];
for (let value = 0; value < 255; value++)
	push(bytes, chr(value));
const all_bytes = join('', bytes);
const long_txt = roundtrip([{ ...txt, rdata: { strings: [all_bytes] } }])[0];
check(long_txt.rdata.strings[0] == all_bytes, '255-byte binary TXT entry');
check(length(long_txt.rdata.strings[0]) == 255, 'maximum TXT entry length');

const key = { name: 'thread-host.local', type: 'KEY', class: 'IN', ttl: 120,
	flush_cache: true, rdata: { raw: '0100030f00ff0123456789abcdef' } };
const key_answer = roundtrip([key])[0];
check(key_answer.type == 'KEY', 'KEY record type');
check(key_answer.rdata.raw == key.rdata.raw, 'KEY data round trip');
check(mdns.TYPE_KEY == 25, 'KEY module constant');

const invalid = mdns.packet_build({ header: { flags: { response: true } },
	questions: [], answers: [{ ...txt, rdata: { strings: [all_bytes + 'x'] } }], authority: [], additional: [] });
check(invalid == null, 'TXT entries over 255 bytes are rejected');

const owner_hex = '04686f7374056c6f63616c00';
const zero20 = '0000000000000000000000000000000000000000';
for (let sample in [
	[2, 'c00c', owner_hex], [39, 'c00c', owner_hex],
	[6, 'c00cc00c' + zero20, owner_hex + owner_hex + zero20],
	[15, '0001c00c', '0001' + owner_hex], [18, '0001c00c', '0001' + owner_hex],
	[21, '0001c00c', '0001' + owner_hex], [36, '0001c00c', '0001' + owner_hex],
	[17, 'c00cc00c', owner_hex + owner_hex], [26, '0001c00cc00c', '0001' + owner_hex + owner_hex],
	[47, 'c00c000140', owner_hex + '000140']
]) {
	const encoded = '000084000001000100000000' + owner_hex + '00ff0001' +
		'c00c' + sprintf('%04x', sample[0]) + '000100000078' + sprintf('%04x', length(sample[1]) / 2) + sample[1];
	const decoded = mdns.packet_parse(hexdec(encoded));
	check(decoded.answers[0].rdata.raw == sample[2], `compressed RDATA type ${sample[0]} is pointer independent`);
	check(mdns.packet_parse(mdns.packet_build(decoded)).answers[0].rdata.raw == sample[2],
		`name-bearing RDATA type ${sample[0]} can move to another packet`);
}
const opaque = { name: 'opaque.local', type: 99, class: 3, ttl: 120, rdata: { raw: '1234' } };
const opaque_wire = mdns.packet_build({ answers: [opaque] });
const opaque_packet = mdns.packet_parse(opaque_wire);
check(opaque_packet.answers[0].type == 'UNKNOWN_99' && opaque_packet.answers[0].class == 'UNKNOWN_3',
	'unknown type and class retain numeric identity');
check(mdns.packet_parse(mdns.packet_build(opaque_packet)).answers[0].rdata.raw == '1234',
	'unknown opaque data survives reassembly');
check(mdns.packet_build({ answers: [{ ...opaque, type: 'UNKNOWN_+99' }] }) == null,
	'an unknown type spelling must hold decimal digits only');
const malformed_nsec = '000084000001000200000000' + owner_hex + '00ff0001' +
	'c00c002f0001000000780001ff' + 'c00c00010001000000780004c0000201';
const after_nsec = mdns.packet_parse(hexdec(malformed_nsec)).answers;
check(length(after_nsec) == 1 && after_nsec[0].type == 'A',
	'an invalid NSEC is skipped without losing the records after it');
const malformed_mx = '000084000001000200000000' + owner_hex + '00ff0001' +
	'c00c000f000100000078000500' + '0101ff00' + 'c00c00010001000000780004c0000201';
const after_mx = mdns.packet_parse(hexdec(malformed_mx)).answers;
check(length(after_mx) == 1 && after_mx[0].type == 'A',
	'an invalid name in MX rdata is skipped without losing the records after it');
let large = '';
for (let i = 0; i < 8922; i++) large += '00';
const oversized = { name: 'x.local', type: 'KEY', class: 'IN', ttl: 120, rdata: { raw: large } };
check(mdns.packet_build({ answers: [oversized] }) == null, '9000-byte ceiling includes IPv6 and UDP headers');
const ipv4_large = mdns.packet_build({ answers: [oversized] }, { family: 'inet' });
check(type(ipv4_large) == 'string' && length(ipv4_large) + 28 <= 9000, 'IPv4 ceiling reserves its own header length');
const medium = { ...oversized, rdata: { raw: substr(large, 0, 3000) } };
const fragmented = mdns.packet_build({ answers: [medium, txt, key] }, { mtu: 1280 });
check(type(fragmented) == 'array', 'MTU-sized packet assembly splits a large response');
let total_records = 0;
for (let piece in fragmented) {
	const decoded = mdns.packet_parse(piece);
	total_records += length(decoded.answers);
	check(length(piece) + 48 <= 1280 || length(decoded.answers) == 1,
		'packet exceeding MTU contains exactly one resource record');
}
check(total_records == 3, 'MTU splitting preserves all records');
for (let mtu in [-1, 0, '1280'])
	check(mdns.packet_build({ answers: [txt] }, { mtu }) == null, `mtu ${mtu} is rejected`);
const excessive = [];
for (let i = 0; i < 17; i++) push(excessive, { ...medium, name: `large${i}.local`, rdata: { raw: substr(large, 0, 2600) } });
check(mdns.packet_build({ answers: excessive }) == null, 'output limit reports failure instead of silent record loss');
const optional = [];
for (let i = 0; i < 20; i++)
	push(optional, { ...medium, name: `extra${i}.local`, rdata: { raw: substr(large, 0, 2600) } });
const trimmed = mdns.packet_build({ header: { flags: { response: true } },
	answers: [txt], additional: optional });
check(type(trimmed) == 'array' && mdns.packet_parse(trimmed[0]).answers[0].type == 'TXT',
	'additional records past the datagram limit are dropped, the answers still go out');
const known = [];
for (let i = 0; i < 40; i++)
	push(known, { name: `known${i}._http._tcp.local`, type: 'PTR', class: 'IN', ttl: 4500,
		rdata: { ptr: `instance-with-a-long-name-${i}._http._tcp.local` } });
const split_query = mdns.packet_build({ questions: [{ name: '_http._tcp.local', type: 'PTR', class: 'IN' }],
	answers: known }, { mtu: 1280 });
check(type(split_query) == 'array' && mdns.packet_parse(split_query[0]).header.flags.truncated &&
	!mdns.packet_parse(split_query[-1]).header.flags.truncated,
	'a query split across packets sets TC on every packet but the last');
const precomposed = 'Caf\xc3\xa9.local';
const decomposed = 'Cafe\xcc\x81.local';
check(mdns.name_prepare(precomposed) == precomposed, 'outgoing names keep their UTF-8 bytes and their case');
check(mdns.name_canonical('CAF\xc3\x89.LOCAL') == 'caf\xc3\x89.local', 'only ASCII letters fold to lower case');
check(mdns.name_canonical(decomposed) != mdns.name_canonical(precomposed),
	'names in different normalization forms are different names');
check(mdns.name_prepare('bad\xc2\x85.local') == null, 'C1 control characters are rejected');
for (let invalid_name in ['bad\xc0\x80.local', 'bad\xed\xa0\x80.local', 'bad\xf4\x90\x80\x80.local', 'safe.local\x00hidden']) {
	check(mdns.name_prepare(invalid_name) == null, 'invalid UTF-8 is rejected before publication');
	check(mdns.packet_build({ questions: [{ name: invalid_name, type: 'A' }] }) == null,
		'wire encoder cannot bypass UTF-8 validation');
}
for (let label in ['c080', 'eda080', 'f4908080', 'e08080', 'c285']) {
	const invalid_query = '000000000001000000000000' + sprintf('%02x', length(label) / 2) + label +
		'056c6f63616c0000010001';
	check(!length(mdns.packet_parse(hexdec(invalid_query)).questions), 'wire decoder rejects malformed UTF-8 labels');
}
const decomposed_query = '000000000001000000000000' + '0643616665cc81' + '056c6f63616c0000010001';
check(mdns.packet_parse(hexdec(decomposed_query)).questions[0].name == decomposed,
	'a received name in decomposed form is accepted');
let full_label = '';
for (let i = 0; i < 63; i++) full_label += 'x';
const maximum_name = full_label + '.' + full_label + '.' + full_label + '.' + substr(full_label, 0, 62);
const maximum_wire = mdns.packet_build({ questions: [{ name: maximum_name, type: 'ANY' }] });
check(type(maximum_wire) == 'string' && mdns.packet_parse(maximum_wire).questions[0].name == maximum_name,
	'RFC 6762 full 256-byte wire name is supported beyond the legacy libc boundary');
check(mdns.packet_build({ questions: [{ name: maximum_name + 'x', type: 'ANY' }] }) == null,
	'names beyond the RFC limit remain rejected');
check(mdns.name_prepare(full_label + 'x.local') == null, 'labels over 63 bytes are rejected');
const maximum_srv = mdns.packet_parse(mdns.packet_build({ header: { flags: { response: true } }, answers: [
	{ name: maximum_name, type: 'SRV', class: 'IN', ttl: 120,
		rdata: { priority: 0, weight: 0, port: 1, target: maximum_name } }
] }));
check(maximum_srv.answers[0].rdata.target == maximum_name,
	'a full-length name compresses and decodes in rdata');

printf('codec: %d checks passed\n', checks);
