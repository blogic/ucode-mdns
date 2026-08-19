#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 John Crispin <john@phrozen.org>

import argparse
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


def name_encode(name):
    return b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'


def name_decode(packet, offset, seen=None):
    seen = set() if seen is None else seen
    if offset in seen:
        raise ValueError('DNS pointer loop')
    seen.add(offset)
    labels = []
    while packet[offset]:
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            pointer = ((length & 63) << 8) | packet[offset + 1]
            suffix, _ = name_decode(packet, pointer, seen)
            labels.append(suffix)
            return '.'.join(labels), offset + 2
        offset += 1
        labels.append(packet[offset:offset + length].decode())
        offset += length
    return '.'.join(labels), offset + 1


def records_decode(packet):
    _, _, questions, answers, authority, additional = struct.unpack_from('!6H', packet)
    offset = 12
    for _ in range(questions):
        _, offset = name_decode(packet, offset)
        offset += 4
    records = []
    for _ in range(answers + authority + additional):
        name, offset = name_decode(packet, offset)
        kind, _, ttl, length = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        records.append((name, kind, ttl, packet[offset:offset + length]))
        offset += length
    return records


def wait_until(condition, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.03)
    raise AssertionError(description)


class Client:
    def __init__(self, socket_path, address):
        self.socket_path = socket_path
        self.address = address
        self.ubus = shutil.which('ubus')

    def call(self, method, arguments=None, success=True):
        reply = subprocess.run([self.ubus, '-s', self.socket_path, 'call', 'mdns.dnssd', method,
                                json.dumps(arguments or {})], capture_output=True, text=True, timeout=8)
        assert (reply.returncode == 0) == success, (method, reply.stderr)
        return json.loads(reply.stdout) if reply.stdout.strip() else {}

    def query(self, name, kind, timeout=4, accept=None):
        self.last_packets = []
        self.last_records = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.bind((self.address, 0))
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.address))
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            channel.settimeout(timeout)
            query = struct.pack('!6H', 0x7453, 0, 1, 0, 0, 0) + name_encode(name) + struct.pack('!HH', kind, 1)
            channel.sendto(query, ('224.0.0.251', 5353))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                channel.settimeout(deadline - time.monotonic())
                try:
                    packet, _ = channel.recvfrom(9000)
                except socket.timeout:
                    return []
                if struct.unpack_from('!H', packet)[0] != 0x7453:
                    continue
                decoded = records_decode(packet)
                self.last_records.extend(decoded)
                self.last_packets.append([(value[0], value[1]) for value in decoded])
                found = [record for record in decoded if record[0] == name and record[1] == kind]
                if found and (accept is None or accept(decoded)):
                    return found
        return []

    def listen(self):
        channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        channel.bind(('', 5353))
        channel.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                           socket.inet_aton('224.0.0.251') + socket.inet_aton(self.address))
        return channel

    @staticmethod
    def goodbyes(channel, names, timeout=4):
        seen = set()
        deadline = time.monotonic() + timeout
        while seen != names and time.monotonic() < deadline:
            channel.settimeout(deadline - time.monotonic())
            try:
                packet, _ = channel.recvfrom(9000)
            except socket.timeout:
                break
            if not struct.unpack_from('!H', packet, 2)[0] & 0x8000:
                continue
            seen.update(record[0] for record in records_decode(packet) if record[2] == 0 and record[0] in names)
        return seen

    def announce(self, name, kind, data, ttl=2):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            channel.bind(('', 5353))
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.address))
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            packet = struct.pack('!6H', 0, 0x8400, 0, 1, 0, 0)
            packet += name_encode(name) + struct.pack('!HHIH', kind, 0x8001, ttl, len(data)) + data
            channel.sendto(packet, ('224.0.0.251', 5353))


def main():
    parser = argparse.ArgumentParser(description='Check dynamic DNS-SD on an explicitly selected LAN')
    parser.add_argument('--module-dir', required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--thread-binary')
    parser.add_argument('--rcp')
    args = parser.parse_args()
    if bool(args.thread_binary) != bool(args.rcp):
        parser.error('--thread-binary and --rcp must be supplied together')
    project = pathlib.Path(__file__).resolve().parent.parent
    prefix = 'tdtest-' + uuid.uuid4().hex[:8]
    owner_name = 'threadd.test.' + prefix
    ucode = shutil.which('ucode')
    command = [ucode, '-L', str(pathlib.Path(args.module_dir).resolve()), '-L', str(project / 'ucode' / '*.uc')]
    with tempfile.TemporaryDirectory(prefix='threadd-dnssd-') as directory:
        base = pathlib.Path(directory)
        socket_path = str(base / 'ubus.sock')
        processes = []
        with open(base / 'server.log', 'w+') as log, open(base / 'events.log', 'w+') as events:
            try:
                bus = subprocess.Popen([shutil.which('ubusd') or '/usr/local/sbin/ubusd', '-s', socket_path],
                                       stdout=log, stderr=log)
                processes.append(bus)
                wait_until(lambda: pathlib.Path(socket_path).exists(), 'private ubus did not start')
                server = subprocess.Popen(command + [str(project / 'tests/dnssd_server.uc'), socket_path,
                                                      args.interface, prefix + '-router'], stdout=log, stderr=log)
                processes.append(server)
                client = Client(socket_path, args.address)

                def provider_ready():
                    if server.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    reply = subprocess.run([client.ubus, '-s', socket_path, 'call', 'mdns.dnssd', 'status'],
                                           capture_output=True, text=True, timeout=2)
                    return reply.returncode == 0 and any(iface['name'] == args.interface and iface['enabled']
                                                        for iface in json.loads(reply.stdout)['interfaces'])

                wait_until(provider_ready, 'DNS-SD provider did not enable the selected interface')
                owner = subprocess.Popen(command + [str(project / 'tests/dnssd_owner.uc'), socket_path, owner_name],
                                         stdout=events, stderr=log)
                processes.append(owner)
                wait_until(lambda: subprocess.run([client.ubus, '-s', socket_path, 'list', owner_name],
                                                   capture_output=True, text=True).stdout.strip() == owner_name,
                           'client owner object did not appear')
                token = client.call('open', {'owner': owner_name})['session']
                client.call('open', {'owner': owner_name}, success=False)

                def register(kind, definition, error=0):
                    reply = client.call('register', {'session': token, 'interface': args.interface,
                                                     'kind': kind, 'definition': definition})
                    assert reply['error'] == error, reply
                    return reply

                host_name = prefix + '-remote'
                host = register('host', {'name': host_name, 'addresses': ['fd00::1234']})
                wire_host = client.query(host['name'], 28)
                assert wire_host and wire_host[0][3] == socket.inet_pton(socket.AF_INET6, 'fd00::1234'), 'remote AAAA missing'
                definition = {'instance': prefix, 'service_type': '_tdtest._udp', 'host': host_name,
                              'port': 12345, 'txt_hex': '0569643d00ff', 'subtypes': ['_scope']}
                service = register('service', definition)
                txt = client.query(service['name'], 16)
                assert txt and txt[0][3] == bytes.fromhex(definition['txt_hex']), 'binary TXT changed on the wire'
                assert client.query('_scope._sub._tdtest._udp.local', 12), ('subtype PTR missing', client.last_packets)
                register('key', {'name': host_name, 'key_hex': '0100030f00ff'})
                key = client.query(host['name'], 25)
                assert key and key[0][3] == bytes.fromhex('0100030f00ff'), 'KEY missing on the wire'
                register('service', dict(definition, txt_hex='036b3d76'))
                assert client.query(service['name'], 16)[0][3] == bytes.fromhex('036b3d76'), 'TXT update missing'

                watched_name = prefix + '-discovered.local'
                watch = client.call('watch', {'session': token, 'interface': args.interface,
                                               'name': watched_name, 'type': 'TXT'})['watch']
                client.announce(watched_name, 16, bytes.fromhex('0569643d00ff'))

                def watch_seen(nonempty):
                    events.flush()
                    lines = (base / 'events.log').read_text().splitlines()
                    for line in lines:
                        event = json.loads(line)
                        if event['type'] == 'records' and event['data'].get('watch') == watch:
                            values = event['data']['records']
                            if bool(values) == nonempty:
                                return event
                    return None

                notification = wait_until(lambda: watch_seen(True), 'discovery update not received')
                assert notification['data']['records'][0]['rdata_hex'] == '0569643d00ff'
                assert 1 <= notification['data']['records'][0]['ttl'] <= 2, 'watch TTL must be remaining seconds'
                wait_until(lambda: watch_seen(False), 'record expiry not received', timeout=5)
                farewell = {host['name'], service['name']}
                with client.listen() as listener:
                    owner.terminate()
                    owner.wait(timeout=5)
                    seen = client.goodbyes(listener, farewell)
                assert seen == farewell, ('owner cleanup sent no goodbye for', farewell - seen)
                assert not client.query(service['name'], 16, timeout=1), 'records survived owner disconnect'
                client.call('close', {'session': token}, success=False)
                report = {'interface': args.interface, 'address': args.address, 'remote_host': True,
                                  'binary_txt': True, 'subtypes': True, 'key_records': True,
                                  'updates': True, 'discovery_and_expiry': True, 'owner_cleanup': True,
                                  'owner_goodbyes': True, 'single_session': True}
                if args.thread_binary:
                    settings = base / 'thread-settings'
                    settings.mkdir(mode=0o700)
                    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as allocator:
                        allocator.bind(('::1', 0))
                        port_base = allocator.getsockname()[1]
                    environment = dict(os.environ, PORT_BASE=str(port_base), PORT_OFFSET='0')
                    thread = subprocess.Popen([str(pathlib.Path(args.thread_binary).resolve()), '-s', socket_path,
                                               '-d', str(settings), '-I', 'tdsimulation', '-B', args.interface,
                                               '-r', f'spinel+hdlc+forkpty://{pathlib.Path(args.rcp).resolve()}?forkpty-arg=1'],
                                              stdout=log, stderr=log, cwd=base, env=environment)
                    processes.append(thread)

                    def thread_call(method, arguments=None, object_name='thread'):
                        result = subprocess.run([client.ubus, '-s', socket_path, 'call', object_name, method,
                                                  json.dumps(arguments or {})], capture_output=True, text=True, timeout=5)
                        if thread.poll() is not None:
                            log.flush()
                            raise RuntimeError((base / 'server.log').read_text()[-5000:])
                        return json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else {}

                    wait_until(lambda: thread_call('status').get('dns_sd'), 'C bridge did not become ready')
                    thread_call('create', {'network_name': 'Threadd DNS', 'channel': 20}, 'thread.network')
                    thread_call('attach')
                    wait_until(lambda: thread_call('status').get('role') == 'leader', 'software RCP did not form', timeout=30)
                    assert thread_call('status')['dns_sd'] is True
                    report['openthread_bridge'] = True
                    report['openthread_formation'] = True

                    def meshcop_visible():
                        return client.query('_meshcop._udp.local', 12,
                                            accept=lambda values: any(record[1] == 16 and b'nn=Threadd DNS' in record[3]
                                                                      for record in values))

                    wait_until(meshcop_visible, 'OpenThread MeshCoP TXT was not advertised', timeout=10)
                    report['meshcop_advertisement'] = True
                    server.terminate()
                    assert server.wait(timeout=5) == 0
                    wait_until(lambda: thread_call('status').get('dns_sd') is False, 'provider loss was not detected')
                    assert thread_call('status')['role'] == 'leader'
                    server = subprocess.Popen(command + [str(project / 'tests/dnssd_server.uc'), socket_path,
                                                          args.interface, prefix + '-router'], stdout=log, stderr=log)
                    processes.append(server)
                    wait_until(provider_ready, 'restarted DNS-SD provider did not start')
                    wait_until(lambda: thread_call('status').get('dns_sd'), 'C bridge did not reconnect')
                    assert thread_call('status')['role'] == 'leader'
                    report['provider_restart'] = True
                    thread_call('detach')
                    thread.terminate()
                    assert thread.wait(timeout=5) == 0
                print(json.dumps(report, indent=2))
            except BaseException:
                log.flush()
                with tempfile.NamedTemporaryFile(prefix='threadd-dnssd-failure-', suffix='.log', delete=False) as failure:
                    failure.write((base / 'server.log').read_bytes())
                    print(f'Diagnostics: {failure.name}', file=sys.stderr)
                raise
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)


if __name__ == '__main__':
    main()
