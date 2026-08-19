# ucode-mdns

An mDNS responder and service browser for OpenWrt, implementing RFC 6762
(Multicast DNS) and RFC 6763 (DNS-Based Service Discovery).

It replaces `umdns`. The ubus object, the method and argument names, the UCI
schema and the service files in `/etc/umdns` keep their meaning, so the `mdns`
cli module and anything else built against `umdns` needs no change.

The daemon is split in two. A small C module owns the wire and the kernel; the
protocol logic lives in ucode.

## Why the split

C does what ucode cannot do cheaply, or at all: raw sockets on port 5353 and
multicast group membership, reading the packet destination via `IP_PKTINFO` /
`IPV6_PKTINFO` (which is how a multicast query is told apart from a unicast
one), DNS name compression and expansion, netlink notifications for link and
address changes, and the packet codec itself.

Everything above the wire is ucode: the record cache, probing and announcing,
conflict detection and resolution, known-answer suppression, response
aggregation and scheduling, query backoff, NSEC generation and service
discovery.

## Layout

`src/` builds to `mdns.so`, which registers under the bare name `mdns` and
exposes `interface_list`, `interface_create`, `interface_destroy`,
`packet_parse`, `packet_build`, `packet_send`, `set_callback`, `set_hostname`,
`set_debug`, `set_trace`, `info`, `debug` and `error`. Traffic comes back into
ucode through two callbacks registered with `set_callback()`: `packet` for every
received datagram, and `interface_change` for netlink link and address events.
The codec understands A, NS, CNAME, PTR, TXT, AAAA, SRV, OPT, NSEC and ANY.

`ucode/` holds the protocol logic, 16 modules imported by bare name:

| Module | Role |
|---|---|
| `main.uc` | orchestration, callback routing, periodic timers, reload |
| `config.uc` | UCI configuration, network to device resolution |
| `cache.uc` | record cache with TTL tracking, expiry and refresh scheduling |
| `service.uc` | service registry, record building, browsing, resolution |
| `services.uc` | local service sources: `/etc/umdns` and procd service data |
| `host.uc` | host names this host claims, and their A and AAAA records |
| `announce.uc` | probing, announcing, conflict resolution, goodbye packets |
| `query.uc` | incoming question handling, decides what to answer |
| `response.uc` | response aggregation, delay scheduling, probe defence |
| `discovery.uc` | discovered services indexed by type |
| `tracker.uc` | active query tracking with exponential backoff |
| `packet.uc` | packet assembly, size estimation, transmission |
| `nsec.uc` | NSEC records for negative responses |
| `mdns_ubus.uc` | the `umdns` ubus object |
| `utils.uc` | name normalisation, parsing, TXT and rdata helpers |
| `const.uc` | protocol timings and implementation limits, one place |

`ucode-mdns.uc` is the entry point and the only executable script.

## Running

On OpenWrt the package installs `/etc/init.d/umdns`, which starts the daemon
under procd. Everywhere else, both the module directory and the source
directory go on the ucode path:

    ucode -L /usr/lib/ucode -L '/usr/share/umdnsd/*.uc' /usr/share/umdnsd/ucode-mdns.uc

The directory holding `mdns.so` has to be an absolute path; a relative one fails
with `Unable to resolve path for module 'mdns'`. The `*.uc` search path may be
relative.

Logging goes to syslog and stdio under the identity `umdnsd`. `SIGHUP` re-reads
the configuration and the local services. `SIGTERM` and the first `SIGINT` start
a graceful shutdown, which sends goodbye packets (TTL 0) for every announced
record before tearing the interfaces down; a second `SIGINT` exits immediately.
A failure to publish the ubus object is logged and otherwise ignored.

## Configuration

`/etc/config/umdns`, one `umdns` section. The last section wins, which is the
`@umdns[-1]` the init script addressed before.

| Option | Type | Meaning |
|---|---|---|
| `network` | list | UCI networks to serve, each resolved to its `l3_device` through netifd |
| `device` | list | raw device names, for a device netifd does not manage |
| `hostname` | string | host name to claim; unset takes the system host name |
| `ipv4` | bool | serve IPv4, default on |
| `ipv6` | bool | serve IPv6, default on |
| `debug` | bool | log the protocol decisions |
| `trace` | bool | log every packet |

    config umdns
        list network lan
        option ipv4 '1'
        option ipv6 '1'

A host name gains a `.local.` suffix if it lacks one. An empty interface set
starts nothing.

The daemon reads this file itself, so a change needs `/etc/init.d/umdns reload`,
`ubus call umdns reload` or `SIGHUP`, not a restart. A reload keeps the
interfaces that stay, along with their sockets and their announcement state.

## Announcing a service

Two sources, both the ones the C `umdns` reads.

A JSON file in `/etc/umdns/`, keyed by an id of your choosing:

    {
        "sshd": {
            "service": "_ssh._tcp.local",
            "port": 22,
            "txt": [ "daemon=dropbear" ]
        }
    }

`service` and `port` are required. `instance` defaults to the host label,
`hostname` defaults to the daemon host name and, when given, is claimed as a
further name this host answers address queries for.

Or the `mdns` blob in the data section of a running procd instance, which takes
the same shape:

    procd_open_data
    json_add_object mdns
    json_add_object sshd
    json_add_string service "_ssh._tcp.local"
    json_add_int port 22
    json_close_object
    json_close_object
    procd_close_data

The daemon probes each name, announces it, defends it, and renames on a lost
tiebreak: a service instance gains ` (2)`, a host name gains `-2`. A reload
compares both sources against what is registered, so an untouched service keeps
its announcement state and a withdrawn one gets a goodbye packet.

## ubus interface

The daemon publishes the object `umdns` once uloop is up.

| Method | Arguments | Returns |
|---|---|---|
| `hosts` | `array` | discovered hostnames with their `ipv4` and `ipv6` addresses, including the names this host answers for |
| `browse` | `service`, `array`, `address` | discovered services grouped by type, then by instance label |
| `query` | `question`, `interface`, `type` | sends a query, on one interface or on all of them |
| `fetch` | `question`, `type` | the cached records for that question |
| `announcements` | none | the services this host announces |
| `update` | none | triggers a discovery refresh |
| `reload` | none | re-reads the configuration and the local services |
| `set_config` | `interfaces`, `keep` | replaces the interface set until the next reload |
| `stats` | none | cache statistics |

`array` reports repeated values as a list; without it only the first value is
reported, because a ucode object cannot hold a repeated key. `address` defaults
to true and drops `ipv4` and `ipv6` from `browse` when set to false. `type`
takes a numeric DNS type, as `umdns` does.

`browse` filters on the service type with the `.local` suffix stripped. Each
instance carries `iface` and `domain`, and, where the cache holds the matching
records, `host`, `port`, `ttl`, `last_update`, `priority`, `weight`, `txt`,
`ipv4` and `ipv6`.

    ubus call umdns browse '{ "service": "_http._tcp", "array": true }'

Note that `priority` and `weight` come back as rubbish for a service announced
by the C `umdns`: `service_add_srv()` there writes only the port into a shared
scratch buffer and leaves the two leading fields holding whatever the previous
record left behind.

## Package

`/src/feed-blogic/ucode-mdns` builds this for OpenWrt. It conflicts with
`umdns` and provides it, since both own `/etc/init.d/umdns` and
`/etc/config/umdns`. The init script adds the firewall rules for UDP 5353 on
each configured network, reloads on a config change and on a netifd interface
event, and reloads five seconds after a procd instance update so a service
advertised through procd data is picked up.

The package ships no seccomp profile and does not use the procd jail. The
profile in `/etc/seccomp/umdns.json` is written for the C daemon and would kill
a ucode process, and a jail would have to carry the interpreter and every
module with it.

## Compliance

RFC 6762 and RFC 6763 are implemented, including probing with simultaneous
probe tiebreaking, conflict resolution and renaming, known-answer suppression
across multiple packets, response aggregation and the multicast rate limit,
cache coherency with the cache-flush bit and goodbye packets, NSEC for negative
responses, and legacy unicast queries.

Known gaps, all of them SHOULD or MAY:

- Punycode validation. A label with an `xn--` prefix is not rejected.
- Duplicate question suppression (Section 7.3) and duplicate answer
  suppression (Section 7.4).
- Passive observation of failures (Section 10.5).
- The reconfirm entry point of Section 10.4.

## Licence

GPL 2.0 only, see `LICENSE.txt`. Every source file carries an
`SPDX-License-Identifier: GPL-2.0-only` header. Copyright (C) 2026 John
Crispin.
