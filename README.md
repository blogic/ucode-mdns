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
The codec understands A, NS, CNAME, PTR, TXT, KEY, AAAA, SRV, OPT, NSEC and ANY.

`ucode/` holds the protocol logic, 19 modules imported by bare name:

| Module | Role |
|---|---|
| `main.uc` | orchestration, callback routing, periodic timers, reload |
| `config.uc` | UCI configuration, network to device resolution |
| `cache.uc` | record cache with TTL tracking, expiry and refresh scheduling |
| `service.uc` | service registry, record building, browsing, resolution |
| `services.uc` | local service sources: `/etc/umdns` and procd service data |
| `host.uc` | host names this host claims, and their A and AAAA records |
| `key.uc` | KEY records published for a host or instance name |
| `publish.uc` | services, hosts and keys other daemons publish through ubus |
| `subscribe.uc` | browse and resolve subscriptions, reported as ubus notifications |
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
| `service_add` | `owner`, `instance`, `service`, `host`, `port`, `txt`, `txt_hex`, `subtypes` | publishes or updates a service, see below |
| `service_del` | `owner`, `instance`, `service` | withdraws a published service |
| `host_add` | `owner`, `host`, `addresses` | publishes or updates a host name with the addresses given |
| `host_del` | `owner`, `host` | withdraws a published host |
| `key_add` | `owner`, `name`, `key` | publishes or replaces the KEY record of a name |
| `key_del` | `owner`, `name` | withdraws a KEY record |
| `subscribe` | `owner`, `service`, `instance`, `host` | starts a browse, a resolve or a host subscription |
| `unsubscribe` | `owner`, `service`, `instance`, `host` | ends it |
| `owner_flush` | `owner` | withdraws every entry and subscription of an owner |

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

## Publishing from another daemon

A daemon can publish records at run time instead of writing a service file.
Every entry carries an `owner` string of the caller's choosing. Only that
owner can change or withdraw it, and `owner_flush` withdraws all of an owner's
entries and subscriptions, which a daemon calls when it starts and when it
stops. Entries do not go away when the caller disconnects from ubus.

`service_add` takes the service type with or without `.local`, an instance
label (default: the host label), a port, and the TXT data either as a list of
strings in `txt` or as encoded TXT RDATA in `txt_hex`. Use `txt_hex` for
binary values. `subtypes` lists labels such as `_printer`, each published as
`_printer._sub.<type>`. `host` names a host published with `host_add`;
without it the SRV record points at this host.

    ubus call umdns service_add '{ "owner": "demo", "instance": "Lab",
        "service": "_http._tcp", "port": 80, "txt": [ "path=/" ] }'

`host_add` publishes A and AAAA records for a label under `.local` with the
addresses given, for a host that does not speak mDNS itself. `key_add`
publishes a KEY record (RFC 2535) for a host or instance name given without
`.local`; it travels with the records of that name.

A publish request is answered once probing for the name is done, at most five
seconds later. The reply is `{ "result": "ok" }`, or `"duplicated"` when
another host or another owner already holds the name. The daemon does not
rename an entry that loses a conflict later: it withdraws it and sends a
`conflict` notification with `owner`, `kind` and `name`. Publishing the same
name again with changed data updates the records and announces them without
probing again (RFC 6762 Section 8.4). Malformed arguments fail with
`Invalid argument`, and a withdrawal by another owner with `Not found`.

## Subscriptions

`subscribe` with `service` browses a service type, with `service` and
`instance` resolves one instance, and with `host` follows the addresses of a
host. The daemon keeps a continuous query running for it and reports changes
to the subscribers of the `umdns` object as notifications:

- `service`: `service`, `instance`, `host`, `port`, `priority`, `weight`,
  `txt`, `txt_hex`, `addresses` (IPv6), `ipv4`, `ttl`, `iface`, `ifindex` and
  `removed`.
- `host`: `host`, `addresses`, `ipv4`, `ttl`, `iface`, `ifindex` and
  `removed`.

A result that goes away is reported once with `removed` set, its identity
fields and `ifindex`. Services and host names this host announces count as
results; they are reported on the first interface served.
The notifications go to every subscriber of the object, so a client tells its
results apart by the fields above.

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
