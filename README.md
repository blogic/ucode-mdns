# ucode-mdns

An mDNS responder and service browser for OpenWrt (RFC 6762, RFC 6763). It
replaces `umdns` and keeps its ubus object, UCI schema and `/etc/umdns` service
files.

A small C module (`src/`, built as `mdns.so`) handles sockets, netlink and the
packet codec. The protocol logic is ucode (`ucode/`); `ucode-mdns.uc` is the
entry point.

## Build and test

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build --output-on-failure

## Running

On OpenWrt, `/etc/init.d/umdns` starts the daemon under procd. Elsewhere:

    ucode -L /usr/lib/ucode -L '/usr/share/umdnsd/*.uc' /usr/share/umdnsd/ucode-mdns.uc

The `mdns.so` directory must be an absolute path.

Options:

| Option | Meaning |
|---|---|
| `--hostname LABEL` | replaces the configured host name |
| `--interface DEVICE` | serves one device without UCI or netifd; needs `--hostname` |
| `--socket PATH` | ubus socket, with `--interface` only |

`SIGHUP` reloads. `SIGTERM` or `SIGINT` sends goodbye packets and exits.

## Configuration

`/etc/config/umdns`:

    config umdns
        list network lan
        option ipv4 '1'
        option ipv6 '1'

| Option | Meaning |
|---|---|
| `network` | UCI networks to serve |
| `device` | raw device names |
| `hostname` | host name to claim, default the system host name |
| `ipv4`, `ipv6` | address families, default on |
| `debug`, `trace` | logging |

Apply a change with `/etc/init.d/umdns reload` or `ubus call umdns reload`.

## Announcing a service

A JSON file in `/etc/umdns/`:

    {
        "sshd": {
            "service": "_ssh._tcp.local",
            "port": 22,
            "txt": [ "daemon=dropbear" ]
        }
    }

Or the same object in the `mdns` data of a procd instance. `instance` defaults
to the host label; `hostname` defaults to the daemon host name.

## ubus

Object `umdns`:

| Method | Arguments |
|---|---|
| `hosts` | `array` |
| `browse` | `service`, `array`, `address` |
| `query` | `question`, `interface`, `type` |
| `fetch` | `question`, `type` |
| `reconfirm` | `question`, `interface`, `type` |
| `announcements`, `update`, `reload`, `stats` | none |
| `set_config` | `interfaces`, `keep` |

    ubus call umdns browse '{ "service": "_http._tcp", "array": true }'

Object `mdns.dnssd` lets a client such as threadd publish hosts, services and
KEY records on an interface, and watch cached records. The client publishes an
owner object with the methods `records`, `registration` and `interface`, then
calls `open` with its name and uses the returned token for `register`,
`unregister`, `watch`, `unwatch` and `close`. Events go to the owner object.
When it disappears, its records are withdrawn.

The live DNS-SD test needs root:

    python3 tests/check_dnssd.py --module-dir build --interface enp1s0 --address 192.168.42.9

## Licence

GPL-2.0-only, see `LICENSE.txt`.
