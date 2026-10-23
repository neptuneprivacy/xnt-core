# Network Stack

`xnt-core` reaches its peers over two network stacks that run side by side:

- the **legacy stack**, plain TCP, which every version of `xnt-core` speaks;
- the **libp2p stack**, with QUIC and TCP transports, which newer versions
  speak in addition.

Both stacks carry the same peer protocol, in the same encoding, and lead into
the same peer loop. A peer counts once, whichever stack it is connected over,
and the limits on peers apply across both stacks.

## Ports

| Stack  | Transport            | Default port | Option         |
|--------|----------------------|--------------|----------------|
| legacy | TCP                  | 9898/tcp     | `--peer-port`  |
| libp2p | QUIC                 | 9901/udp     | `--quic-port`  |
| libp2p | TCP (TLS or Noise)   | 9902/tcp     | `--tcp-port`   |

All three listen on the address given with `--peer-listen-addr`, which is `::`
by default. With `::`, the legacy stack accepts IPv4 and IPv6 on one socket,
and the libp2p stack listens on both `0.0.0.0` and `::`. With any other
address, such as `0.0.0.0` or `127.0.0.1`, the libp2p stack listens on that
address only.

With `--max-num-peers 0`, the node accepts no incoming connections on either
stack.

### Firewalls

For other nodes to connect to this node, open these ports for incoming
traffic:

- 9898/tcp, for older nodes and for nodes that run the legacy stack only;
- 9901/udp, for QUIC;
- 9902/tcp, for libp2p over TCP.

The node asks the router for port mappings through UPnP, and finds out through
AutoNAT whether it is reachable from the outside. A node that is not reachable
holds reservations on relays, through which other nodes can contact it and
then connect directly (hole punching). Peer loops run over direct connections
only, never over relayed ones. If the node is reachable at a known public IP
address, give it with `--public-ip`; AutoNAT is then not needed.

The node offers relay reservations to other nodes by default. Turn this off
with `--disable-relay-server`.

## Peers given with `--peer`

`--peer` accepts `ip:port`, a bare IP address, or a multiaddress. The syntax
decides which stack dials the peer, with the default libp2p ports as the
exception:

| Input                                              | Stack, address dialed                       |
|----------------------------------------------------|---------------------------------------------|
| `ip:port`, port other than 9901 and 9902           | legacy, `ip:port`                           |
| `ip:9902`                                          | libp2p, `/ip4/<ip>/tcp/9902`                |
| `ip:9901`                                          | libp2p, `/ip4/<ip>/udp/9901/quic-v1`        |
| bare IP, or a multiaddress naming only an IP       | both: legacy on 9898, libp2p QUIC on 9901   |
| `/ip4/<ip>/tcp/9898` (or `/ip6/...`)               | legacy                                      |
| other multiaddress with `/tcp/<port>`              | libp2p TCP                                  |
| multiaddress with `/quic-v1` or `/p2p/<peer id>`   | libp2p                                      |

The ports compared against are the defaults above, not the ports this node is
configured with. A multiaddress ending in `/p2p/<peer id>` only connects to the
peer with that identity. Multiaddresses that name a host by DNS name (`/dns`,
`/dns4`, `/dns6`, `/dnsaddr`) are refused, because the DNS transport of libp2p
is not compiled in; give an IP address instead.

The node redials a peer given with `--peer` when its connection is lost. A
peer that cannot be reached, or that closes the connection again within five
minutes, is redialed with exponential back-off, up to once an hour. A peer
whose IP address is banned is not redialed until the ban is lifted.

With `--restrict-peers-to-list`, the node connects only with the IP addresses
of the `--peer` entries, on both stacks, and the libp2p stack does not look
for other peers.

## Moving a peer to QUIC

A peer given as `--peer 1.2.3.4:9898` is reached over the legacy stack. To
reach it over QUIC instead, give one of:

```text
--peer /ip4/1.2.3.4/udp/9901/quic-v1
--peer 1.2.3.4:9901
```

To try both stacks, give the bare IP address, `--peer 1.2.3.4`. If a peer is
reachable over both stacks, the first connection carries the peer loop, and
the second one is refused as a duplicate of the same node.

A running node can be asked to dial a peer over libp2p with `xnt-cli dial`;
see below.

## Identity

On the libp2p stack, a node is known by its peer ID, which derives from a key
pair. The key is kept in `<data-dir>/network/identity.key`, created on the
first start, readable and writable by its owner only. It identifies the node
on the network only; it holds no funds.

- `--identity-file <FILE>` uses the key in another file.
- `--new-identity` creates a new key, and keeps the previous file as a backup
  named `identity.<timestamp>.bak`.

If the identity file cannot be read, or the libp2p stack cannot be set up, the
node logs an error and starts without the libp2p stack. The identity file is
left as it is.

The same directory holds `address-book.json`, the libp2p peers the node has
seen, and `blacklist.json`, the IP addresses refused on the libp2p stack. Both
files are replaced atomically when written. Older versions of `xnt-core`
ignore the directory.

## Bans and standings

Peer standings are kept per IP address, in the same database as before, and
both stacks go by them. An IPv4 address and its IPv4-mapped IPv6 form, such as
`1.2.3.4` and `::ffff:1.2.3.4`, count as one address throughout: for
standings, bans, `--ban`, `--peer`, and the limit on connections per IP
address. Peers that connect over IPv4 are listed as `1.2.3.4:port`.

A ban refuses an IP address on both stacks and closes the connections from it.
Bans expire after 48 hours, except those given with `--ban`, which last as
long as the node runs.

The libp2p stack also limits inbound connections per address prefix (/24 for
IPv4, /64 for IPv6, `--max-connections-per-prefix`, 8 by default) and the
connection attempts per IP address and minute
(`--max-connection-attempts-per-ip-per-minute`, 6 by default).

## Commands

`xnt-cli` has these commands for the network stacks:

| Command                                | Effect                                                                                                    |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `ban <address>...`                     | Give the IP addresses a bad standing, disconnect their peers, and refuse them on both stacks.              |
| `unban <address>...`                   | Clear the standings of the IP addresses and lift their bans on both stacks.                                |
| `unban --all`                          | Clear all standings and lift all bans.                                                                     |
| `dial <multiaddress>`                  | Dial a peer over libp2p, e.g. `/ip4/1.2.3.4/udp/9901/quic-v1`. Clears a bad standing of its IP address.  |
| `network-overview`                     | Show the peer ID, NAT status, reachability, connections, relay reservations, and external addresses.       |
| `probe-nat`                            | Check now whether the node is reachable from the outside; the outcome shows in `network-overview`.        |
| `reset-relay-reservations`             | Drop the relay reservations and make new ones.                                                             |
| `clear-standing-by-ip <ip>`            | As `unban`, for one IP address.                                                                            |
| `clear-all-standings`                  | As `unban --all`.                                                                                          |

The addresses for `ban` and `unban` are IP addresses, `ip:port`, or
multiaddresses that name an IP address; only the IP address counts. Bans given
with `--ban` stand. After `unban`, `dial`, `clear-standing-by-ip`, and
`clear-all-standings`, the peers at the IP addresses concerned can reconnect at
once: neither the reconnect cooldown (`--reconnect-cooldown`) nor their earlier
connection attempts hold them back.

`dial`, `probe-nat`, and `reset-relay-reservations` fail if the libp2p stack
does not run, and `network-overview` says so.

## Running without libp2p

`--disable-libp2p` turns the libp2p stack off; the node then uses the legacy
stack only. Every `ip:port` given with `--peer` is dialed over the legacy
stack, whatever its port. `--peer` entries that only libp2p can reach are not
dialed, and the node logs a warning for each of them at startup. The same
holds for builds without the `libp2p` cargo feature.

If the libp2p stack stops while the node runs, the node logs an error and
continues with the legacy stack.

## Compatibility with older nodes

The legacy stack is unchanged on the wire. Older nodes and newer nodes connect
to each other over it, in either direction, on port 9898. Peer lists exchanged
between nodes name legacy addresses only, so older nodes are only ever given
addresses they can dial.

The RPC interface keeps its existing methods; the new ones are added after
them. An older `xnt-cli` or `xnt-dashboard` works with a newer node. A newer
`xnt-cli` reports that an older node does not support the new commands, and a
newer `xnt-dashboard` shows `-` for the libp2p line when connected to an older
node.
