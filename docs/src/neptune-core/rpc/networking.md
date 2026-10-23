# Networking RPC

Information about the libp2p network stack (QUIC on 9901/udp, libp2p over TCP
on 9902/tcp), which runs next to the legacy TCP peer stack (9898/tcp).

The namespace is off by default. Enable it with `--rpc-modules`, e.g.
`--rpc-modules Node,Chain,Networking`. The node logs a warning if it is enabled
without `--unsafe-rpc`, because the overview includes the node's peer ID and
external addresses.

Banning, unbanning and dialing peers are not available over JSON-RPC; use
`xnt-cli` (`ban`, `unban`, `dial`, `probe-nat`, `reset-relay-reservations`).

---

## networking_networkOverview

Returns an overview of the libp2p network stack.

**Parameters**

None

**Returns**

`networkOverview` - object, or null if the libp2p network stack does not run on
this node (built without libp2p, or started with `--disable-libp2p`):

- `peerId` - string, the node's libp2p peer ID
- `natStatus` - string, `unknown`, `private`, or `public(<multiaddress>)`
- `reachabilityState` - string, the node's view of its reachability
- `externalAddresses` - array of strings, multiaddresses at which the node
  believes it can be reached
- `connectionCount` - number, peers connected over libp2p
- `connectionLimit` - number, maximum number of peers
- `numActiveRelays` - number, relay reservations held
- `addressBookSize` - number, peers in the address book
- `numBannedPeers` - number, IP addresses on the libp2p ban list

**Example**

```
// Request
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"networking_networkOverview","params":[],"id":1}'

// Result
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "networkOverview": {
      "addressBookSize": 0,
      "connectionCount": 1,
      "connectionLimit": 10,
      "externalAddresses": [],
      "natStatus": "unknown",
      "numActiveRelays": 0,
      "numBannedPeers": 0,
      "peerId": "12D3KooWB5AMHdJ73otBNupRekRZRCzEq1gvb5SJcr6XrUvJbRKB",
      "reachabilityState": "unknown"
    }
  }
}
```
