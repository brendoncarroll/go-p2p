# P2P
A Library for writing Peer-to-Peer applications.

It seems most peer-to-peer libraries go to great lengths to provide a reliable stream abstraction over as many different transports as possible.
This makes them unsuitable for building protocols over lossy mediums (UDP, IP, ethernet).

It is also the wrong abstraction for the job.  Almost no protocols are actually stream based.
Reliable streams are just used to create reliable request-response abstractions in most cases.
Many protocols are built on reliable request-response abstractions.
It is a valuable primitive to have.

This library takes a message based approach instead of a stream based approach.
Messages can either be unreliable, or reliable and (therefore) require a response.
These two kinds of communication are represented by the `Tell` and `Ask` methods respectively.

## Design
The core abstraction is the `Swarm`. Which represents a group of nodes which can send messages to one another.

```
type Swarm interface {
    Tell(addr Addr, data []byte) error
    OnTell(TellHandler)

    LocalAddrs() []Addr
    MTU(Addr) int
    Close() error
}
```
`Addr` is an interface type.
`p2p.Addr` must marshal/unmarshal to/from a text format.

Swarms each define their own Addr type, and should panic if a caller tries to send a message to an address of another type.
In other languages Swarms might be defined as a generic type.
```
type Swarm[A] {
    Tell(addr: A, data: []byte) error
    LocalAddrs() []A
    ...
}
```

Overlay networks are a common pattern in p2p systems.
Swarms have methods for introspection such as `LocalAddrs` and `MTU`.
`Addrs` also have a canonical serialization procided by `MarshalText` and `UnmarshalText`.
These two features make Swarms the building blocks for higher order swarms, which can be overlay networks.
The underlying swarm is often referred to as the `transport` throughout these packages.

The power of the `Swarm` abstraction is exemplified by the fact we merely call some `Swarms` "transports" in certain contexts rather than having a separate Transport type, as other libraries do.

`Swarms` provide a `Tell` method, which makes a best effort to send the message payload to the destination.
It will error if the message cannot be set in flight, but does not guarantee the transmision of the message if the error is nil.

The interface ends up resembling a hybrid between the server in `http` and the `PacketConn` interface from `net`

## Directory Organization 
### S is for Swarm
- **UDP Swarm**
An insecure swarm, included mainly as a building block.

- **SSH Swarm**
A secure swarm supporting `Asks` built on the SSH protocol (TCP based).

- **QUIC Swarm**
A secure swarm supporting `Asks` built on the QUIC protocol (UDP based).

- **Aggregating Swarm**
Aggregates messages from multiple transport swarms by the public key that sent them.
Assigns indexes to each new `(swarm, address)` pair that is encountered.

- **In-Memory Swarm**
A swarm which transfers data to other swarms in memory. Useful for testing.

- **NAT Swarm**
Creates and manages NAT mappings for addresses behind a IPv4 router using NAT.
Applies the mappings to values returned from `LocalAddr`


Routers for distributed routing protocols like CJDNS, or Yggdrasil would be next on the wishlist.

### P is for Protocols

The utility of this library is determined entirely by how easily well-known p2p algorithms can be built and composed using it's primitives.

- **Kademlia**
A package with a DHT, overlay network, and cache is in the works.  Right now a cache that evicts keys distant in XOR space is available.

- **Simple Multiplexing**
A service which multiplexes multiple logical swarms, over the same underlying transport swarm.

### D is for Discovery
Services for discovering peers.

## PKI
A `PeerID` type is provided to be used as the hash of public keys, for identifying peers.
Canonical serialization functions are provided for public keys (just `x509.MarshalPKIXPublicKey`).

## Test Utilities
The `p2ptest` packages contains utilities for testing, such as generating adjacency matricies for networks of various connectivities.
