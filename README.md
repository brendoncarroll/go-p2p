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
    Tell(ctx context.Context, dst Addr, data []byte) error
    Recv(ctx context.Context, src, dst, *Addr, buf []byte) (int, error)

    ParseAddr(data []byte) (Addr, error)
    LocalAddrs() []Addr
    MTU(Addr) int
    Close() error
}
```
`Addr` is an interface type.

Swarms each define their own Addr type, and should panic if a caller tries to send a message to an address of another type.
In other languages Swarms might be defined as a generic type.
```
type Swarm[A: Addr] {
    Tell(addr: A, data: []byte) error
    LocalAddrs() []A
    ...
}
```

Overlay networks are a common pattern in p2p systems.
Swarms have methods for introspection such as `LocalAddrs` and `MTU`.
`Addrs` also have a canonical serialization provided by `MarshalText` and `ParseAddr`
These two features make Swarms the building blocks for higher order swarms, which can be overlay networks.
The underlying swarm is often referred to as the `transport` throughout these packages.

The power of the `Swarm` abstraction is exemplified by the fact we merely call some `Swarms` "transports" in certain contexts rather than having a separate Transport type, as other libraries do.

`Swarms` provide a `Tell` method, which makes a best effort to send the message payload to the destination.
It will error if the message cannot be set in flight, but does not guarantee the transmision of the message if the error is nil.

The interface ends up resembling a hybrid between the server in `http` and the `PacketConn` interface from `net`

## Directory Organization 

### C is for Cell
Compare-and-swap cells are a synchronization primitive.
Cells are useful for modeling shared state that can change.

- **Signed Cell**
A cell which signs and verifies it's contents using the `p2p.Sign` and `p2p.Verify` functions

### D is for Discovery
Services for discovering peers.

- **Cell Tracker**
A tracker for announcing and looking up peer addresses.
Works on top of any cell.
A default client and server implementation are provided.

### S is for Swarm

- **In-Memory Swarm**
A swarm which transfers data to other swarms in memory. Useful for testing.

- **Multi Swarm**
Creates a multiplexed addressed space using names given to each subswarm.
Applications can use this to "future-proof" their transport layer.

- **Peer Swarm**
A swarm that uses PeerIDs as addresses.
It requires an underlying swarm, and a function that maps PeerIDs to addresses.

- **QUIC Swarm**
A secure swarm supporting `Asks` built on the QUIC protocol.
It can wrap any other `p2p.Swarm`, and provide a `p2p.SecureAskSwarm`

- **SSH Swarm**
A secure swarm supporting `Asks` built on the SSH protocol (TCP based).

- **UDP Swarm**
An insecure swarm, included mainly as a building block.

- **UPnP Swarm**
Creates and manages NAT mappings for addresses behind a IPv4 with a NAT table, using UPnP.
Applies the mappings to values returned from `LocalAddr`

- **Fragmenting Swarm**
A higher order swarm which increases the MTU of an underlying swarm by breaking apart messages,
and assembling them on the other side.

The `swarmutil` package contains utilities for writing `Swarms` and a test suite to make sure it exhibits all the behaviors expected.

### P is for Protocols

The utility of this library is determined entirely by how easily well-known p2p algorithms can be built and composed using it's primitives.

- **Kademlia**
A package with a DHT, overlay network, and cache is in the works.  Right now a cache that evicts keys distant in XOR space is available.

- **Multiplexing**
Multiplexing creates multiple logical swarms on top of a single swarm.
The `p2pmux` package provides string and integer multiplexers.

## PKI
A `PeerID` type is provided to be used as the hash of public keys, for identifying peers.
Canonical serialization functions are provided for public keys (just `x509.MarshalPKIXPublicKey`).

The `Sign` and `Verify` methods provided allow for keys to sign in multiple protocols without the risk of signature collisions.

## Test Utilities
The `p2ptest` packages contains utilities for testing, such as generating adjacency matricies for networks of various connectivities.
