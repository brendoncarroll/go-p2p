# P2P
A Library for writing Peer-to-Peer applications.

Many peer-to-peer libraries go to great lengths to provide a reliable stream abstraction over as many different transports as possible.
That makes them unsuitable for modeling protocols over lossy mediums (UDP, IP, ethernet).
This library takes a message oriented approach instead of a stream oriented approach.

Unreliable, fire-and-forget communication is provided using `Tell` and `Receive` methods.
Reliable request-response communication is provided using `Ask` and `ServeAsk` methods.

The core abstraction is the `Swarm`. Which represents a group of nodes which can send messages to one another.

```
type Swarm[A Addr] interface {
    Tell(ctx context.Context, dst A, data []byte) error
    Receive(ctx context.Context, fn func(Message[A])) error

    ParseAddr(data []byte) (A, error)
    LocalAddrs() []A
    MTU(A) int
    Close() error
}
```
`Addr` is an interface type.

Overlay networks are a common pattern in p2p systems.
Swarms have methods for introspection such as `LocalAddrs` and `MTU`.
`Addrs` also have a canonical serialization provided by `MarshalText` and `ParseAddr`
These two features make Swarms the building blocks for higher order swarms, which can be overlay networks.
The underlying swarm is often referred to as the `transport` throughout these packages.

The power of the `Swarm` abstraction is exemplified by the fact we merely call some `Swarms` "transports" in certain contexts rather than having a separate Transport type, as other libraries do.

`Swarms` provide a `Tell` method, which makes a best effort to send the message payload to the destination.
It will error if the message cannot be set in flight, but does not guarantee the transmision of the message if the error is nil.

## Directory Organization


### D is for Discovery
Services for discovering peers.

- **Cell Tracker**
A tracker for announcing and looking up peer addresses.
Works on top of any cell.
A default client and server implementation are provided.

### F is for Formats
Formats are just protocols that send/write once and receive/read many times.

- **x509**
Deals with the formats in the x509 public key infrastructure.


### S is for Swarm

- **In-Memory Swarm**
A swarm which transfers data to other swarms in memory. Useful for testing.

- **Multi Swarm**
Creates a multiplexed addressed space using names given to each subswarm.
Applications can use this to "future-proof" their transport layer.

- **P2PKE Swarm**
A Secure Swarm which can secure any underlying Swarm.

- **QUIC Swarm**
A secure swarm supporting `Asks` built on the QUIC protocol.
It can wrap any other `p2p.Swarm`, and provide a `p2p.SecureAskSwarm`

- **SSH Swarm**
A secure swarm supporting `Asks` built on the SSH protocol (TCP based).

- **UDP Swarm**
An insecure swarm, included mainly as a building block.

- **Fragmenting Swarm**
A higher order swarm which increases the MTU of an underlying swarm by breaking apart messages,
and assembling them on the other side.

The `swarmutil` package contains utilities for writing `Swarms`.
The `swarmtest` package contains a test suite which checks that a given Swarm implementation exhibits all the behaviors expected.

### P is for Protocols

- **Chord**
A package for the Chord DHT algorithm.

- **Kademlia**
A package for the Kademlia DHT algorithm.

- **Multiplexing**
Multiplexing creates multiple logical swarms on top of a single swarm.
The `p2pmux` package provides string and integer multiplexers.

- **P2PKE**
P2PKE is an authenticated key exchange suitable for securing `p2p.Swarms`.
Provides a session state machine, and a long-lived secure channel, which is used by `s/p2pkeswarm`

## Test Utilities
The `p2ptest` packages contains utilities for testing, such as generating adjacency matricies for networks of various connectivities.
