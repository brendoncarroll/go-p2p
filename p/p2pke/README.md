# P2P Key Exchange

P2P Key Exchange is an authenticated key exchange built using the Noise Protocol Framework (NPF).
It depends on a message based transport beneath it, and provides security, and at-most-once delivery of messages to callers.
It makes no assumptions about the underlying transport, which can be anything that delivers datagrams larger than the per packet overhead.

## Goals
- Secure any message based transport without knowing anything about the underlying transport protocol.
This would make it useful on ethernet, IP, and UDP, as well as in overlay networks.
- Be Composable.  Layer well on top of protocols and beneath protocols.
Never assume the protocol is running on the bottom or top of the stack.
This means small headers, and minimal communication not explicitly directed by the layer above.
- Work with signing keys.
- Simple. Use private and public keys directly, no certificates.

## Compared to Other Protocols
|                    | P2PKE             | WireGuard       | QUIC                  | DTLS 1.2              |
|--------------------|-------------------|-----------------|-----------------------|-----------------------|
| Secure Datagrams   | ✅                | ✅              | ⚠️️ Draft Spec         | ✅                    |
| P2P                | ✅                | ✅              | ⚠️ Connection IDs     | ❌ Client/Server      |
| Transport Agnostic | ✅                | ❌ UDP          | ❌ UDP                | ❌ UDP                |
| PKI Complexity     | ✅  Public Keys   | ✅ Public Keys  | ❌ x509 Certificates  | ❌ x509 Certificates  |
| Algorithm Choice   | Signing Keys      | None            | Lots                  | Lots                  |

### Why not {DTLS, QUIC, WireGuard} instead?
- In practice, all of the mentioned protocols make assumptions about UDP being beneath them.
Even if the spec doesn't, the implementations usually do.
Wireguard for example, assumes it has access to the IP address and UDP port of incoming messages.
- QUIC and DTLS are client server, so Wireguard is really the only protocol designed for p2p communication.
QUIC does have connection IDs which solves the problem of both sides initiating connections simultaneously.
- QUIC doesn't provide a way to send Datagrams that doesn't assume it is running on UDP.
You can't send a datagram larger than the max UDP size, for example.
- QUIC and DTLS require x509 certificates which are complicated.  There are almost a dozen parameters that a user needs to understand
to create a self signed cert.
Contrast that with Wireguard which passes around base64 encoded public keys.

## Cryptography
P2PKE uses the Noise Protocol Framework's `NN Handshake` with the suite `(X25519, ChaCha20Poly1309, BLAKE2b)` to establish a secure channel.
The `channel binding` is signed using a long-lived public signing key to authenticate the connection. 
There is no way to configure the cryptography used to establish the secure session.

There is a choice of signing algorithm, a few types of signing key are supported.
P2PKE uses the `p2p.Sign` and `p2p.Verify` functions, which support RSA, DSA, and Ed25519 keys.
The signature scheme includes an extra layer of hashing with `CSHAKE256` which includes an application specific *purpose* tag.

## Wire Protocol
Sessions pass messages between one another consisting of a 4 byte header.
The header is a single 32 bit integer containing the counter used for the message.
The rest of the message is called the *body* herein.

Certain low counter values are reserved for the handshake messages, and the rest are used as nonces for symmetric encryption.
The counter values are considered when noise calculates an authentication tag for a message.
The counter values are also used for replay protection.

### Message Types

#### InitHello
This message has a counter value of 0.
The message body is an NPF handshake message containing a protocol buffer, and an appended 16 bit big endian integer which is the length of the protocol buffer data.
This makes it possible to parse an InitHello from the end of the message regardless of the size of the public key which noise has prepended.

The protocol buffer contains the initiators signing key, and a signature of a timestamp.

#### RespHello
This message has a counter value of 1.
The message body is an NPF handshake message containing a protocol buffer.

The protocol buffer contains the responders signing key, and a signature of the channel binding.

#### InitDone
This message has a counter value of 2.
The message body is an NPF symmetric message containing a protocol buffer.

The protocol buffer contains a signature of the channel binding from the initiator.

#### RespDone
This message has a counter value of 3.
The message body is an NPF symmetric message containing an empty payload.

#### Data
Data messages have counter values >= 16 and <= 2^32 - 2.
The non-counter portion is an NPF message containing application data.

## Sessions
A Session encapsulates the handshake state machine, the symmetric ciphers, outbound counter, and replay filter.
The idea is that you can just keep delivering messages to a session and it will either give you an error, or some data to send back, or data to deliver to the application.

The session has no internal timers or background goroutines.
It only knows what time it is based on what the caller tells it.
Sessions have a tree-like state machine, without any cycles, starting in an initial state and eventually expiring due to a handshake failure, or message count or time conditions.
Sessions have a short lifecycle.
They are bounded both by a maximum number of messages (2^32-2) and a maximum age (3 minutes).

### Handshake
The Session handshake state machine looks like this:
```
                INITIATOR                       RESPONDER
0   SendingInitHello/AwaitingRespHello          AwaitingInitHello
1                                               SendingResponseHello/AwaitingInitDone
2   SendingInitDone/AwaitingRespDone
3                                               HandshakeComplete
4   HandshakeComplete
```

In each of these states except HandshakeComplete, the sessions will respond to the preceeding handshake messages with the next handshake message, even if they have already done so.  This allows for retries.

The Initiator has authenticated the Responder after RespHello is received, but it cannot send until the Responder has authenticated it, or it risks having its messages dropped.
The Responder will not buffer messages which it cannot authenticate.
So the Initiator must wait until it receives application data or (more likely) the RespDone message.

The Responder has authenticated the Initiator after it has received the InitDone, but will respond to handshake messages until application data has been sent.

## Channels
Channels are a long lived secure channel between two parties.
Channels manage creating and discarding sessions as they expire.
Once a channel has established a session all future sessions must have the same remote key.

The Channel API:
```
    // NewChannel creates a channel, there is no distinction between initiator or responder
    NewChannel(ChannelConfig) *Channel
    // Send is used to send an encrypted message across the channel, it may need to create a session.
    Send(ctx context.Context, x []byte) error
    // Deliver is used to deliver inbound messages to the channel.
    Deliver(out, x []byte) ([]byte, error)
```

### Parameters (Required)
- `PrivateKey: PrivateKey` The signing key to use when authenticating the Channel.
- `Send: func([]byte)` A function which is called by the Channel to send data.
- `AcceptKey: func(PublicKey) bool` A function which determines whether to connect to a party identifying as a given public key.

## Versions
P2PKE is a versioned protocol; the InitHello message has a version field.
The version determines all the cryptographic parameters in the protocol.
There is no version negotiation.
The initiator dictates what protocol to use, and the responder can respond with an error if it does not support that protocol.
So if and when a version 2 shows up, peers will prefer version 2, but accept version 1, and then eventually reject version 1 completely.
