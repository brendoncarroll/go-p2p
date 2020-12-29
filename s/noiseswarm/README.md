# Noise Swarm
This is a `SecureSwarm` which can operate on top of any `Swarm`.

## Swarm
Addresses for this swarm are a (address key, peer id) pair.
The swarm manages creating new sessions for encryption, setting them up, and caching them, transparently to the user.
The swarm handles delivery of messages to the correct session.

# Sessions
There can be 0 to 2 sessions active for a given address, one inbound, and one outbound.
The swarm randomly selects a session if there are 2 ready for an address.
Sessions have a lifetime of about a minute after which they expire.
Sessions also have a message limit of a couple billion messages in either direction.
It is intended that sessions are created and destroyed frequently, there is only one handshake and no rekeying.
The session state machine straightforwardly moves to an end state, at which point all of the secret state is unreferenced.

Reducing worst case latency by always having a session around is possible, but is currently not implemented.
This would work by preemptively creating the outgoing session if the inbound session had recent activity.

## Cryptography
The Noise Protocol Framework is used with the NN key exchange to establish a secure channel.
The cipher suite is X25519, ChaCha20Poly1309, and BLAKE2b.
The first message through the channel from both parties is a serialized public key and signature of the channel binding.
The Sign and Verify functions provided by the `p2p` library are used to sign the channel.

## Wire Protocol
This protocol is comprised of messages consisting of a header, and then a message from the noise protocol framework.

The first 4 bytes are the header.
The header consists of 1 direction bit, which is:
0 when sending from intiator to responder
and 1 when sending from responder to initiator.

The following 31 bytes of header are interpretted as a counter in big endian format.

Certain low counter values are reserved for the handshake messages, and the rest are used as nonces for symmetric encryption.
The counter values are considered when noise calculates an authentication tag for a message.
The counter values are also used for replay protection.
The maximum counter value is considered a "closing" message.
