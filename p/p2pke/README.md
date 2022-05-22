# P2P Key Exchange

P2P Key Exchange is an authenticated key exchange built using the Noise Protocol Framework (NPF).
It requires a message based transport to deliver messages between sessions.

## Sessions
Sessions have a short lifecycle.
They are bounded both by a maximum number of messages (2^31-1) and a maximum age (1 minute).

### Handshake
The Session handshake state machine looks like this:
```
                INITIATOR                       RESPONDER
0   SendingInitHello/AwaitingRespHello          AwaitingInitHello
1                                               SendingResponseHello/AwaitingInitDone
2   SendingInitDone/AwaitingFirstMessage
3                                               HandshakeComplete
4   HandshakeComplete
```

In each of these states except HandshakeComplete, the sessions will respond to handshake messages with the next handshake message.

The Responder is ready to send after it has received the InitDone, and will no longer send handshake messages.
The Initiator is ready to send after it has sent the InitDone, but will still respond to handshake messages until it has received channel data from the responder.

## Channels
Channels are a secure channel between two parties.
Channels manage creating and recreating sessions as they expire.
Once a channel has created a session all further sessions must have the same remote key.

## Wire Format
This protocol is comprised of messages consisting of a header, and then a message from the noise protocol framework.

The first 4 bytes are the header. The header consists of 1 direction bit, which is: 0 when sending from intiator to responder and 1 when sending from responder to initiator.

The following 31 bytes of header are interpretted as a counter in big endian format.

Certain low counter values are reserved for the handshake messages, and the rest are used as nonces for symmetric encryption. The counter values are considered when noise calculates an authentication tag for a message. The counter values are also used for replay protection. The maximum counter value is considered a "closing" message.
