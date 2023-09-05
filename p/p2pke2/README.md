# P2P Key Exchange
P2PKE is an Authenticated Key Exchange using KEMs for confidentiality and Proof/Verification provided by the caller for authenticity.

## Messages

P2PKE messages contain application data or handshake data.

```
0 Init -> Resp
KEMPub

1 Resp -> Init
Cookie
KEMCtext

2 Init -> Resp
Cookie
AEAD
    Proof

3 Resp -> Init
    Proof

4 Init -> Resp

```

### 0. Init -> Resp
```
- InitKEMPub
```

### 1. Resp -> Init
```
- KEM_Encapsulate(InitKEMPub)
- AEAD_Seal(k1,
    Proof(Init_Static_ID, proof_target)
)
```

### 2. Init -> Resp
```
- AEAD_Seal(k2,
    Proof(Resp_Static_ID, proof_target)
)
```

### 3. Resp -> Init
```
- AEAD_Seal(k3, "")
```

## User Considerations

### Keep Alive
P2PKE does not attempt to keep the `Channel` ready pre-emptively.
Handshake messages are sent reactively to incoming handshake messages, or during a call to `Send`.  That's it, never in the background.

During a call to `Send` a `Channel` may additionally send a handshake message for a new session, when a current one already exists.
This is to asynchronously pay the latency cost of establishing the next session.

For some applications, the overhead of establishing a new handshake may not be significant.
Using the empty message as a keep alive can work, or it can be another type of message in the application's protocol.

