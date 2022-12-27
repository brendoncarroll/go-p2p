# P2PKE

## Messages

P2PKE Handshake messages contain application data, and handshake data.
The P2PKE handshake information is always last in the message.

### 0. Init -> Resp
```
- InitKEMPub
- Proof(Init_Static_ID, proof_target)
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

