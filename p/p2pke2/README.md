# P2PKE

## Messages

P2PKE Handshake messages contain application data, and handshake data.
The P2PKE handshake information is always last in the message.

### 0. Init -> Resp
- InitKEMPub

### 1. Resp -> Init
- KEM_Encapsulate(InitKEMPub)
- AEAD_Seal(k1, Sign(RespSigPriv, shared) ++ RespKEMPub)

### 2. Init -> Resp
- AEAD_Seal(k2, Sign(InitSigPriv, shared))

### 3. Resp -> Init
- Done
