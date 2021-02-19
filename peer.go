package p2p

import (
	"crypto/hmac"
	"encoding/base64"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type PeerID [32]byte

func ZeroPeerID() PeerID {
	return PeerID{}
}

func NewPeerID(pubKey PublicKey) PeerID {
	data := MarshalPublicKey(pubKey)
	id := PeerID{}
	sha3.ShakeSum256(id[:], data)
	return id
}

func (a PeerID) Equals(b PeerID) bool {
	return hmac.Equal(a[:], b[:])
}

func (pid PeerID) String() string {
	data, _ := pid.MarshalText()
	return string(data)
}

func (pid PeerID) Key() string {
	return string(pid[:])
}

func (pid PeerID) MarshalText() ([]byte, error) {
	enc := base64.RawURLEncoding
	data := make([]byte, enc.EncodedLen(len(pid)))
	enc.Encode(data, pid[:])
	return data, nil
}

func (pid *PeerID) UnmarshalText(data []byte) error {
	enc := base64.RawURLEncoding
	if len(data) != enc.EncodedLen(len(pid)) {
		return errors.New("data is wrong length")
	}
	enc.Decode(pid[:], data)
	return nil
}
