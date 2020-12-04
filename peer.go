package p2p

import (
	"bytes"
	"context"
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
	return sha3.Sum256(data)
}

func (a PeerID) Equals(b PeerID) bool {
	return bytes.Compare(a[:], b[:]) == 0
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

// LookupPublicKeyInHandler calls LookupPublicKey with
// an expired context, and panics on an error.  SecureSwarms must
// be able to return a PublicKey retrieved from memory, during the
// execution of an AskHandler or TellHandler.
// to lookup a public key outside a handler, use the swarms LookupPublicKey method
func LookupPublicKeyInHandler(s Secure, target Addr) PublicKey {
	ctx, cf := context.WithCancel(context.Background())
	cf()
	pubKey, err := s.LookupPublicKey(ctx, target)
	if err != nil {
		err = errors.Wrapf(err, "swarms must provide public key during callback")
		panic(err)
	}
	if pubKey == nil {
		panic("swarms must provide public key during callback. got nil")
	}
	return pubKey
}
