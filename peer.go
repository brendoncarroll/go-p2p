package p2p

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/sha3"
)

type PrivateKey = crypto.Signer

type PublicKey = crypto.PublicKey

func MarshalPublicKey(x PublicKey) []byte {
	data, err := x509.MarshalPKIXPublicKey(x)
	if err != nil {
		panic(err)
	}
	return data
}

func ParsePublicKey(data []byte) (PublicKey, error) {
	return x509.ParsePKIXPublicKey(data)
}

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
