package p2p

import (
	"bytes"
	"encoding/base64"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// PeerIDSize is the size of a PeerID in bytes
const PeerIDSize = 32

// PeerID is a identifier cryptographically related to a public key
type PeerID [32]byte

// Fingerprinter is the type of functions which create PeerIDs from PublicKeys
type Fingerprinter func(PublicKey) PeerID

// DefaultFingerprinter is a Fingerprinter
func DefaultFingerprinter(pubKey PublicKey) PeerID {
	data := MarshalPublicKey(pubKey)
	id := PeerID{}
	sha3.ShakeSum256(id[:], data)
	return id
}

func (pid PeerID) String() string {
	data, _ := pid.MarshalText()
	return string(data)
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

func (p PeerID) Compare(q PeerID) int {
	return bytes.Compare(p[:], q[:])
}

func (p PeerID) Lt(q PeerID) bool {
	return p.Compare(q) < 0
}

func (p PeerID) IsZero() bool {
	return p == (PeerID{})
}

type HasPeerID interface {
	Addr
	GetPeerID() PeerID
}

func ExtractPeerID(x Addr) PeerID {
	if hasPeerID, ok := x.(HasPeerID); ok {
		return hasPeerID.GetPeerID()
	}
	if unwrap, ok := x.(UnwrapAddr); ok {
		return ExtractPeerID(unwrap.Unwrap())
	}
	return PeerID{}
}
