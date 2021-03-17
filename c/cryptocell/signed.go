package cryptocell

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

var _ p2p.Cell = &Signed{}

type Signed struct {
	inner      p2p.Cell
	purpose    string
	publicKey  p2p.PublicKey
	privateKey p2p.PrivateKey
}

func NewSigned(inner p2p.Cell, purpose string, publicKey p2p.PublicKey, privateKey p2p.PrivateKey) *Signed {
	if publicKey == nil {
		panic("must specify public key")
	}
	if purpose == "" {
		panic("cannot use an empty purpose")
	}
	return &Signed{
		inner:      inner,
		purpose:    purpose,
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

func (s *Signed) CAS(ctx context.Context, prev, next []byte) (bool, []byte, error) {
	if s.privateKey == nil {
		return false, nil, errors.Errorf("cannot write to signing cell without private key")
	}
	payload, raw, err := s.get(ctx)
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(payload, prev) {
		return false, payload, nil
	}
	sig, err := p2p.Sign(s.privateKey, s.purpose, next)
	if err != nil {
		return false, nil, err
	}
	next2 := makeContents(next, sig)
	swapped, raw, err := s.inner.CAS(ctx, raw, next2)
	if err != nil {
		return false, nil, err
	}
	var actual []byte
	if len(raw) > 0 {
		actual, _, err = splitContents(raw)
		if err != nil {
			return false, nil, err
		}
	}
	return swapped, actual, nil
}

func (s *Signed) get(ctx context.Context) (payload, raw []byte, err error) {
	raw, err = s.inner.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 {
		return nil, nil, nil
	}
	payload, sig, err := splitContents(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := p2p.Verify(s.publicKey, s.purpose, payload, sig); err != nil {
		return nil, nil, err
	}
	return payload, raw, nil
}

func (s *Signed) Get(ctx context.Context) ([]byte, error) {
	payload, _, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func Validate(pubKey p2p.PublicKey, purpose string, contents []byte) error {
	payload, sig, err := splitContents(contents)
	if err != nil {
		return err
	}
	if err := p2p.Verify(pubKey, purpose, payload, sig); err != nil {
		return err
	}
	return nil
}

func makeContents(payload, sig []byte) []byte {
	contents := make([]byte, 4+len(payload)+len(sig))
	binary.BigEndian.PutUint32(contents[:4], uint32(len(payload)))
	copy(contents[4:4+len(payload)], payload)
	copy(contents[4+len(payload):], sig)
	return contents
}

func splitContents(raw []byte) (payload, sig []byte, err error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	if len(raw) < 4 {
		return nil, nil, errors.Errorf("data too short")
	}
	payloadLength := int(binary.BigEndian.Uint32(raw[:4]))
	if payloadLength+4 > len(raw) {
		return nil, nil, errors.Errorf("incorrect payload length=%d in buffer len=%d", payloadLength, len(raw))
	}
	payload = raw[4 : 4+payloadLength]
	sig = raw[4+payloadLength:]
	return payload, sig, nil
}
