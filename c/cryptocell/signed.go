package cryptocell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"io"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-state/cells"
	"github.com/pkg/errors"
)

const overhead = ed25519.SignatureSize + 4

var _ cells.Cell = &Signed{}

type Signed struct {
	inner      cells.Cell
	purpose    string
	publicKey  p2p.PublicKey
	privateKey p2p.PrivateKey
}

func NewSigned(inner cells.Cell, purpose string, publicKey p2p.PublicKey, privateKey p2p.PrivateKey) *Signed {
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

func (s *Signed) CAS(ctx context.Context, actual, prev, next []byte) (bool, int, error) {
	if len(next) > s.MaxSize() {
		return false, 0, cells.ErrTooLarge{}
	}
	if s.privateKey == nil {
		return false, 0, errors.Errorf("cannot write to signing cell without private key")
	}
	actual2, err := cells.GetBytes(ctx, s.inner)
	if err != nil {
		return false, 0, err
	}
	n, err := s.unwrap(actual, actual2)
	if err != nil {
		return false, 0, err
	}
	if !bytes.Equal(actual[:n], prev) {
		return false, n, nil
	}
	buf := make([]byte, s.inner.MaxSize())
	n, err = s.wrap(buf, next)
	if err != nil {
		return false, 0, nil
	}
	next2 := buf[:n]
	swapped, n, err := s.inner.CAS(ctx, buf, actual2, next2)
	if err != nil {
		return false, 0, err
	}
	if n > 0 {
		n, err = s.unwrap(actual, buf[:n])
		if err != nil {
			return false, 0, err
		}
	}
	return swapped, n, nil
}

func (s *Signed) Read(ctx context.Context, buf []byte) (int, error) {
	buf2, err := cells.GetBytes(ctx, s.inner)
	if err != nil {
		return 0, err
	}
	if len(buf) < len(buf2)-overhead {
		return 0, io.ErrShortBuffer
	}
	return s.unwrap(buf, buf2)
}

func (s *Signed) MaxSize() int {
	return s.inner.MaxSize() - overhead
}

func (s *Signed) wrap(dst, x []byte) (int, error) {
	if len(dst) < len(x)+overhead {
		return 0, nil
	}
	sig, err := p2p.Sign(s.privateKey, s.purpose, x)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint32(dst[:4], uint32(len(x)))
	copy(dst[4:], x)
	copy(dst[4+len(x):], sig)
	return len(x) + overhead, nil
}

func (s *Signed) unwrap(dst, x []byte) (int, error) {
	if len(x) == 0 {
		return 0, nil
	}
	payload, sig, err := splitContents(x)
	if err != nil {
		return 0, err
	}
	if len(dst) < len(payload) {
		return 0, io.ErrShortBuffer
	}
	if err := p2p.Verify(s.publicKey, s.purpose, payload, sig); err != nil {
		return 0, err
	}
	return copy(dst, payload), nil
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
