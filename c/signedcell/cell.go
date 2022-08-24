// signedcell provides a Cell with contents authenticated by a signing algorithm.
// Anyone with access to the Cell can determine if the contents are valid as long as they have the set of allowed public keys
package signedcell

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/brendoncarroll/go-p2p/crypto/sign"
	"github.com/brendoncarroll/go-state/cells"
	"github.com/pkg/errors"
)

var _ cells.Cell = &Cell[struct{}, struct{}]{}

type Cell[Private, Public any] struct {
	inner      cells.Cell
	scheme     sign.Scheme[Private, Public]
	privateKey *Private
	pubs       []Public
}

func New[Private, Public any](inner cells.Cell, scheme sign.Scheme[Private, Public], priv *Private, pubs []Public) *Cell[Private, Public] {
	return &Cell[Private, Public]{
		inner:      inner,
		scheme:     scheme,
		privateKey: priv,
		pubs:       pubs,
	}
}

func (s *Cell[Private, Public]) CAS(ctx context.Context, actual, prev, next []byte) (bool, int, error) {
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
	n = s.wrap(buf, next)
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

func (s *Cell[Private, Public]) Read(ctx context.Context, buf []byte) (int, error) {
	buf2, err := cells.GetBytes(ctx, s.inner)
	if err != nil {
		return 0, err
	}
	if len(buf) < len(buf2)-s.Overhead() {
		return 0, io.ErrShortBuffer
	}
	return s.unwrap(buf, buf2)
}

func (s *Cell[Private, Public]) MaxSize() int {
	return s.inner.MaxSize() - s.Overhead()
}

func (s *Cell[Private, Public]) Overhead() int {
	return s.scheme.SignatureSize()
}

func (s *Cell[Private, Public]) wrap(dst, x []byte) int {
	if len(dst) < len(x)+s.Overhead() {
		panic(fmt.Sprintf("dst too short len=%d", len(dst)))
	}
	sigSize := s.scheme.SignatureSize()
	n := copy(dst, x)
	s.scheme.Sign(dst[n:n+sigSize], s.privateKey, x)
	return n + sigSize
}

func (s *Cell[Private, Public]) unwrap(dst, x []byte) (int, error) {
	if len(x) == 0 {
		return 0, nil
	}
	payload, sig, err := splitContents(s.scheme.SignatureSize(), x)
	if err != nil {
		return 0, err
	}
	if len(dst) < len(payload) {
		return 0, io.ErrShortBuffer
	}
	var countVerified int
	for _, pub := range s.pubs {
		if s.scheme.Verify(&pub, payload, sig) {
			countVerified++
		}
	}
	if countVerified > 0 {
		return copy(dst, payload), nil
	}
	return 0, errors.New("signedcell: invalid signature")
}

func Validate[Private, Public any](scheme sign.Scheme[Private, Public], pubKey *Public, contents []byte) error {
	if len(contents) == 0 {
		return nil
	}
	payload, sig, err := splitContents(scheme.SignatureSize(), contents)
	if err != nil {
		return err
	}
	if !scheme.Verify(pubKey, payload, sig) {
		return errors.New("signedcell: invalid signature")
	}
	return nil
}

func splitContents(sigSize int, raw []byte) (payload, sig []byte, err error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	if len(raw) < sigSize {
		return nil, nil, fmt.Errorf("signedcell: too small to contain signature len=%d sig_size=%d", len(raw), sigSize)
	}
	splitAt := len(raw) - sigSize
	return raw[:splitAt], raw[splitAt:], nil
}
