package cryptocell

import (
	"bytes"
	"context"
	"crypto/rand"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

var _ p2p.Cell = &SecretBoxCell{}

type SecretBoxCell struct {
	inner  p2p.Cell
	secret []byte
}

func NewSecretBox(inner p2p.Cell, secret []byte) *SecretBoxCell {
	return &SecretBoxCell{
		inner:  inner,
		secret: secret,
	}
}

func (c *SecretBoxCell) Get(ctx context.Context) ([]byte, error) {
	data, _, err := c.get(ctx)
	return data, err
}

func (c *SecretBoxCell) get(ctx context.Context) (data, ctext []byte, err error) {
	ctext, err = c.inner.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(ctext) == 0 {
		return nil, nil, nil
	}
	ptext, err := decrypt(ctext, c.secret)
	if err != nil {
		return nil, ctext, err
	}
	return ptext, ctext, nil
}

func (c *SecretBoxCell) CAS(ctx context.Context, prev, next []byte) (bool, []byte, error) {
	data, ctext, err := c.get(ctx)
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(data, prev) {
		return false, data, nil
	}
	nextCtext := encrypt(next, c.secret)
	swapped, actualCtext, err := c.inner.CAS(ctx, ctext, nextCtext)
	if err != nil {
		return false, nil, err
	}
	var actual []byte
	if len(actualCtext) > 0 {
		actual, err = decrypt(actualCtext, c.secret)
		if err != nil {
			return false, nil, err
		}
	}
	return swapped, actual, nil
}

func encrypt(ptext, secret []byte) []byte {
	nonce := [24]byte{}
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	s := [32]byte{}
	copy(s[:], secret)
	return secretbox.Seal(nonce[:], ptext, &nonce, &s)
}

func decrypt(ctext, secret []byte) ([]byte, error) {
	const nonceSize = 24
	if len(ctext) < nonceSize {
		return nil, errors.Errorf("secret box too short")
	}
	nonce := [nonceSize]byte{}
	copy(nonce[:], ctext[:nonceSize])
	s := [32]byte{}
	copy(s[:], secret)
	ptext, success := secretbox.Open([]byte{}, ctext[nonceSize:], &nonce, &s)
	if !success {
		return nil, errors.Errorf("secret box was invalid")
	}
	return ptext, nil
}
