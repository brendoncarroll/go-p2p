package naclcell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
)

var _ p2p.Cell = &NaClCell{}

type NaClCell struct {
	cell       p2p.Cell
	privateKey ed25519.PrivateKey
}

func New(cell p2p.Cell, privKey ed25519.PrivateKey) *NaClCell {
	return &NaClCell{
		cell:       cell,
		privateKey: privKey,
	}
}

func (c *NaClCell) Get(ctx context.Context) ([]byte, error) {
	data, _, err := c.get(ctx)
	return data, err
}

func (c *NaClCell) get(ctx context.Context) (data []byte, ctext []byte, err error) {
	ctext, err = c.cell.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(ctext) == 0 {
		return nil, nil, nil
	}
	ptext, err := decrypt(ctext, c.privateKey)
	if err != nil {
		return nil, ctext, err
	}
	return ptext, ctext, nil
}

func (c *NaClCell) CAS(ctx context.Context, current, next []byte) (bool, []byte, error) {
	data, ctext, err := c.get(ctx)
	if err != nil {
		return false, nil, err
	}
	if bytes.Compare(data, current) != 0 {
		return false, data, nil
	}

	nextCtext := encrypt(next, c.privateKey)
	return c.cell.CAS(ctx, ctext, nextCtext)
}

func encrypt(ptext []byte, privKey ed25519.PrivateKey) []byte {
	nonce := [24]byte{}
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	secret := [32]byte{}
	copy(secret[:], privKey)

	signer := [64]byte{}
	copy(signer[:], privKey)

	ctext := secretbox.Seal(nonce[:], ptext, &nonce, &secret)
	signedCtext := sign.Sign([]byte{}, ctext, &signer)

	return signedCtext
}

func decrypt(ctext []byte, privKey ed25519.PrivateKey) ([]byte, error) {
	pubKey := [32]byte{}
	copy(pubKey[:], privKey.Public().(ed25519.PublicKey))

	signedCtext, success := sign.Open([]byte{}, ctext, &pubKey)
	if !success {
		return nil, errors.New("invalid signature")
	}

	l := len(signedCtext)
	if l <= secretbox.Overhead {
		return nil, errors.New("signedCtext is too small to contain a secret box")
	}

	nonce := [24]byte{}
	copy(nonce[:], signedCtext[:24])

	secret := [32]byte{}
	copy(secret[:], privKey)

	ptext, success := secretbox.Open([]byte{}, signedCtext[24:], &nonce, &secret)
	if !success {
		return nil, errors.New("secret box was invalid")
	}
	return ptext, nil
}
