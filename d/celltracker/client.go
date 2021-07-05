package celltracker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/url"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/c/cryptocell"
	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/httpcell"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const purposeCellTracker = "p2p/cell-tracker"

func GenerateToken(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	privateKey := derivePrivateKey(secret)
	id := p2p.NewPeerID(privateKey.Public())
	u.Path = "/" + base64.URLEncoding.EncodeToString(id[:])
	u.Fragment = base64.URLEncoding.EncodeToString(secret)
	return u.String()
}

type Client struct {
	url string

	cell cells.Cell
	*CellTracker
}

func NewClient(token string) (*Client, error) {
	u, err := url.Parse(token)
	if err != nil {
		return nil, err
	}
	secret, err := base64.URLEncoding.DecodeString(u.Fragment)
	if err != nil {
		return nil, err
	}
	u.Fragment = ""

	symmetricKey := deriveSymmetricKey(secret)
	privateKey := derivePrivateKey(secret)
	pubKeyBytes := p2p.MarshalPublicKey(privateKey.Public())

	var cell cells.Cell
	cell = httpcell.New(httpcell.Spec{
		URL: u.String(),
		Headers: map[string]string{
			SignerHeader: base64.URLEncoding.EncodeToString(pubKeyBytes),
		},
	})
	cell = cryptocell.NewSigned(cell, purposeCellTracker, privateKey.Public(), privateKey)
	cell = cryptocell.NewSecretBox(cell, symmetricKey)

	return &Client{
		url:         u.String(),
		cell:        cell,
		CellTracker: New(cell),
	}, nil
}

func deriveKey(secret []byte, purpose string, n int) []byte {
	r := hkdf.Expand(sha3.New256, secret, []byte(purpose))
	key := make([]byte, n)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(err)
	}
	return key
}

func derivePrivateKey(secret []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(deriveKey(secret, "ed25519-private-key", ed25519.SeedSize))
}

func deriveSymmetricKey(secret []byte) []byte {
	return deriveKey(secret, "secretbox-symmetric-key", 32)
}
