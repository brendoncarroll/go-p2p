package celltracker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/url"

	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/httpcell"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/c/secretboxcell"
	"github.com/brendoncarroll/go-p2p/c/signedcell"
	"github.com/brendoncarroll/go-p2p/crypto/sign"
	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
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
	var privateKey sig_ed25519.PrivateKey
	deriveKey(privateKey[:], secret, "ed25519-private")
	id := p2p.DefaultFingerprinter((ed25519.PrivateKey)(privateKey[:]).Public())
	u.Path = "/" + id.Base64String()
	u.Fragment = base64.URLEncoding.EncodeToString(secret)
	return u.String()
}

type Client struct {
	url string

	cell cells.Cell
	*CellTracker
}

func NewClient(token string) (*Client, error) {
	type (
		PrivateKey = sig_ed25519.PrivateKey
		PublicKey  = sig_ed25519.PublicKey
	)
	scheme := sign.WithPurpose[PrivateKey, PublicKey](sig_ed25519.Ed25519{}, purposeCellTracker)

	u, err := url.Parse(token)
	if err != nil {
		return nil, err
	}
	secret, err := base64.URLEncoding.DecodeString(u.Fragment)
	if err != nil {
		return nil, err
	}
	u.Fragment = ""

	var privateKey PrivateKey
	var symmetricKey [32]byte
	deriveKey(privateKey[:], secret, "ed25519-private")
	deriveKey(symmetricKey[:], secret, "secret-box")
	pubKey := scheme.DerivePublic(&privateKey)
	pubKeyBytes := p2p.MarshalPublicKey(ed25519.PublicKey(pubKey[:]))

	var cell cells.Cell
	cell = httpcell.New(httpcell.Spec{
		URL: u.String(),
		Headers: map[string]string{
			SignerHeader: base64.URLEncoding.EncodeToString(pubKeyBytes),
		},
	})
	cell = signedcell.New[PrivateKey, PublicKey](cell, scheme, &privateKey, []PublicKey{pubKey})
	cell = secretboxcell.New(cell, symmetricKey[:])

	return &Client{
		url:         u.String(),
		cell:        cell,
		CellTracker: New(cell),
	}, nil
}

func deriveKey(dst []byte, secret []byte, purpose string) {
	r := hkdf.Expand(sha3.New256, secret, []byte(purpose))
	if _, err := io.ReadFull(r, dst); err != nil {
		panic(err)
	}
}
