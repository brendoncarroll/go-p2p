package celltracker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/url"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/c/httpcell"
	"github.com/brendoncarroll/go-p2p/c/naclcell"
	"github.com/pkg/errors"
)

func GenerateToken(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		panic(err)
	}

	id := p2p.NewPeerID(pubKey)
	u.Path = "/" + base64.URLEncoding.EncodeToString(id[:])
	u.Fragment = base64.URLEncoding.EncodeToString(privKeyBytes)

	return u.String()
}

type Client struct {
	url string

	p2p.Cell
	*CellTracker
}

func NewClient(token string) (*Client, error) {
	u, err := url.Parse(token)
	if err != nil {
		return nil, err
	}
	keyBytes, err := base64.URLEncoding.DecodeString(u.Fragment)
	if err != nil {
		return nil, err
	}
	u.Fragment = ""
	privKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("only ed25519 keys supported")
	}
	pubKeyBytes := p2p.MarshalPublicKey(privateKey.Public())

	cell := naclcell.New(
		httpcell.New(httpcell.Spec{
			URL: u.String(),
			Headers: map[string]string{
				SignerHeader: base64.URLEncoding.EncodeToString(pubKeyBytes),
			},
		}),
		privateKey,
	)

	return &Client{
		url:         u.String(),
		Cell:        cell,
		CellTracker: New(cell),
	}, nil
}
