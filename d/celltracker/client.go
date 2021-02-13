package celltracker

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/c/httpcell"
	"github.com/brendoncarroll/go-p2p/c/naclcell"
)

func GenerateToken(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	cell := naclcell.New(nil, secret)
	id := p2p.NewPeerID(cell.PublicKey())
	u.Path = "/" + base64.URLEncoding.EncodeToString(id[:])
	u.Fragment = base64.URLEncoding.EncodeToString(secret)

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
	secret, err := base64.URLEncoding.DecodeString(u.Fragment)
	if err != nil {
		return nil, err
	}
	u.Fragment = ""
	dummyCell := naclcell.New(nil, secret)
	pubKeyBytes := p2p.MarshalPublicKey(dummyCell.PublicKey())

	cell := naclcell.New(
		httpcell.New(httpcell.Spec{
			URL: u.String(),
			Headers: map[string]string{
				SignerHeader: base64.URLEncoding.EncodeToString(pubKeyBytes),
			},
		}),
		secret,
	)

	return &Client{
		url:         u.String(),
		Cell:        cell,
		CellTracker: New(cell),
	}, nil
}
