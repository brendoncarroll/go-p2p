package p2p

import (
	"crypto"
	"crypto/x509"
)

type PrivateKey = crypto.Signer

type PublicKey = crypto.PublicKey

func MarshalPublicKey(x PublicKey) []byte {
	data, err := x509.MarshalPKIXPublicKey(x)
	if err != nil {
		log.Infof("%T %+v", x, x)
		panic(err)
	}
	return data
}

func ParsePublicKey(data []byte) (PublicKey, error) {
	return x509.ParsePKIXPublicKey(data)
}
