package swarmutil

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/brendoncarroll/go-p2p"
)

func GenerateSelfSigned(privKey p2p.PrivateKey) tls.Certificate {
	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          big.NewInt(1),
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(make([]byte, 16))},
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
}
