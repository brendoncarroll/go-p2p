package p2pke2

import (
	"encoding/json"

	"github.com/brendoncarroll/go-p2p/f/x509"
)

type X509Auth struct {
	registry   x509.Registry
	privateKey x509.PrivateKey
	allow      func(x509.PublicKey) bool

	remoteKey x509.PublicKey
}

func NewX509Auth(reg x509.Registry, privateKey x509.PrivateKey, allow func(x509.PublicKey) bool) *X509Auth {
	return &X509Auth{
		registry:   reg,
		privateKey: privateKey,
		allow:      allow,
	}
}

func (a *X509Auth) Prove(out []byte, target *[64]byte) []byte {
	signer, err := a.registry.LoadSigner(&a.privateKey)
	if err != nil {
		return out
	}
	sig, err := signer.Sign(nil, target[:])
	if err != nil {
		return out
	}
	pubKey, _ := a.registry.PublicFromPrivate(&a.privateKey)
	data, _ := json.Marshal(X509Proof{
		PublicKey: x509.MarshalPublicKey(nil, &pubKey),
		Sig:       sig,
	})
	return append(out, data...)
}

func (a *X509Auth) Verify(target *[64]byte, proof []byte) bool {
	var x X509Proof
	if err := json.Unmarshal(proof, &x); err != nil {
		return false
	}
	pubKey, err := x509.ParsePublicKey(x.PublicKey)
	if err != nil {
		return false
	}
	if !a.allow(pubKey) {
		return false
	}
	v, err := a.registry.LoadVerifier(&pubKey)
	if err != nil {
		return false
	}
	if !v.Verify(target[:], proof[:]) {
		return false
	}
	a.remoteKey = pubKey
	return true
}

func (a *X509Auth) Remote() x509.PublicKey {
	return a.remoteKey
}

type X509Proof struct {
	PublicKey []byte `json:"key"`
	Sig       []byte `json:"sig"`
}
