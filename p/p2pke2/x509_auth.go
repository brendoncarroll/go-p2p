package p2pke2

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/brendoncarroll/go-p2p/f/x509"
	"github.com/brendoncarroll/go-tai64"
)

var _ Authenticator = &X509Auth{}

type X509Auth struct {
	registry   x509.Registry
	privateKey x509.PrivateKey
	allow      func(x509.PublicKey) bool

	remoteKey *x509.PublicKey
}

func NewX509Auth(reg x509.Registry, privateKey x509.PrivateKey, remoteKey *x509.PublicKey, allow func(x509.PublicKey) bool) *X509Auth {
	if allow == nil {
		allow = func(x509.PublicKey) bool { return true }
	}
	return &X509Auth{
		registry:   reg,
		privateKey: privateKey,
		allow:      allow,
		remoteKey:  remoteKey,
	}
}

func (a *X509Auth) Intro(out []byte) ([]byte, error) {
	if a.remoteKey == nil {
		return nil, fmt.Errorf("can only generate intro when remoteKey is set")
	}
	pubKey, _ := a.registry.PublicFromPrivate(&a.privateKey)
	signer, err := a.registry.LoadSigner(&a.privateKey)
	if err != nil {
		return nil, err
	}
	now := tai64.Now().TAI64()
	sigTarget := a.makeIntroSigTarget(now, a.remoteKey)
	sig, err := signer.Sign(nil, sigTarget)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(X509Intro{
		PublicKey: x509.MarshalPublicKey(nil, &pubKey),
		Timestamp: now,
		Sig:       sig,
	})
	if err != nil {
		panic(err)
	}
	return append(out, data...), nil
}

func (a *X509Auth) Accept(data []byte) error {
	if a.remoteKey != nil {
		return errors.New("remoteKey is not set")
	}
	var intro X509Intro
	if err := json.Unmarshal(data, &intro); err != nil {
		return err
	}
	remoteKey, err := x509.ParsePublicKey(intro.PublicKey)
	if err != nil {
		return err
	}
	v, err := a.registry.LoadVerifier(&remoteKey)
	if err != nil {
		return err
	}

	// prepare sigTarget
	localKey, err := a.registry.PublicFromPrivate(&a.privateKey)
	if err != nil {
		return err
	}
	sigTarget := a.makeIntroSigTarget(intro.Timestamp, &localKey)
	if !a.allow(remoteKey) {
		return fmt.Errorf("public key not allowed %v", remoteKey)
	}
	if !v.Verify(sigTarget, intro.Sig) {
		return fmt.Errorf("invalid signature")
	}
	if !a.allow(remoteKey) {
		return fmt.Errorf("public key not allowed %v", remoteKey)
	}
	return nil
}

func (a *X509Auth) makeIntroSigTarget(ts tai64.TAI64, remoteKey *x509.PublicKey) (ret []byte) {
	ret = x509.MarshalPublicKey(ret, remoteKey)
	ret = append(ret, ts.Marshal()...)
	return ret
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

func (a *X509Auth) Verify(target *[64]byte, proof []byte) error {
	var x X509Proof
	if err := json.Unmarshal(proof, &x); err != nil {
		return err
	}
	pubKey, err := x509.ParsePublicKey(x.PublicKey)
	if err != nil {
		return err
	}
	if !a.allow(pubKey) {
		return fmt.Errorf("public key not allowed: %v", pubKey)
	}
	v, err := a.registry.LoadVerifier(&pubKey)
	if err != nil {
		return err
	}
	if !v.Verify(target[:], proof[:]) {
		return fmt.Errorf("invalid proof: %q", proof)
	}
	return nil
}

func (a *X509Auth) Remote() *x509.PublicKey {
	return a.remoteKey
}

type X509Proof struct {
	PublicKey []byte `json:"key"`
	Sig       []byte `json:"sig"`
}

type X509Intro struct {
	PublicKey []byte      `json:"key"`
	Timestamp tai64.TAI64 `json:"ts"`
	Sig       []byte      `json:"sig"`
}
