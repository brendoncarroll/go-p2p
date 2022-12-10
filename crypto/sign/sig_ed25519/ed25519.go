package sig_ed25519

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/brendoncarroll/go-p2p/crypto/sign"
)

type (
	PrivateKey = [ed25519.PrivateKeySize]byte
	PublicKey  = [ed25519.PublicKeySize]byte
)

var _ sign.Scheme[PrivateKey, PublicKey] = Ed25519{}

type Ed25519 struct{}

func New() Ed25519 {
	return Ed25519{}
}

func (s Ed25519) Generate(rng io.Reader) (retPub PublicKey, retPriv PrivateKey, _ error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return retPub, retPriv, err
	}
	copy(retPub[:], pub)
	copy(retPriv[:], priv)
	return retPub, retPriv, nil
}

func (s Ed25519) DerivePublic(priv *PrivateKey) (ret PublicKey) {
	priv2 := ed25519.PrivateKey(priv[:])
	copy(ret[:], priv2.Public().(ed25519.PublicKey))
	return ret
}

func (s Ed25519) Sign(dst []byte, priv *PrivateKey, msg []byte) {
	sig := ed25519.Sign(priv[:], msg)
	if len(dst) != len(sig) {
		panic(len(dst))
	}
	copy(dst, sig)
}

func (s Ed25519) Verify(pub *PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub[:], msg, sig)
}

func (s Ed25519) MarshalPublic(dst []byte, pub *PublicKey) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	copy(dst[:], pub[:])
}

func (s Ed25519) ParsePublic(x []byte) (PublicKey, error) {
	if len(x) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("incorrect size for public key")
	}
	return *(*PublicKey)(x), nil
}

func (s Ed25519) PublicKeySize() int {
	return ed25519.PublicKeySize
}

func (s Ed25519) SignatureSize() int {
	return ed25519.SignatureSize
}
