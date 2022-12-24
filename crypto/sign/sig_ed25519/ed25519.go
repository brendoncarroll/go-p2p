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

var _ sign.Scheme[PrivateKey, PublicKey] = Scheme{}

type Scheme struct{}

func New() Scheme {
	return Scheme{}
}

func (s Scheme) Generate(rng io.Reader) (retPub PublicKey, retPriv PrivateKey, _ error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return retPub, retPriv, err
	}
	copy(retPub[:], pub)
	copy(retPriv[:], priv)
	return retPub, retPriv, nil
}

func (s Scheme) DerivePublic(priv *PrivateKey) (ret PublicKey) {
	priv2 := ed25519.PrivateKey(priv[:])
	copy(ret[:], priv2.Public().(ed25519.PublicKey))
	return ret
}

func (s Scheme) Sign(dst []byte, priv *PrivateKey, msg []byte) {
	sig := ed25519.Sign(priv[:], msg)
	if len(dst) != len(sig) {
		panic(len(dst))
	}
	copy(dst, sig)
}

func (s Scheme) Sign512(dst []byte, priv *PrivateKey, input *sign.Input512) {
	s.Sign(dst, priv, input[:])
}

func (s Scheme) Verify(pub *PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub[:], msg, sig)
}

func (s Scheme) Verify512(pub *PublicKey, input *sign.Input512, sig []byte) bool {
	return s.Verify(pub, input[:], sig)
}

func (s Scheme) MarshalPublic(dst []byte, pub *PublicKey) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	copy(dst[:], pub[:])
}

func (s Scheme) ParsePublic(x []byte) (PublicKey, error) {
	if len(x) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("incorrect size for public key")
	}
	return *(*PublicKey)(x), nil
}

func (s Scheme) PublicKeySize() int {
	return ed25519.PublicKeySize
}

func (s Scheme) SignatureSize() int {
	return ed25519.SignatureSize
}
