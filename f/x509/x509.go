// package x509 implements Public Key Infrastructure X.509 formats.
package x509

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/brendoncarroll/go-p2p/crypto/sign"
	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
	"github.com/brendoncarroll/go-p2p/f/x509/oids"
)

// PublicKey is an AlgorithmID and a marshaled public key
type PublicKey struct {
	Algorithm oids.OID
	Data      []byte
}

// MarshalPublicKey appends the marshalled bytes of x to out and returns the result.
func MarshalPublicKey(out []byte, x *PublicKey) []byte {
	data, err := asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: x.Algorithm.ASN1(),
		},
		asn1.BitString{
			Bytes:     x.Data,
			BitLength: len(x.Data) * 8,
		},
	})
	if err != nil {
		panic(err)
	}
	return append(out, data...)
}

// ParsePublicKey attempts to parse a PublicKey from input, and returns the PublicKey or an error.
func ParsePublicKey(input []byte) (PublicKey, error) {
	var record struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(input, &record)
	if err != nil {
		return PublicKey{}, err
	} else if len(rest) > 0 {
		return PublicKey{}, errors.New("data after public key")
	}
	return PublicKey{
		Algorithm: oids.New(record.Algorithm.Algorithm...),
		Data:      record.PublicKey.RightAlign(),
	}, nil
}

type PrivateKey struct {
	Algorithm oids.OID
	Data      []byte
}

// MarshalPrivateKey appends the marshalled bytes of x to out and returns the result.
func MarshalPrivateKey(out []byte, x *PrivateKey) []byte {
	data, err := asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: x.Algorithm.ASN1(),
		},
		asn1.BitString{
			Bytes:     x.Data,
			BitLength: len(x.Data) * 8,
		},
	})
	if err != nil {
		panic(err)
	}
	return append(out, data...)
}

// ParsePrivateKey attempts to parse a PrivateKey from input, and returns the PrivateKey or an error.
func ParsePrivateKey(input []byte) (PrivateKey, error) {
	var record struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(input, &record)
	if err != nil {
		return PrivateKey{}, err
	} else if len(rest) > 0 {
		return PrivateKey{}, errors.New("data after public key")
	}
	return PrivateKey{
		Algorithm: oids.New(record.Algorithm.Algorithm...),
		Data:      record.PublicKey.RightAlign(),
	}, nil
}

// Verifier contains the verify method
type Verifier interface {
	Verify(msg, sig []byte) bool
}

type verifier[Private, Public any] struct {
	scheme sign.Scheme[Private, Public]
	public Public
}

func (v *verifier[Private, Public]) Verify(msg, sig []byte) bool {
	return v.scheme.Verify(&v.public, msg, sig)
}

// NewVerifier creates a Verifier from a sign.Scheme and a public key
func NewVerifier[Private, Public any](sch sign.Scheme[Private, Public], pub *Public) Verifier {
	return &verifier[Private, Public]{
		scheme: sch,
		public: *pub,
	}
}

// Signer contains the Sign method
type Signer interface {
	// Sign appends a signature for msg to out, and returns out, or an error
	Sign(out []byte, msg []byte) ([]byte, error)
	Verifier() Verifier
}

type signer[Private, Public any] struct {
	scheme  sign.Scheme[Private, Public]
	private Private
}

func (s *signer[Private, Public]) Sign(out []byte, msg []byte) ([]byte, error) {
	initLen := len(out)
	out = append(out, make([]byte, s.scheme.SignatureSize())...)
	s.scheme.Sign(out[:initLen], &s.private, msg)
	return out, nil
}

func (s *signer[Private, Public]) Verifier() Verifier {
	public := s.scheme.DerivePublic(&s.private)
	return NewVerifier(s.scheme, &public)
}

// NewSigner returns a Signer from a sign.Scheme and a private key
func NewSigner[Private, Public any](sch sign.Scheme[Private, Public], priv *Private) Signer {
	return &signer[Private, Public]{
		scheme:  sch,
		private: *priv,
	}
}

// SignerFromStandard returns a Signer and oids.OID for a standard library crypto.Signer
// If the algorithm is not supported it returns the zero value for both
func SignerFromStandard(x crypto.Signer) (oids.OID, Signer) {
	switch x := x.(type) {
	case ed25519.PrivateKey:
		y := sig_ed25519.PrivateKeyFromStandard(x)
		return Algo_Ed25519, NewSigner[sig_ed25519.PrivateKey, sig_ed25519.PublicKey](sig_ed25519.New(), &y)
	default:
		return "", nil
	}
}

// VerifierFromStandard returns a Verifier and oids.OID for a standard library crypto.PublicKey
// If the algorithm is not supported it returns the zero value for both
func VerifierFromStandard(x crypto.PublicKey) (oids.OID, Verifier) {
	switch x := x.(type) {
	case ed25519.PublicKey:
		y := sig_ed25519.PublicKeyFromStandard(x)
		return Algo_Ed25519, NewVerifier[sig_ed25519.PrivateKey, sig_ed25519.PublicKey](sig_ed25519.New(), &y)
	default:
		return "", nil
	}
}

func ToStandardSigner(x *PrivateKey) (crypto.Signer, error) {
	switch x.Algorithm {
	case Algo_Ed25519:
		if len(x.Data) != ed25519.SeedSize {
			return nil, errors.New("not a valid ed25519 private key")
		}
		return ed25519.NewKeyFromSeed(x.Data), nil
	default:
		return nil, ErrUnrecognizedAlgo{x.Algorithm}
	}
}
