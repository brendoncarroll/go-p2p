package x509

import (
	"fmt"

	"github.com/brendoncarroll/go-p2p/crypto/sign"
	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
	"github.com/brendoncarroll/go-p2p/f/x509/oids"
)

type ErrUnrecognizedAlgo struct {
	AlgorithmID oids.OID
}

func (e ErrUnrecognizedAlgo) Error() string {
	return fmt.Sprintf("unrecognized algorithm: %v", e.AlgorithmID)
}

// A Codec contains functions for Parsing and Marshaling Verifiers and Signers
type Codec struct {
	ParsePublic   func([]byte) (Verifier, error)
	MarshalPublic func(out []byte, v Verifier) []byte

	ParsePrivate   func([]byte) (Signer, error)
	MarshalPrivate func(out []byte, s Signer) []byte
}

// NewCodec returns a Codec for a signing scheme.
func NewCodec[Private, Public any](sch sign.Scheme[Private, Public]) Codec {
	return Codec{
		ParsePublic: func(x []byte) (Verifier, error) {
			pub, err := sch.ParsePublic(x)
			if err != nil {
				return nil, err
			}
			return NewVerifier[Private, Public](sch, &pub), nil
		},
		MarshalPublic: func(out []byte, v Verifier) []byte {
			v2 := v.(*verifier[Private, Public])
			return sign.AppendPublicKey[Public](out, sch, &v2.public)
		},
		ParsePrivate: func(x []byte) (Signer, error) {
			priv, err := sch.ParsePrivate(x)
			if err != nil {
				return nil, err
			}
			return NewSigner(sch, &priv), nil
		},
		MarshalPrivate: func(out []byte, s Signer) []byte {
			s2 := s.(*signer[Private, Public])
			return sign.AppendPrivateKey[Private](out, sch, &s2.private)
		},
	}
}

// Registry mananges parsing Verifiers and Signers for a given set of algorithms.
type Registry map[oids.OID]Codec

func (r Registry) LoadVerifier(pk *PublicKey) (Verifier, error) {
	codec, err := r.getCodec(pk.Algorithm)
	if err != nil {
		return nil, err
	}
	return codec.ParsePublic(pk.Data)
}

func (r Registry) StoreVerifier(algoID oids.OID, v Verifier) (PublicKey, error) {
	codec, err := r.getCodec(algoID)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{
		Algorithm: algoID,
		Data:      codec.MarshalPublic(nil, v),
	}, nil
}

func (r Registry) LoadSigner(pk *PrivateKey) (Signer, error) {
	codec, err := r.getCodec(pk.Algorithm)
	if err != nil {
		return nil, err
	}
	return codec.ParsePrivate(pk.Data)
}

func (r Registry) StoreSigner(algoID oids.OID, s Signer) (PrivateKey, error) {
	codec, err := r.getCodec(algoID)
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{
		Algorithm: algoID,
		Data:      codec.MarshalPrivate(nil, s),
	}, nil
}

func (r Registry) ParseVerifier(data []byte) (Verifier, error) {
	pk, err := ParsePublicKey(data)
	if err != nil {
		return nil, err
	}
	return r.LoadVerifier(&pk)
}

func (r Registry) getCodec(algoID oids.OID) (Codec, error) {
	codec, exists := r[algoID]
	if !exists {
		return Codec{}, ErrUnrecognizedAlgo{algoID}
	}
	return codec, nil
}

func (r Registry) PublicFromPrivate(private *PrivateKey) (ret PublicKey, _ error) {
	s, err := r.LoadSigner(private)
	if err != nil {
		return ret, err
	}
	pubKey, err := r.StoreVerifier(private.Algorithm, s.Verifier())
	if err != nil {
		return ret, err
	}
	return pubKey, err
}

func DefaultRegistry() Registry {
	return Registry{
		Algo_Ed25519: NewCodec[sig_ed25519.PrivateKey, sig_ed25519.PublicKey](sig_ed25519.New()),
	}
}
