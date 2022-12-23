// package x509 implements Public Key Infrastructure X.509 formats.
package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/brendoncarroll/go-p2p/f/x509/oids"
)

// PublicKey is an AlgorithmID and a marshaled public key
type PublicKey struct {
	AlgorithmID oids.OID
	Data        []byte
}

func MarshalPublicKey(out []byte, x PublicKey) []byte {
	data, err := asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: x.AlgorithmID.ASN1(),
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
		AlgorithmID: oids.New(record.Algorithm.Algorithm...),
		Data:        record.PublicKey.RightAlign(),
	}, nil
}
