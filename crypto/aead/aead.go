// package aead provides an interface for Advanced Encryption with Associated Data (AEAD).
package aead

// K256N64 is an AEAD with a 256 bit key and a 64 bit nonce
// A 64 bit nonce is not large enough to use randomly generated nonces.
type K256N64 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and writes it to dst
	SealK256N64(dst []byte, key *[32]byte, nonce [8]byte, ptext, ad []byte)
	// Open authenticates and decryptes ctext and writes the result to dst or returns an error.
	OpenK256N64(dst []byte, key *[32]byte, nonce [8]byte, ctext, ad []byte) error
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

// K256N192 is an AEAD with a 256 bit key and a 192 bit nonce
// 192 bits is large enough to use randomly generated nonces.
type K256N192 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and writes it to dst
	SealK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte)
	// Open authenticates and decryptes ctext and writes the result to dst or returns an error.
	OpenK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) error
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

// SUV256 is an AEAD which takes a Secret and Unique Value instead of a key and a nonce
type SUV256 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and writes it to dst.
	SealSUV256(dst []byte, suv *[32]byte, ptext, ad []byte)
	// Open authenticates and decryptes ctext and writes the result to dst returns an error.
	OpenSUV256(dst []byte, suv *[32]byte, ctext, ad []byte) error
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

func AppendSealK256N64(out []byte, sch K256N64, key *[32]byte, nonce [8]byte, ptext, ad []byte) []byte {
	initLen := len(out)
	out = append(out, make([]byte, len(ptext)+sch.Overhead())...)
	dst := out[initLen:]
	sch.SealK256N64(dst, key, nonce, ptext, ad)
	return out
}

func AppendOpenK256N64(out []byte, sch K256N64, key *[32]byte, nonce [8]byte, ctext, ad []byte) ([]byte, error) {
	initLen := len(out)
	out = append(out, make([]byte, len(ctext)-sch.Overhead())...)
	dst := out[initLen:]
	err := sch.OpenK256N64(dst, key, nonce, ctext, ad)
	return out, err
}

func AppendSealSUV256(sch SUV256, out []byte, suv *[32]byte, ptext, ad []byte) []byte {
	initLen := len(out)
	out = append(out, make([]byte, len(ptext)+sch.Overhead())...)
	dst := out[initLen:]
	sch.SealSUV256(dst, suv, ptext, ad)
	return out
}

func AppendOpenSUV256(sch SUV256, out []byte, suv *[32]byte, ctext, ad []byte) ([]byte, error) {
	initLen := len(out)
	out = append(out, make([]byte, len(ctext)-sch.Overhead())...)
	dst := out[initLen:]
	if err := sch.OpenSUV256(dst, suv, ctext, ad); err != nil {
		return nil, err
	}
	return out, nil
}
