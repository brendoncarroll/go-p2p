// package aead provides an interface for Advanced Encryption with Associated Data (AEAD).
package aead

// Scheme256x64 is an AEAD with a 256 bit key and a 64 bit nonce
// A 64 bit nonce is not large enough to use randomly generated nonces.
type SchemeK256N64 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and appends it to out
	Seal(out []byte, key *[32]byte, nonce *[8]byte, ptext, ad []byte) []byte
	// Open authenticates and decryptes ctext and appends the result to out or returns an error.
	Open(out []byte, key *[32]byte, nonce *[8]byte, ctext, ad []byte) ([]byte, error)
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

// SchemeK256N192 is an AEAD with a 256 bit key and a 192 bit nonce
// 192 bits is large enough to use randomly generated nonces.
type SchemeK256N192 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and appends it to out
	Seal(out []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) []byte
	// Open authenticates and decryptes ctext and appends the result to out or returns an error.
	Open(out []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) ([]byte, error)
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

// SchemeSUV256 is an AEAD which takes a Secret and Unique Value instead of a key and a nonce
type SchemeSUV256 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and appends it to out
	Seal(out []byte, suv *[32]byte, ptext, ad []byte) []byte
	// Open authenticates and decryptes ctext and appends the result to out or returns an error.
	Open(out []byte, suv *[32]byte, ctext, ad []byte) ([]byte, error)
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}
