// package aead provides an interface for Advanced Encryption with Associated Data (AEAD).
package aead

// Scheme32x8 is an AEAD with a 32 byte key and an 8 byte nonce
type SchemeK32N8 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and appends it to out
	Seal(out []byte, key *[32]byte, nonce *[8]byte, ptext, ad []byte) []byte
	// Open authenticates and decryptes ctext and appends the result to out or returns an error.
	Open(out []byte, key *[32]byte, nonce *[8]byte, ctext, ad []byte) ([]byte, error)
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}

// SchemeK32N24 is an AEAD with a 32 byte key and a 24 byte nonce
type SchemeK32N24 interface {
	// Seal creates an confidential and authenticated ciphertext for ptext and appends it to out
	Seal(out []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) []byte
	// Open authenticates and decryptes ctext and appends the result to out or returns an error.
	Open(out []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) ([]byte, error)
}

// SchemeSUV32 is an AEAD which takes a Secret and Unique Value instead of a key and a nonce
type SchemeSUV32 interface {
	Seal(out []byte, key *[32]byte, ptext, ad []byte) []byte
	Open(out []byte, key *[32]byte, ctext, ad []byte) ([]byte, error)
	// Overhead is the ciphertext_size - plaintext_size
	Overhead() int
}
