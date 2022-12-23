package x509

import "github.com/brendoncarroll/go-p2p/f/x509/oids"

var (
	// https://www.rfc-editor.org/rfc/rfc8410#section-3
	Ed25519PublicKey = oids.New(1, 3, 101, 112)
	Ed448PublicKey   = oids.New(1, 3, 101, 113)
)
