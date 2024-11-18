package x509

import "go.brendoncarroll.net/p2p/f/x509/oids"

var (
	// https://www.rfc-editor.org/rfc/rfc8410#section-3
	Algo_Ed25519 = oids.New(1, 3, 101, 112)
	Algo_Ed448   = oids.New(1, 3, 101, 113)
)
