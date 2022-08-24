package sig_ed25519

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/crypto/sign"
)

func TestEd25519(t *testing.T) {
	sign.TestScheme[PrivateKey, PublicKey](t, New())
}
