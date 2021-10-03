package p2pke

import (
	"github.com/flynn/noise"
)

var cipherSuites = map[string]noise.CipherSuite{}
var cipherSuiteNames = []string{}

func init() {
	for _, suite := range []noise.CipherSuite{
		noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
	} {
		name := string(suite.Name())
		cipherSuites[name] = suite
		cipherSuiteNames = append(cipherSuiteNames, name)
	}
}
