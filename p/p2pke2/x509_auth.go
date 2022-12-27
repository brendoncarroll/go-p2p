package p2pke2

type X509Authenticator struct {
	registry  x509.Registry
	publicKey x509.PublicKey
}

func New(reg x509.Registry, local x509.PrivateKey, allowed func(x509.PublicKey) bool) X509Authenticator {

}
