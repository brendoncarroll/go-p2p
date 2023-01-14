package sshswarm

import (
	"crypto"

	"golang.org/x/crypto/ssh"
)

func NewSignerFromSigner(x crypto.Signer) (ssh.Signer, error) {
	return ssh.NewSignerFromSigner(x)
}
