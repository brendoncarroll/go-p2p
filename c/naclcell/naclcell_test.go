package naclcell

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	seed := make([]byte, 32)
	privKey := ed25519.NewKeyFromSeed(seed)

	ptext := []byte("hello world")
	ctext := encrypt(ptext, privKey)
	t.Log(hex.Dump(ctext))

	ptext2, err := decrypt(ctext, privKey)
	require.Nil(t, err)
	t.Log(string(ptext2))

	ctextTamper := append([]byte{}, ctext...)
	ctextTamper[0] ^= 1
	_, err = decrypt(ctextTamper, privKey)
	assert.NotNil(t, err)
}
