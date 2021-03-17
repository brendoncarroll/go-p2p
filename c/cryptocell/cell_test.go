package cryptocell

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: add memcell for tests
// func TestSecretBox(t *testing.T) {
// 	cellutil.CellTestSuite(t, func() p2p.Cell {
// 	})
// }

// func TestSigned(t *testing.T) {
// 	cellutil.CellTestSuite(t, func() p2p.Cell {
// 	})
// }

func TestEncryptDecrypt(t *testing.T) {
	secret := make([]byte, 32)

	ptext := []byte("hello world")
	ctext := encrypt(ptext, secret)
	t.Log(hex.Dump(ctext))

	ptext2, err := decrypt(ctext, secret)
	require.Nil(t, err)
	t.Log(string(ptext2))

	ctextTamper := append([]byte{}, ctext...)
	ctextTamper[0] ^= 1
	_, err = decrypt(ctextTamper, secret)
	assert.NotNil(t, err)
}
