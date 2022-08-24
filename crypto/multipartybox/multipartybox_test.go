package multipartybox

import (
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestV1(t *testing.T) {
	s := NewV1()
	type PrivateKey = PrivateKeyV1
	type PublicKey = PublicKeyV1
	generate := func(i int) (PublicKeyV1, PrivateKeyV1) {
		rng := mrand.New(mrand.NewSource(int64(i)))
		pub, priv, err := s.Generate(rng)
		require.NoError(t, err)
		return pub, priv
	}
	makeParties := func(n int) (privs []PrivateKeyV1, readers []KEMPublicKeyV1, writers []SignPublicKeyV1) {
		for i := 0; i < n; i++ {
			pub, priv := generate(i)
			privs = append(privs, priv)
			readers = append(readers, pub.KEM)
			writers = append(writers, pub.Sign)
		}
		return privs, readers, writers
	}

	t.Run("Encrypt", func(t *testing.T) {
		const N = 3
		privs, readers, _ := makeParties(N)

		ptext := []byte("hello world")
		for i := 0; i < N; i++ {
			ctext, err := s.EncryptDet(nil, &privs[i], readers, ptext)
			require.NoError(t, err)
			expected := s.CiphertextSize(N, len(ptext))
			require.Equal(t, expected, len(ctext))
		}
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		const N = 3
		privs, readers, writers := makeParties(N)

		ptext := []byte("hello world")
		for i := 0; i < N; i++ {
			ctext, err := s.EncryptDet(nil, &privs[i], readers, ptext)
			require.NoError(t, err)

			for j := 0; j < N; j++ {
				sender, ptext2, err := s.Decrypt(nil, &privs[j], writers, ctext)
				require.NoError(t, err)
				require.Equal(t, ptext, ptext2)
				require.Equal(t, i, sender)
			}
		}
	})
}
