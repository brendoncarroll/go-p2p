package p2pke

import (
	"fmt"
	"time"
)

// ErrSessionExpired is returned when the session is too old to be used anymore and needs to be put down.
type ErrSessionExpired struct {
	ExpiredAt time.Time
}

func (e ErrSessionExpired) Error() string {
	return fmt.Sprintf("p2pke: session expired at %v", e.ExpiredAt)
}

// ErrDecryptionFailure is returned by a Session when a message failed to decrypt.
type ErrDecryptionFailure struct {
	Nonce    uint32
	NoiseErr error
}

func (e ErrDecryptionFailure) Error() string {
	return fmt.Sprintf("p2pke: decryption failure: nonce=%d noise=%v", e.Nonce, e.NoiseErr)
}

// ErrEarlyData is returned by the session when application data arrives early.
// There is no way to verify this data without a
type ErrEarlyData struct {
	State uint8
	Nonce uint32
}

func (e ErrEarlyData) Error() string {
	return fmt.Sprintf("p2pke: early data: state=%d nonce=%d", e.State, e.Nonce)
}
