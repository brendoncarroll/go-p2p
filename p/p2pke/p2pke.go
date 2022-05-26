package p2pke

import (
	"math"
	"time"

	"github.com/flynn/noise"
)

const (
	MaxNonce        = math.MaxUint32 - 1
	SessionOverhead = 4 + 16
	Overhead        = 4 + SessionOverhead

	// RekeyAttemptTime is the duration spent trying to rekey before giving up and letting the channel die.
	RekeyAttemptTime = 90 * time.Second
	// RekeyTimeout is the durtation spent waiting for a response before retrying
	RekeyTimeout = 5 * time.Second
	// RekeyAfterTime is the time the current session is alive before another session is created.
	RekeyAfterTime = 120 * time.Second
	// RejectAfterTime is the time a session has been alive, after which messages will automatically be rejected.
	RejectAfterTime = 180 * time.Second
	// RekeyAfterMessages is the number of messages that can be sent over a session before a rekey is triggered.
	RekeyAfterMessages = MaxNonce / 2
	// KeepAliveTimeout is the amount of time to keep the session alive if no authenticated packets have been received.
	KeepAliveTimeout = 15 * time.Second
	// HandshakeTimeout
	HandshakeTimeout = time.Second

	MaxSessionDuration = 1 * time.Minute
)

const (
	nonceInitHello = 0
	nonceRespHello = 1
	nonceInitDone  = 2

	noncePostHandshake = 16
)

const (
	purposeChannelBinding = "p2pke/sig-channel-binding"
	purposeTimestamp      = "p2pke/timestamp"
)

var v1CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

type Direction uint8

const (
	InitToResp = Direction(iota)
	RespToInit
)

func (d Direction) String() string {
	switch d {
	case InitToResp:
		return "INIT->RESP"
	case RespToInit:
		return "RESP->INIT"
	default:
		panic("unknown direction")
	}
}

// IsInitHello returns true if x contains an InitHello message
func IsInitHello(x []byte) bool {
	msg, err := ParseMessage(x)
	return err == nil && msg.GetNonce() == nonceInitHello
}

// IsRespHello returns true if x contains a RespHello message
func IsRespHello(x []byte) bool {
	msg, err := ParseMessage(x)
	return err == nil && msg.GetNonce() == nonceRespHello
}

func IsHello(x []byte) bool {
	return IsInitHello(x) || IsRespHello(x)
}

func IsPostHandshake(x []byte) bool {
	msg, err := ParseMessage(x)
	return err == nil && msg.GetNonce() >= noncePostHandshake
}
