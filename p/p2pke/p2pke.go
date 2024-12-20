package p2pke

import (
	"math"
	"time"

	"github.com/flynn/noise"
	"go.brendoncarroll.net/p2p/f/x509"
)

const (
	// Overhead is the per message overhead taken up by P2PKE.
	Overhead = 4 + 16
	// MaxMessageLen is the maximum message size that applications can send through the channel.
	MaxMessageLen = noise.MaxMsgLen - Overhead

	// MaxNonce is the maxmium number of messages that can be sent through a channel.
	MaxNonce = math.MaxUint32 - 1
	// RekeyAfterTime is the default.
	RekeyAfterTime = 120 * time.Second
	// RejectAfterTime is the default.
	RejectAfterTime = 180 * time.Second
	// RekeyAfterMessages is the number of messages that can be sent over a session before a rekey is triggered.
	RekeyAfterMessages = MaxNonce / 2

	// KeepAliveTimeout is the default.
	KeepAliveTimeout = 15 * time.Second
	// HandshakeBackoff is the default.
	HandshakeBackoff = 250 * time.Millisecond
)

const (
	nonceInitHello = 0
	nonceRespHello = 1
	nonceInitDone  = 2
	nonceRespDone  = 3

	noncePostHandshake = 16
)

const (
	purposeChannelBinding = "p2pke/channel-binding"
	purposeTimestamp      = "p2pke/timestamp"
)

var v1CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)

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

type privateKey struct {
	Registry x509.Registry
	Key      x509.PrivateKey
}

func (pk *privateKey) Public() publicKey {
	if pk.Registry == nil || pk.Key.IsZero() {
		return publicKey{}
	}
	pub, err := pk.Registry.PublicFromPrivate(&pk.Key)
	if err != nil {
		panic(err)
	}
	return publicKey{
		Registry: pk.Registry,
		Key:      pub,
	}
}

func (pk *privateKey) Sign(out []byte, msg []byte) ([]byte, error) {
	sign, err := pk.Registry.LoadSigner(&pk.Key)
	if err != nil {
		return nil, err
	}
	return sign.Sign(out, msg)
}

type publicKey struct {
	Registry x509.Registry
	Key      x509.PublicKey
}

func (pk *publicKey) Verify(msg, sig []byte) bool {
	v, err := pk.Registry.LoadVerifier(&pk.Key)
	if err != nil {
		return false
	}
	return v.Verify(msg, sig)
}

func (pk *publicKey) IsZero() bool {
	return pk.Registry == nil || pk.Key.IsZero()
}
