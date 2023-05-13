package p2pke2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
)

const MaxCounter = 1<<32 - 1

type Authenticator interface {
	// Intro is called to produce an introduction message.
	// The message is used to convince the remote party to allocate resources to communicate with us.
	Intro(out []byte) ([]byte, error)
	// Accept is used to validate an intro message and determine if it is from a known party.
	Accept(intro []byte) error

	// Prove is used to produce a proof that relates the authenticating party to the target.
	Prove(out []byte, target *[64]byte) []byte
	// Verify is used to verify that proof relates to target.
	Verify(target *[64]byte, proof []byte) error
}

type SessionParams[KEMPriv, KEMPub any] struct {
	Suite         Suite[KEMPriv, KEMPub]
	Seed          *[32]byte
	IsInit        bool
	Authenticator Authenticator
}

func (s *SessionParams[KEMPriv, KEMPub]) HandshakeParams() HandshakeParams[KEMPriv, KEMPub] {
	return HandshakeParams[KEMPriv, KEMPub]{
		Suite:  s.Suite,
		Seed:   s.Seed,
		IsInit: s.IsInit,

		Prove:  s.Authenticator.Prove,
		Verify: s.Authenticator.Verify,
	}
}

// Session contains the state for a cryptographic session.
// Session has a non-looping state machine, and eventually moves to a dead state where no more messages can be sent.
type Session[KEMPriv, KEMPub any] struct {
	initialized bool
	aead        aead.K256N64
	hs          HandshakeState[KEMPriv, KEMPub]
	auth        Authenticator

	inboundKey, outboundKey [32]byte
	replay                  replayFilter
	counter                 uint32
}

func NewSession[KEMPriv, KEMPub any](params SessionParams[KEMPriv, KEMPub]) Session[KEMPriv, KEMPub] {
	return Session[KEMPriv, KEMPub]{
		initialized: true,
		aead:        params.Suite.AEAD,
		hs:          NewHandshakeState(params.HandshakeParams()),
		auth:        params.Authenticator,
	}
}

func (s *Session[KEMPriv, KEMPub]) Send(out []byte, payload []byte) ([]byte, error) {
	if s.IsExhausted() {
		return nil, ErrSessionExhausted{}
	}
	// Handshake
	if !s.IsHandshakeDone() {
		return nil, fmt.Errorf("cannot send, session handshake is not done")
	}
	// Transport
	if s.counter == MaxCounter {
		return nil, errors.New("this session has sent the maximum number of messages")
	}
	counter := atomic.AddUint32(&s.counter, 1) - 1
	out = binary.BigEndian.AppendUint32(out, counter)
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], uint64(counter))
	return aead.AppendSealK256N64(out, s.aead, &s.outboundKey, nonce, payload, nil), nil
}

func (s *Session[KEMPriv, KEMPub]) SendHandshake(out []byte) ([]byte, error) {
	if s.IsHandshakeDone() {
		return nil, errors.New("handshake is already complete")
	}
	idx := s.hs.Index()
	out = binary.BigEndian.AppendUint32(out, uint32(idx))

	switch idx {
	case 0:
		var err error
		out, err = s.auth.Intro(out)
		if err != nil {
			return nil, err
		}
	case 1:
		// TODO: verify
	}

	out, err := s.hs.Send(out)
	if err != nil {
		return nil, err
	}
	if s.IsHandshakeDone() {
		s.inboundKey, s.outboundKey = s.hs.Split()
		s.counter = 8
	}
	return out, nil
}

// Deliver
// - returns (nil, non-nil) for errors.
// - returns (nil, nil) for protocol messages which do not produce an application message, such as during the handshake.
// - returns (out, nil) for 0 length application messages.
// - returns (out + ptext, nil) for valid messages.
func (s *Session[KEMPriv, KEMPub]) Deliver(out []byte, msg []byte) ([]byte, error) {
	if len(msg) < 4 {
		return nil, ErrShortMessage{}
	}
	if s.IsExhausted() {
		return nil, ErrSessionExhausted{}
	}
	counter := binary.BigEndian.Uint32(msg[:4])
	if !s.IsHandshakeDone() {
		if counter >= 4 {
			return nil, fmt.Errorf("early data message")
		}
		if err := s.hs.Deliver(msg[4:]); err != nil {
			return nil, err
		}
		if s.IsHandshakeDone() {
			s.inboundKey, s.outboundKey = s.hs.Split()
			s.counter = 4
		}
		return nil, nil
	}
	if counter < 4 {
		return nil, fmt.Errorf("late handshake message")
	}
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], uint64(binary.BigEndian.Uint32(msg[0:4])))
	ctext := msg[4:]
	out, err := aead.AppendOpenK256N64(out, s.aead, &s.inboundKey, nonce, ctext, nil)
	if err != nil {
		return nil, err
	}
	if !s.replay.Apply(uint64(counter)) {
		return nil, errors.New("replayed message")
	}
	// TODO: update replay filter
	return out, nil
}

func (s *Session[KEMPriv, KEMPub]) IsInitiator() bool {
	return s.hs.IsInitiator() && s.initialized
}

func (s *Session[KEMPriv, KEMPub]) IsHandshakeDone() bool {
	return s.hs.IsDone() && s.initialized
}

func (s *Session[KEMPriv, KEMPub]) IsExhausted() bool {
	return s.counter == MaxCounter || s.replay.Max() >= MaxCounter
}

// Zero clears all the state in session.
func (s *Session[KEMPriv, KEMPub]) Zero() {
	*s = Session[KEMPriv, KEMPub]{}
}

func (s *Session[KEMPriv, KEMPub]) Authenticator() Authenticator {
	return s.Authenticator()
}

type ErrShortMessage struct{}

func (e ErrShortMessage) Error() string {
	return "short message"
}

type ErrSessionExhausted struct{}

func (e ErrSessionExhausted) Error() string {
	return "session has been exhausted"
}
