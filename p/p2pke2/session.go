package p2pke2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
)

const MaxCounter = 1<<32 - 1

type Session[XOF, KEMPriv, KEMPub any] struct {
	aead aead.SchemeK256N64
	hs   HandshakeState[XOF, KEMPriv, KEMPub]

	inboundKey, outboundKey [32]byte
	replay                  replayFilter
	counter                 uint32
}

func New[XOF, KEMPriv, KEMPub any](scheme Scheme[XOF, KEMPriv, KEMPub], seed *[32]byte, isInit bool) Session[XOF, KEMPriv, KEMPub] {
	return Session[XOF, KEMPriv, KEMPub]{
		aead: scheme.AEAD,
		hs:   NewHandshakeState[XOF, KEMPriv, KEMPub](scheme, seed, isInit),
	}
}

func (s *Session[XOF, KEMPriv, KEMPub]) Send(out []byte, payload []byte) ([]byte, error) {
	// Handshake
	if !s.IsHandshakeDone() {
		if payload != nil {
			return nil, fmt.Errorf("cannot send session handshake is not done")
		}
		out = appendUint32(out, uint32(s.hs.Index()))
		return s.hs.Send(out)
	}
	// Transport
	if s.counter == MaxCounter {
		return nil, errors.New("this session has sent the maximum number of messages")
	}
	counter := atomic.AddUint32(&s.counter, 1) - 1
	out = appendUint32(out, counter)
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], uint64(counter))
	return s.aead.Seal(out, &s.outboundKey, &nonce, payload, nonce[4:]), nil
}

// Deliver
// - returns (nil, non-nil) for errors.
// - returns (nil, nil) for protocol messages which do not produce an application message, such as during the handshake.
// - returns (out, nil) for 0 length application messages.
// - returns (out + ptext, nil) for valid messages.
func (s *Session[XOF, KEMPriv, KEMPub]) Deliver(out []byte, msg []byte) ([]byte, error) {
	if len(msg) < 4 {
		return nil, ErrShortMessage{}
	}
	counter := binary.BigEndian.Uint32(msg[:4])
	if !s.IsHandshakeDone() {
		if counter >= 4 {
			return nil, fmt.Errorf("early data message")
		}
		if err := s.hs.Deliver(msg[4:]); err != nil {
			return nil, err
		}
		if s.hs.IsDone() {
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
	out, err := s.aead.Open(out, &s.inboundKey, &nonce, ctext, nil)
	if err != nil {
		return nil, err
	}
	if !s.replay.Apply(uint64(counter)) {
		return nil, errors.New("replayed message")
	}
	// TODO: update replay filter
	return out, nil
}

func (s *Session[XOF, KEMPriv, KEMPub]) IsHandshakeDone() bool {
	return s.hs.IsDone()
}

func (s *Session[XOF, KEMPriv, KEMPub]) ShouldSend() bool {
	return false
}

func appendUint32(out []byte, x uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], x)
	return append(out, buf[:]...)
}

type ErrShortMessage struct{}

func (e ErrShortMessage) Error() string {
	return "short message"
}
