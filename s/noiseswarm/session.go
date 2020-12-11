package noiseswarm

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/replay"
)

type session struct {
	createdAt time.Time
	initiator bool
	send      func(context.Context, []byte) error

	mu sync.Mutex
	// handshake
	handshakeDone chan struct{}
	hsstate       *noise.HandshakeState

	// symetric
	outCount    uint32
	inFilter    replay.Filter
	outCS, inCS *noise.CipherState
}

func newSession(initiator bool, privateKey p2p.PrivateKey, send func(context.Context, []byte) error) *session {
	privKey := privateKey.(ed25519.PrivateKey)
	keyPair := noise.DHKey{
		Private: privKey[:32],
		Public:  privKey[32:],
	}
	hsstate, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Initiator:     initiator,
		StaticKeypair: keyPair,
		Pattern:       noise.HandshakeXX,
	})
	if err != nil {
		panic(err)
	}
	return &session{
		createdAt: time.Now(),
		initiator: initiator,
		send:      send,

		hsstate:       hsstate,
		handshakeDone: make(chan struct{}),
	}
}

func (s *session) startHandshake(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initiator {
		return nil
	}
	out, _, _, err := s.hsstate.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	if err := s.send(ctx, out); err != nil {
		return err
	}
	return nil
}

func (s *session) handle(in []byte) (up []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()
	if isChanOpen(s.handshakeDone) {
		log.Println("got handshake message")
		_, outCS, inCS, err := s.hsstate.ReadMessage(nil, in)
		if err != nil {
			return nil, err
		}
		if inCS != nil && outCS != nil {
			s.finishHandshake(outCS, inCS)
			return nil, nil
		}
		out, outCS, inCS, err := s.hsstate.WriteMessage(nil, nil)
		if err != nil {
			return nil, err
		}
		if inCS != nil && outCS != nil {
			s.finishHandshake(outCS, inCS)
			return nil, nil
		}
		if err := s.send(ctx, out); err != nil {
			return nil, err
		}
		return nil, nil
	} else {
		if err := checkMessageLen(in); err != nil {
			return nil, err
		}
		cipher := s.inCS.Cipher()
		countBytes := in[:4]
		ctext := in[4:]
		count := binary.BigEndian.Uint32(countBytes)
		ptext, err := cipher.Decrypt(nil, uint64(count), countBytes, ctext)
		if err != nil {
			return nil, err
		}
		if !s.inFilter.ValidateCounter(uint64(count), 1<<32-1) {
			return nil, errors.Errorf("replayed counter %d", count)
		}
		return ptext, nil
	}
}

// tell waits for the handshake to complete if it hasn't and then sends data over fn
func (s *session) tell(ctx context.Context, ptext []byte) error {
	if err := s.waitHandshake(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, s.outCount)
	s.outCount++
	msg := s.outCS.Encrypt(counter[:], counter[:], ptext)
	s.mu.Unlock()
	return s.send(ctx, msg)
}

func (s *session) finishHandshake(outCS, inCS *noise.CipherState) {
	s.outCS = outCS
	s.inCS = inCS
	close(s.handshakeDone)
}

func (s *session) waitHandshake(ctx context.Context) error {
	ctx, cf := context.WithTimeout(ctx, time.Second)
	defer cf()
	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "timeout during handshake")
	case <-s.handshakeDone:
		return nil
	}
}

func (s *session) remotePeerID() p2p.PeerID {
	return p2p.NewPeerID(s.remotePublicKey())
}

func (s *session) remotePublicKey() p2p.PublicKey {
	return ed25519.PublicKey(s.hsstate.PeerStatic())
}

func checkMessageLen(x []byte) error {
	if len(x) < 4 {
		return errors.Errorf("message too short")
	}
	return nil
}

func isChanOpen(x chan struct{}) bool {
	select {
	case <-x:
		return false
	default:
		return true
	}
}
