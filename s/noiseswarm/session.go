package noiseswarm

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/replay"
	"google.golang.org/protobuf/proto"
)

const (
	MaxSessionLife     = time.Minute
	MaxSessionMessages = (1 << 32) - 1

	// SigPurpose is the purpose passed to p2p.Sign when signing
	// channel bindings.
	// Your application should not reuse this purpose with the privateKey used for the swarm.
	SigPurpose = "p2p/noiseswarm/channel"
)

const (
	countInit              = uint32(0)
	countResp              = uint32(1)
	countSigChannelBinding = uint32(2)
	countPostHandshake     = uint32(3)

	countLastMessage = uint32(MaxSessionMessages)
)

type session struct {
	createdAt  time.Time
	initiator  bool
	privateKey p2p.PrivateKey
	send       func(context.Context, []byte) error

	mu sync.Mutex
	// handshake
	hsstate         *noise.HandshakeState
	remotePublicKey p2p.PublicKey
	handshakeDone   chan struct{}
	handshakeErr    error

	// symetric
	outCount    uint32
	inFilter    replay.Filter
	outCS, inCS *noise.CipherState
}

func newSession(initiator bool, privateKey p2p.PrivateKey, send func(context.Context, []byte) error) *session {
	hsstate, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Initiator:   initiator,
		Pattern:     noise.HandshakeNN,
	})
	if err != nil {
		panic(err)
	}
	return &session{
		createdAt:  time.Now(),
		privateKey: privateKey,
		initiator:  initiator,
		send:       send,

		hsstate:       hsstate,
		handshakeDone: make(chan struct{}),
	}
}

func (s *session) startHandshake(ctx context.Context) error {
	if !s.initiator {
		return nil
	}
	s.mu.Lock()
	countBytes := [4]byte{}
	binary.BigEndian.PutUint32(countBytes[:], countInit)
	out, _, _, err := s.hsstate.WriteMessage(countBytes[:], nil)
	if err != nil {
		panic(err)
	}
	s.mu.Unlock()
	return s.send(ctx, out)
}

func (s *session) handle(in []byte) (up []byte, err error) {
	if err := checkMessageLen(in); err != nil {
		return nil, err
	}
	countBytes := in[:4]
	count := binary.BigEndian.Uint32(countBytes)
	if count < countPostHandshake {
		err := s.handleHandshake(count, in[4:])
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isChanOpen(s.handshakeDone) {
		return nil, errors.Errorf("transport message before handshake is complete")
	}
	ctext := in[4:]
	ptext, err := s.decryptMessage(count, ctext)
	if err != nil {
		return nil, err
	}
	if !s.inFilter.ValidateCounter(uint64(count), MaxSessionMessages) {
		return nil, errors.Errorf("replayed counter %d", count)
	}
	return ptext, nil
}

func (s *session) handleHandshake(counter uint32, in []byte) error {
	var resps [][]byte
	if err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case !s.initiator && counter == countInit:
			_, _, _, err := s.hsstate.ReadMessage(nil, in)
			if err != nil {
				return err
			}
			counterBytes := [4]byte{}
			binary.BigEndian.PutUint32(counterBytes[:], countResp)
			out, cs1, cs2, err := s.hsstate.WriteMessage(counterBytes[:], nil)
			if err != nil {
				return err
			}
			if cs1 == nil || cs2 == nil {
				panic("no error and no cipherstates")
			}
			resps = append(resps, out)
			s.completeNoiseHandshake(cs1, cs2)

			// also send intro
			introBytes, err := signChannelBinding(s.privateKey, s.hsstate.ChannelBinding())
			if err != nil {
				return err
			}
			out = s.encryptMessage(countSigChannelBinding, introBytes)
			resps = append(resps, out)
			return nil

		case s.initiator && counter == countResp:
			_, cs1, cs2, err := s.hsstate.ReadMessage(nil, in)
			if err != nil {
				return err
			}
			if cs1 == nil || cs2 == nil {
				panic("no error and no cipherstates")
			}
			s.completeNoiseHandshake(cs1, cs2)
			// send intro
			introBytes, err := signChannelBinding(s.privateKey, s.hsstate.ChannelBinding())
			if err != nil {
				return err
			}
			out := s.encryptMessage(countSigChannelBinding, introBytes)
			resps = append(resps, out)
			return nil

		case counter == countSigChannelBinding:
			if !isChanOpen(s.handshakeDone) {
				return nil
			}
			if s.inCS == nil {
				return errors.Errorf("noise handshake not complete")
			}
			ptext, err := s.decryptMessage(countSigChannelBinding, in)
			if err != nil {
				return err
			}
			remotePubKey, err := verifyIntro(s.hsstate.ChannelBinding(), ptext)
			if err != nil {
				return err
			}
			s.completeHandshake(remotePubKey)
			return nil
		default:
			return errors.Errorf("concurrent handshake")
		}
	}(); err != nil {
		s.failHandshake(err)
		return err
	}
	ctx := context.Background()
	for _, resp := range resps {
		if err := s.send(ctx, resp); err != nil {
			return err
		}
	}
	return nil
}

// tell waits for the handshake to complete if it hasn't and then sends data over fn
func (s *session) tell(ctx context.Context, ptext []byte) error {
	if err := s.waitHandshake(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	outCount := s.outCount
	s.outCount++
	s.mu.Unlock()
	if outCount >= MaxSessionMessages {
		return errors.Errorf("session has reached message limit")
	}
	out := s.encryptMessage(outCount, ptext)
	return s.send(ctx, out)
}

// failHandshake must be called with mu
func (s *session) failHandshake(err error) {
	if isChanOpen(s.handshakeDone) {
		s.handshakeErr = err
		close(s.handshakeDone)
	}
}

// completeNoiseHandshake must be called with mu
func (s *session) completeNoiseHandshake(cs1, cs2 *noise.CipherState) {
	if !s.initiator {
		cs1, cs2 = cs2, cs1
	}
	s.outCS = cs1
	s.inCS = cs2
	s.outCount = countPostHandshake
}

// completeHandshake must be called with mu
func (s *session) completeHandshake(remotePublicKey p2p.PublicKey) {
	if remotePublicKey == nil {
		panic(remotePublicKey)
	}
	s.remotePublicKey = remotePublicKey
	s.outCount = countPostHandshake
	close(s.handshakeDone)
}

func (s *session) waitHandshake(ctx context.Context) error {
	// this is necessary to ensure we can return a public key from memory
	// when a cancelled context is passed in, as is required by p2p.LookupPublicKeyInHandler
	if !isChanOpen(s.handshakeDone) {
		return s.handshakeErr
	}
	ctx, cf := context.WithTimeout(ctx, time.Second)
	defer cf()
	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "timeout during handshake")
	case <-s.handshakeDone:
		return s.handshakeErr
	}
}

func (s *session) isExpired(now time.Time) bool {
	age := now.Sub(s.createdAt)
	return age < MaxSessionLife
}

func (s *session) getRemotePeerID() p2p.PeerID {
	return p2p.NewPeerID(s.getRemotePublicKey())
}

func (s *session) getRemotePublicKey() p2p.PublicKey {
	if isChanOpen(s.handshakeDone) {
		panic("getRemotePublicKey called before handshake has completed")
	}
	if s.remotePublicKey == nil {
		panic("remotePublicKey cannot be nil")
	}
	return s.remotePublicKey
}

func (s *session) encryptMessage(count uint32, ptext []byte) []byte {
	cipher := s.outCS.Cipher()
	counterBytes := [4]byte{}
	binary.BigEndian.PutUint32(counterBytes[:], count)
	return cipher.Encrypt(counterBytes[:], uint64(count), counterBytes[:], ptext)
}

func (s *session) decryptMessage(count uint32, in []byte) ([]byte, error) {
	cipher := s.inCS.Cipher()
	counterBytes := [4]byte{}
	binary.BigEndian.PutUint32(counterBytes[:], count)
	return cipher.Decrypt(nil, uint64(count), counterBytes[:], in)
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

func shouldClearSession(err error) bool {
	return true
}

func signChannelBinding(privateKey p2p.PrivateKey, cb []byte) ([]byte, error) {
	if len(cb) < 64 {
		panic("short cb")
	}
	sig, err := p2p.Sign(privateKey, SigPurpose, cb)
	if err != nil {
		return nil, err
	}
	pubKey := privateKey.Public()
	intro := &AuthIntro{
		PublicKey:    p2p.MarshalPublicKey(pubKey),
		SigOfChannel: sig,
	}
	return proto.Marshal(intro)
}

func verifyIntro(cb []byte, introBytes []byte) (p2p.PublicKey, error) {
	intro := AuthIntro{}
	if err := proto.Unmarshal(introBytes, &intro); err != nil {
		return nil, err
	}
	pubKey, err := p2p.ParsePublicKey(intro.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := p2p.Verify(pubKey, SigPurpose, cb, intro.SigOfChannel); err != nil {
		return nil, err
	}
	return pubKey, nil
}
