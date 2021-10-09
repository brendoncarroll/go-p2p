package p2pke

import (
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/replay"
)

const (
	MaxSessionDuration = 1 * time.Minute
	Overhead           = 4 + 16
)

type Sender func([]byte)

type Session struct {
	privateKey p2p.PrivateKey
	isInit     bool
	log        *logrus.Logger
	createdAt  time.Time

	// handshake
	hs        *noise.HandshakeState
	remoteKey p2p.PublicKey

	// ciphers
	cipherOut, cipherIn noise.Cipher
	nonce               uint32
	rp                  *replay.Filter
}

type SessionParams struct {
	IsInit     bool
	PrivateKey p2p.PrivateKey
	Logger     *logrus.Logger
	Now        time.Time
}

func NewSession(params SessionParams) *Session {
	if params.Logger == nil {
		params.Logger = logrus.StandardLogger()
	}
	s := &Session{
		privateKey: params.PrivateKey,
		isInit:     params.IsInit,
		log:        params.Logger,
		createdAt:  params.Now,
	}
	return s
}

func (s *Session) StartHandshake(send Sender) {
	if s.isInit {
		s.sendInit(send)
	}
}

func (s *Session) sendInit(send Sender) {
	hs, err := noise.NewHandshakeState(noise.Config{
		Initiator:   s.isInit,
		Pattern:     noise.HandshakeNN,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
	})
	if err != nil {
		panic(err)
	}
	s.hs = hs

	msg := newMessage(InitToResp, 0)
	msg, _, _, err = s.hs.WriteMessage(msg, marshal(nil, &InitHello{
		CipherSuites: cipherSuiteNames,
	}))
	if err != nil {
		panic(err)
	}
	send(msg)
}

func (s *Session) deliverInitHello(msg Message, send Sender) error {
	// TODO: select cipher suite
	hs, err := noise.NewHandshakeState(noise.Config{
		Initiator:   false,
		Pattern:     noise.HandshakeNN,
		CipherSuite: cipherSuites[cipherSuiteNames[0]],
	})
	if err != nil {
		panic(err)
	}
	s.hs = hs
	payload, _, _, err := hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return err
	}
	// TODO: use initHello
	_, err = parseInitHello(payload)
	if err != nil {
		return err
	}
	s.sendRespHello(send)
	return nil
}

func (s *Session) sendRespHello(send Sender) {
	msg := newMessage(RespToInit, 1)
	cb := s.hs.ChannelBinding()
	msg, cs1, cs2, err := s.hs.WriteMessage(msg, marshal(nil, &RespHello{
		CipherSuite: cipherSuiteNames[0],
		AuthClaim:   s.makeAuthClaim(cb),
	}))
	if err != nil {
		panic(err)
	}
	s.cipherOut, s.cipherIn = pickCS(s.isInit, cs1, cs2)
	send(msg)
}

func (s *Session) deliverRespHello(msg Message, send Sender) error {
	cb := append([]byte{}, s.hs.ChannelBinding()...)
	helloBytes, cs1, cs2, err := s.hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return err
	}
	respHello, err := parseRespHello(helloBytes)
	if err != nil {
		return err
	}
	pubKey, err := p2p.ParsePublicKey(respHello.AuthClaim.KeyX509)
	if err != nil {
		return err
	}
	if err := p2p.Verify(pubKey, purpose, cb, respHello.AuthClaim.Sig); err != nil {
		return err
	}
	s.cipherOut, s.cipherIn = pickCS(s.isInit, cs1, cs2)
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	s.sendInitDone(send)
	return nil
}

func (s *Session) sendInitDone(send Sender) {
	authClaim := s.makeAuthClaim(s.hs.ChannelBinding())
	msg := newMessage(s.outgoingDirection(), nonceInitDone)
	out := s.cipherOut.Encrypt(msg, nonceInitDone, msg, marshal(nil, &InitDone{
		AuthClaim: authClaim,
	}))
	send(out)
}

func (s *Session) deliverInitDone(msg Message) error {
	if s.cipherIn == nil {
		return errors.Errorf("initDone too early")
	}
	ptext, err := s.cipherIn.Decrypt(nil, uint64(msg.GetNonce()), msg.HeaderBytes(), msg.Body())
	if err != nil {
		return err
	}
	initDone, err := parseInitDone(ptext)
	if err != nil {
		return err
	}
	pubKey, err := p2p.ParsePublicKey(initDone.AuthClaim.KeyX509)
	if err != nil {
		return err
	}
	cb := s.hs.ChannelBinding()
	if err := p2p.Verify(pubKey, purpose, cb, initDone.AuthClaim.Sig); err != nil {
		return err
	}
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	return nil
}

// Deliver gives the session a message.
// If there is data in the message it will be returned as a non nil slice, appended to out.
// If there is not data, then a nil slice, and nil error will be returned.
func (s *Session) Deliver(out []byte, incoming []byte, now time.Time, send Sender) ([]byte, error) {
	if err := s.checkExpired(now); err != nil {
		return nil, err
	}
	msg, err := ParseMessage(incoming)
	if err != nil {
		return nil, err
	}
	nonce := msg.GetNonce()
	if s.remoteKey == nil {
		switch nonce {
		case 0:
			return nil, s.deliverInitHello(msg, send)
		case 1:
			return nil, s.deliverRespHello(msg, send)
		case 2:
			return nil, s.deliverInitDone(msg)
		default:
			s.log.Warnf("p2pke: received data before handshake has completed. nonce=%v", nonce)
			return nil, nil
		}
	} else {
		if nonce < noncePostHandshake {
			s.log.Warnf("p2pke: late handshake message. nonce=%v", nonce)
			return nil, nil
		}
		out, err := s.cipherIn.Decrypt(out, uint64(nonce), msg.HeaderBytes(), msg.Body())
		if err != nil {
			return nil, err
		}
		if !s.rp.ValidateCounter(uint64(nonce), MaxNonce) {
			return nil, nil
		}
		return out, nil
	}
}

func (s *Session) Send(ptext []byte, now time.Time, send Sender) error {
	if err := s.checkExpired(now); err != nil {
		return err
	}
	if s.cipherOut == nil {
		return errors.Errorf("handshake has not completed")
	}
	nonce := s.nonce
	s.nonce++
	msg := newMessage(s.outgoingDirection(), nonce)
	msg = s.cipherOut.Encrypt(msg, uint64(nonce), msg, ptext)
	send(msg)
	return nil
}

func (s *Session) IsReady() bool {
	return s.remoteKey != nil
}

func (s *Session) RemoteKey() p2p.PublicKey {
	return s.remoteKey
}

func (s *Session) Close() error {
	return nil
}

func (s *Session) outgoingDirection() Direction {
	if s.isInit {
		return InitToResp
	} else {
		return RespToInit
	}
}

func (s *Session) makeAuthClaim(cb []byte) *AuthClaim {
	sig, err := p2p.Sign(nil, s.privateKey, purpose, cb)
	if err != nil {
		panic(err)
	}
	return &AuthClaim{
		KeyX509: p2p.MarshalPublicKey(s.privateKey.Public()),
		Sig:     sig,
	}
}

func (s *Session) checkExpired(now time.Time) error {
	if now.Sub(s.createdAt) > MaxSessionDuration {
		return ErrSessionExpired{}
	}
	return nil
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCipher, inCipher noise.Cipher) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCipher = cs1.Cipher()
	inCipher = cs2.Cipher()
	return outCipher, inCipher
}
