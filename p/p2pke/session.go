package p2pke

import (
	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/replay"
)

type Sender func([]byte)

type Session struct {
	privateKey p2p.PrivateKey
	send       Sender
	isInit     bool
	log        *logrus.Logger

	// handshake
	hs        *noise.HandshakeState
	remoteKey p2p.PublicKey

	// ciphers
	cipherOut, cipherIn noise.Cipher
	nonce               uint32
	rp                  *replay.Filter
}

type Params struct {
	IsInit     bool
	PrivateKey p2p.PrivateKey
	Send       Sender
	Logger     *logrus.Logger
}

func NewSession(params Params) *Session {
	if params.Logger == nil {
		params.Logger = logrus.StandardLogger()
	}
	s := &Session{
		privateKey: params.PrivateKey,
		isInit:     params.IsInit,
		send:       params.Send,
		log:        params.Logger,
	}
	return s
}

func (s *Session) StartHandshake() {
	if s.isInit {
		s.sendInit()
	}
}

func (s *Session) sendInit() {
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
	msg, _, _, err = s.hs.WriteMessage(msg, marshal(nil, InitHello{
		CipherSuites: cipherSuiteNames,
	}))
	if err != nil {
		panic(err)
	}
	s.send(msg)
}

func (s *Session) deliverInitHello(msg Message) error {
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
	s.sendRespHello()
	return nil
}

func (s *Session) sendRespHello() {
	msg := newMessage(RespToInit, 1)
	cb := s.hs.ChannelBinding()
	msg, cs1, cs2, err := s.hs.WriteMessage(msg, marshal(nil, &RespHello{
		CipherSuite: cipherSuiteNames[0],
		AuthProof:   s.makeAuthProof(cb),
	}))
	if err != nil {
		panic(err)
	}
	s.cipherOut, s.cipherIn = pickCS(s.isInit, cs1, cs2)
	s.send(msg)
}

func (s *Session) deliverRespHello(msg Message) error {
	cb := append([]byte{}, s.hs.ChannelBinding()...)
	helloBytes, cs1, cs2, err := s.hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return err
	}
	// TODO: use resp hello
	respHello, err := parseRespHello(helloBytes)
	if err != nil {
		return err
	}
	pubKey, err := p2p.ParsePublicKey(respHello.AuthProof.KeyX509)
	if err != nil {
		return err
	}
	if err := p2p.Verify(pubKey, purpose, cb, respHello.AuthProof.Sig); err != nil {
		return err
	}
	s.cipherOut, s.cipherIn = pickCS(s.isInit, cs1, cs2)
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	s.sendInitDone()
	return nil
}

func (s *Session) sendInitDone() {
	authProof := s.makeAuthProof(s.hs.ChannelBinding())
	msg := newMessage(s.outgoingDirection(), nonceInitDone)
	out := s.cipherOut.Encrypt(msg, nonceInitDone, msg, marshal(nil, InitDone{
		AuthProof: authProof,
	}))
	s.send(out)
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
	pubKey, err := p2p.ParsePublicKey(initDone.AuthProof.KeyX509)
	if err != nil {
		return err
	}
	cb := s.hs.ChannelBinding()
	if err := p2p.Verify(pubKey, purpose, cb, initDone.AuthProof.Sig); err != nil {
		return err
	}
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	return nil
}

// Deliver gives the session a message.
// If there is data in the message it will be returned as a non nil slice, appended to out.
// If there is not data, then a nil slice, and nil error will be returned.
func (s *Session) Deliver(out []byte, incoming []byte) ([]byte, error) {
	msg, err := ParseMessage(incoming)
	if err != nil {
		return nil, err
	}
	nonce := msg.GetNonce()
	if s.remoteKey == nil {
		switch nonce {
		case 0:
			return nil, s.deliverInitHello(msg)
		case 1:
			return nil, s.deliverRespHello(msg)
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

func (s *Session) Send(ptext []byte) error {
	if s.cipherOut == nil {
		return errors.Errorf("handshake has not completed")
	}
	nonce := s.nonce
	s.nonce++
	msg := newMessage(s.outgoingDirection(), nonce)
	msg = s.cipherOut.Encrypt(msg, uint64(nonce), msg, ptext)
	s.send(msg)
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

func (s *Session) makeAuthProof(cb []byte) AuthProof {
	sig, err := p2p.Sign(nil, s.privateKey, purpose, cb)
	if err != nil {
		panic(err)
	}
	return AuthProof{
		KeyX509: p2p.MarshalPublicKey(s.privateKey.Public()),
		Sig:     sig,
	}
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCipher, inCipher noise.Cipher) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCipher = cs1.Cipher()
	inCipher = cs2.Cipher()
	return outCipher, inCipher
}
