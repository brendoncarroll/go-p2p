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

func NewSession(isInit bool, privateKey p2p.PrivateKey, sendFunc Sender) *Session {
	s := &Session{
		privateKey: privateKey,
		isInit:     isInit,
		send:       sendFunc,
		log:        logrus.StandardLogger(),
	}
	return s
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
		PSKHash:      nil,
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
	helloBytes, _, _, err := hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return err
	}
	// TODO: use initHello
	_, err = parseInitHello(helloBytes)
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
		PSKUsed:     false,
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
	s.sendAuthProof()
	return nil
}

func (s *Session) sendAuthProof() {
	authProof := s.makeAuthProof(s.hs.ChannelBinding())
	msg := newMessage(s.outgoingDirection(), nonceAuthProof)
	out := s.cipherOut.Encrypt(msg, nonceAuthProof, msg, marshal(nil, authProof))
	s.send(out)
}

func (s *Session) deliverAuthProof(msg Message) error {
	if s.cipherIn == nil {
		return errors.Errorf("auth proof too early")
	}
	ptext, err := s.cipherIn.Decrypt(nil, uint64(msg.GetNonce()), msg.NonceBytes(), msg.Body())
	if err != nil {
		return err
	}
	authProof, err := parseAuthProof(ptext)
	if err != nil {
		return err
	}
	pubKey, err := p2p.ParsePublicKey(authProof.KeyX509)
	if err != nil {
		return err
	}
	cb := s.hs.ChannelBinding()
	if err := p2p.Verify(pubKey, purpose, cb, authProof.Sig); err != nil {
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
			return nil, s.deliverAuthProof(msg)
		default:
			s.log.Warnf("p2pke: received data before handshake has completed. nonce=%v", nonce)
			return nil, nil
		}
	} else {
		if nonce < noncePostHandshake {
			s.log.Warnf("p2pke: late handshake message. nonce=%v", nonce)
			return nil, nil
		}
		out, err := s.cipherIn.Decrypt(out, uint64(nonce), msg.NonceBytes(), msg.Body())
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

func (s *Session) incomingDirection() Direction {
	if s.isInit {
		return RespToInit
	} else {
		return InitToResp
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
