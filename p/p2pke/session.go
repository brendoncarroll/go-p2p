package p2pke

import (
	"crypto/rand"
	"io"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
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
	expiresAt  time.Time

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
		expiresAt:  params.Now.Add(MaxSessionDuration),
		rp:         &replay.Filter{},
	}
	return s
}

func (s *Session) StartHandshake(out []byte) []byte {
	if s.isInit {
		return s.sendInit(out)
	}
	return nil
}

func (s *Session) sendInit(out []byte) []byte {
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
	return append(out, msg...)
}

func (s *Session) deliverInitHello(out []byte, msg Message) ([]byte, error) {
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
		return nil, err
	}
	// TODO: use initHello
	_, err = parseInitHello(payload)
	if err != nil {
		return nil, err
	}
	return s.sendRespHello(out), nil
}

func (s *Session) sendRespHello(out []byte) []byte {
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
	return append(out, msg...)
}

func (s *Session) deliverRespHello(out []byte, msg Message) ([]byte, error) {
	cb := append([]byte{}, s.hs.ChannelBinding()...)
	helloBytes, cs1, cs2, err := s.hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return nil, err
	}
	respHello, err := parseRespHello(helloBytes)
	if err != nil {
		return nil, err
	}
	pubKey, err := p2p.ParsePublicKey(respHello.AuthClaim.KeyX509)
	if err != nil {
		return nil, err
	}
	xof := s.makeAuthClaimXOF()
	if _, err := xof.Write(cb); err != nil {
		return nil, err
	}
	if err := p2p.VerifyXOF(pubKey, xof, respHello.AuthClaim.Sig); err != nil {
		return nil, err
	}
	s.cipherOut, s.cipherIn = pickCS(s.isInit, cs1, cs2)
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	return s.sendInitDone(out), nil
}

func (s *Session) sendInitDone(out []byte) []byte {
	authClaim := s.makeAuthClaim(s.hs.ChannelBinding())
	msg := newMessage(s.outgoingDirection(), nonceInitDone)
	msg = s.cipherOut.Encrypt(msg, nonceInitDone, msg, marshal(nil, &InitDone{
		AuthClaim: authClaim,
	}))
	return append(out, msg...)
}

func (s *Session) deliverInitDone(msg Message) error {
	if s.cipherIn == nil {
		return errors.Errorf("initDone too early")
	}
	ptext, err := s.cipherIn.Decrypt(nil, uint64(msg.GetNonce()), msg.HeaderBytes(), msg.Body())
	if err != nil {
		return errors.Wrapf(err, "delivering initDone")
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
	xof := s.makeAuthClaimXOF()
	if _, err := xof.Write(cb); err != nil {
		return err
	}
	if err := p2p.VerifyXOF(pubKey, xof, initDone.AuthClaim.Sig); err != nil {
		return err
	}
	s.remoteKey = pubKey
	s.nonce = noncePostHandshake
	return nil
}

// Deliver gives the session a message.
// If there is data in the message it will be returned as a non nil slice, appended to out.
// If there is not data, then a nil slice, and nil error will be returned.
//
// out, isApp err := s.Deliver(out, incoming, now)
// if err != nil {
// 		// handle err
// }
// if !isApp && len(out) > 0 {
//
// } else if isApp {
//
// }
func (s *Session) Deliver(out []byte, incoming []byte, now time.Time) (bool, []byte, error) {
	if err := s.checkExpired(now); err != nil {
		return false, nil, err
	}
	msg, err := ParseMessage(incoming)
	if err != nil {
		return false, nil, err
	}
	nonce := msg.GetNonce()
	if s.remoteKey == nil {
		var ret []byte
		var err error
		switch nonce {
		case 0:
			ret, err = s.deliverInitHello(out, msg)
		case 1:
			ret, err = s.deliverRespHello(out, msg)
		case 2:
			err = s.deliverInitDone(msg)
		default:
			s.log.Warnf("p2pke: received data before handshake has completed. nonce=%v", nonce)
			return false, nil, nil
		}
		return false, ret, err
	} else {
		if nonce < noncePostHandshake {
			s.log.Warnf("p2pke: late handshake message. nonce=%v", nonce)
			return false, nil, nil
		}
		out, err := s.cipherIn.Decrypt(out, uint64(nonce), msg.HeaderBytes(), msg.Body())
		if err != nil {
			return false, nil, errors.Wrapf(err, "decryption failure nonce=%v", nonce)
		}
		if !s.rp.ValidateCounter(uint64(nonce), MaxNonce) {
			return false, nil, nil
		}
		return true, out, nil
	}
}

func (s *Session) Send(out, ptext []byte, now time.Time) ([]byte, error) {
	if err := s.checkExpired(now); err != nil {
		return nil, err
	}
	if s.cipherOut == nil {
		return nil, errors.Errorf("handshake has not completed")
	}
	nonce := s.nonce
	s.nonce++
	msg := newMessage(s.outgoingDirection(), nonce)
	out = append(out, msg...)
	out = s.cipherOut.Encrypt(out, uint64(nonce), msg, ptext)
	return out, nil
}

func (s *Session) IsReady() bool {
	return s.remoteKey != nil
}

func (s *Session) RemoteKey() p2p.PublicKey {
	return s.remoteKey
}

func (s *Session) ExpiresAt() time.Time {
	return s.expiresAt
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
	xof := s.makeAuthClaimXOF()
	if _, err := xof.Write(cb); err != nil {
		panic(err)
	}
	sig, err := p2p.SignXOF(nil, s.privateKey, rand.Reader, xof)
	if err != nil {
		panic(err)
	}
	return &AuthClaim{
		KeyX509: p2p.MarshalPublicKey(s.privateKey.Public()),
		Sig:     sig,
	}
}

func (s *Session) checkExpired(now time.Time) error {
	if now.After(s.expiresAt) {
		return ErrSessionExpired{}
	}
	return nil
}

// makeAuthClaimXOF creates an XOF and writes the auth claim purpose to it
// then returns it.
// The XOF will be created using the same cryptographic primitive used for the handshake.
// Right now, that will always be blake2b.
func (s *Session) makeAuthClaimXOF() io.ReadWriter {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}
	if _, err := xof.Write([]byte(purpose)); err != nil {
		panic(err)
	}
	return xof
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCipher, inCipher noise.Cipher) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCipher = cs1.Cipher()
	inCipher = cs2.Cipher()
	return outCipher, inCipher
}
