package p2pke

import (
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-tai64"
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
	expiresAt  time.Time

	// handshake
	hsIndex       uint8
	msgCache      [3][]byte
	hs            *noise.HandshakeState
	initHelloTime tai64.TAI64N
	remoteKey     p2p.PublicKey

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
	hs, err := noise.NewHandshakeState(noise.Config{
		Initiator:   params.IsInit,
		Pattern:     noise.HandshakeNN,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
	})
	if err != nil {
		panic(err)
	}
	s := &Session{
		privateKey: params.PrivateKey,
		isInit:     params.IsInit,
		log:        params.Logger,
		expiresAt:  params.Now.Add(MaxSessionDuration),
		hs:         hs,
		rp:         &replay.Filter{},
	}
	if s.isInit {
		s.msgCache[0] = writeInitHello(nil, s.hs, s.privateKey, tai64.FromGoTime(params.Now))
	}
	return s
}

// Handshake appends the current handshake message to out.
// Handshake returns nil if there is no handshake message to send.
func (s *Session) Handshake(out []byte) []byte {
	return s.writeHandshake(out)
}

// Deliver gives the session a message.
// If there is data in the message it will be returned as a non nil slice, appended to out.
// If there is not data, then a nil slice, and nil error will be returned.
//
// isApp, out, err := s.Deliver(out, incoming, now)
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
	switch nonce {
	case 0, 1, 2:
		if err := s.readHandshake(msg); err != nil {
			return false, nil, errors.Wrap(err, "readHandshake")
		}
		return false, s.writeHandshake(out), nil
	default:
		if s.remoteKey == nil {
			return false, nil, errors.New("p2pke: data before handshake complete")
		}
		s.hsIndex = 3
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

// Send encrypts ptext and appends the ciphertext to out, returning out.
// It is an error to call Send before the handshake has completed.
func (s *Session) Send(out, ptext []byte, now time.Time) ([]byte, error) {
	if err := s.checkExpired(now); err != nil {
		return nil, err
	}
	if s.hsIndex < 2 {
		return nil, errors.New("handshake has not completed")
	}
	nonce := s.nonce
	s.nonce++
	msg := newMessage(s.outgoingDirection(), nonce)
	out = append(out, msg...)
	out = s.cipherOut.Encrypt(out, uint64(nonce), msg, ptext)
	return out, nil
}

// IsReady returns true if the session is ready to send data.
func (s *Session) IsReady() bool {
	return s.remoteKey != nil
}

func (s *Session) RemoteKey() p2p.PublicKey {
	return s.remoteKey
}

func (s *Session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *Session) InitHelloTime() tai64.TAI64N {
	return s.initHelloTime
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

func (s *Session) checkExpired(now time.Time) error {
	if now.After(s.expiresAt) {
		return ErrSessionExpired{}
	}
	return nil
}

// writeHandshake writes the current handshake message to out.
func (s *Session) writeHandshake(out []byte) []byte {
	switch {
	case s.hsIndex >= 3:
		// handshake is over; we have received a message through the symmetric channel
		// from the other party.
		return nil
	case s.isInit && s.hsIndex == 0:
		if s.msgCache[0] == nil {
			panic("writeHandshake without init")
		}
		return s.msgCache[0]
	case !s.isInit && s.hsIndex == 1:
		if s.msgCache[1] == nil {
			panic("writeHandshake called before readHandshake")
		}
		return append(out, s.msgCache[1]...)
	case s.isInit && s.hsIndex == 2:
		if s.msgCache[2] == nil {
			panic("writeHandshake called before readHandshake")
		}
		return append(out, s.msgCache[2]...)
	default:
		return nil
	}
}

// readHandshake is idempotent. It can only advance the state of the session.
func (s *Session) readHandshake(msg Message) error {
	switch {
	case s.hsIndex >= 3:
		return nil
	case !s.isInit && s.hsIndex == 0 && msg.GetNonce() == nonceInitHello:
		res, err := readInitHello(s.hs, s.privateKey, msg)
		if err != nil {
			return err
		}
		s.initHelloTime = res.Timestamp
		s.msgCache[1] = res.RespHello
		s.cipherOut, s.cipherIn = res.CipherOut, res.CipherIn
		s.hsIndex = 1
	case s.isInit && s.hsIndex == 0 && msg.GetNonce() == nonceRespHello:
		res, err := readRespHello(s.hs, s.privateKey, msg)
		if err != nil {
			return err
		}
		s.msgCache[2] = res.InitDone
		s.cipherOut, s.cipherIn = res.CipherOut, res.CipherIn
		s.hsIndex = 2 // the initiator doesn't know if the server got the initDone yet.
		s.nonce = noncePostHandshake
		s.remoteKey = res.RemoteKey
	case !s.isInit && s.hsIndex == 1 && msg.GetNonce() == nonceInitDone:
		res, err := readInitDone(s.hs, s.cipherIn, msg)
		if err != nil {
			return err
		}
		s.remoteKey = res.RemoteKey
		s.hsIndex = 3
		s.nonce = noncePostHandshake
	}
	return nil
}

// writeInit writes an InitHello message to out using hs, and initHelloTime
func writeInitHello(out []byte, hs *noise.HandshakeState, privateKey p2p.PrivateKey, initHelloTime tai64.TAI64N) []byte {
	msg := newMessage(InitToResp, 0)
	tsBytes := initHelloTime.Marshal()
	var err error
	msg, _, _, err = hs.WriteMessage(msg, marshal(nil, &InitHello{
		CipherSuites:    cipherSuiteNames,
		TimestampTai64N: tsBytes[:],
		AuthClaim:       makeTAI64NAuthClaim(privateKey, initHelloTime),
	}))
	if err != nil {
		panic(err)
	}
	return append(out, msg...)
}

type initHelloResult struct {
	CipherOut, CipherIn noise.Cipher
	Timestamp           tai64.TAI64N
	RespHello           []byte
}

// readInitHello
func readInitHello(hs *noise.HandshakeState, privateKey p2p.PrivateKey, msg Message) (*initHelloResult, error) {
	payload, _, _, err := hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return nil, err
	}
	hello, err := parseInitHello(payload)
	if err != nil {
		return nil, err
	}
	timestamp, err := tai64.ParseN(hello.TimestampTai64N)
	if err != nil {
		return nil, err
	}
	if hello.AuthClaim == nil {
		return nil, errors.Errorf("InitHello missing auth claim")
	}
	if err := verifyAuthClaim(purposeTimestamp, hello.AuthClaim, hello.TimestampTai64N); err != nil {
		return nil, errors.Wrapf(err, "validating InitHello")
	}
	// prepare response
	msg2 := newMessage(RespToInit, 1)
	cb := hs.ChannelBinding()
	msg2, cs1, cs2, err := hs.WriteMessage(msg2, marshal(nil, &RespHello{
		CipherSuite: cipherSuiteNames[0],
		AuthClaim:   makeChannelAuthClaim(privateKey, cb),
	}))
	if err != nil {
		panic(err)
	}
	cipherOut, cipherIn := pickCS(false, cs1, cs2)
	return &initHelloResult{
		CipherOut: cipherOut,
		CipherIn:  cipherIn,
		Timestamp: timestamp,
		RespHello: msg2,
	}, nil
}

// respHelloResult is the result of processing a RespHello message
type respHelloResult struct {
	CipherOut, CipherIn noise.Cipher
	RemoteKey           p2p.PublicKey
	InitDone            []byte
}

func readRespHello(hs *noise.HandshakeState, privateKey p2p.PrivateKey, msg Message) (*respHelloResult, error) {
	cb := append([]byte{}, hs.ChannelBinding()...)
	helloBytes, cs1, cs2, err := hs.ReadMessage(nil, msg.Body())
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
	if err := p2p.Verify(pubKey, purposeChannelBinding, cb, respHello.AuthClaim.Sig); err != nil {
		return nil, err
	}
	cipherOut, cipherIn := pickCS(true, cs1, cs2)
	authClaim := makeChannelAuthClaim(privateKey, hs.ChannelBinding())
	msg2 := newMessage(InitToResp, nonceInitDone)
	msg2 = cipherOut.Encrypt(msg2, uint64(nonceInitDone), msg2, marshal(nil, &InitDone{
		AuthClaim: authClaim,
	}))
	if err != nil {
		panic(err)
	}
	return &respHelloResult{
		CipherIn:  cipherIn,
		CipherOut: cipherOut,
		RemoteKey: pubKey,
		InitDone:  msg2,
	}, nil
}

// initDoneResult is returned by readInitDone
type initDoneResult struct {
	RemoteKey p2p.PublicKey
}

func readInitDone(hs *noise.HandshakeState, cipherIn noise.Cipher, msg Message) (*initDoneResult, error) {
	ptext, err := cipherIn.Decrypt(nil, uint64(nonceInitDone), msg.HeaderBytes(), msg.Body())
	if err != nil {
		return nil, errors.Wrapf(err, "readInitDone")
	}
	initDone, err := parseInitDone(ptext)
	if err != nil {
		return nil, err
	}
	pubKey, err := p2p.ParsePublicKey(initDone.AuthClaim.KeyX509)
	if err != nil {
		return nil, err
	}
	cb := hs.ChannelBinding()
	if err := verifyAuthClaim(purposeChannelBinding, initDone.AuthClaim, cb); err != nil {
		return nil, err
	}
	return &initDoneResult{
		RemoteKey: pubKey,
	}, nil
}

func makeChannelAuthClaim(privateKey p2p.PrivateKey, cb []byte) *AuthClaim {
	sig, err := p2p.Sign(nil, privateKey, purposeChannelBinding, cb)
	if err != nil {
		panic(err)
	}
	return &AuthClaim{
		KeyX509: p2p.MarshalPublicKey(privateKey.Public()),
		Sig:     sig,
	}
}

func makeTAI64NAuthClaim(privateKey p2p.PrivateKey, timestamp tai64.TAI64N) *AuthClaim {
	tsBytes := timestamp.Marshal()
	sig, err := p2p.Sign(nil, privateKey, purposeTimestamp, tsBytes[:])
	if err != nil {
		panic(err)
	}
	return &AuthClaim{
		KeyX509: p2p.MarshalPublicKey(privateKey.Public()),
		Sig:     sig,
	}
}

func verifyAuthClaim(purpose string, ac *AuthClaim, data []byte) error {
	pubKey, err := p2p.ParsePublicKey(ac.KeyX509)
	if err != nil {
		return err
	}
	return p2p.Verify(pubKey, purpose, data, ac.Sig)
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCipher, inCipher noise.Cipher) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCipher = cs1.Cipher()
	inCipher = cs2.Cipher()
	return outCipher, inCipher
}
