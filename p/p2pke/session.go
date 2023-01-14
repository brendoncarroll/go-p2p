package p2pke

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"time"

	"github.com/brendoncarroll/go-tai64"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/replay"

	"github.com/brendoncarroll/go-p2p/f/x509"
)

type Session struct {
	registry   x509.Registry
	privateKey privateKey
	isInit     bool
	log        *slog.Logger
	expiresAt  time.Time

	// handshake
	hsIndex       uint8
	msgCache      [4][]byte
	hs            *noise.HandshakeState
	initHelloTime tai64.TAI64N
	remoteKey     publicKey

	// ciphers
	cipherOut, cipherIn noise.Cipher
	nonce               uint64
	rp                  *replay.Filter
}

// SessionConfig configures a session all the parameters are required.
type SessionConfig struct {
	Registry    x509.Registry
	PrivateKey  x509.PrivateKey
	IsInit      bool
	Now         time.Time
	RejectAfter time.Duration
	Logger      *slog.Logger
}

func NewSession(params SessionConfig) *Session {
	hs, err := noise.NewHandshakeState(noise.Config{
		Initiator:   params.IsInit,
		Pattern:     noise.HandshakeNN,
		CipherSuite: v1CipherSuite,
	})
	if err != nil {
		panic(err)
	}
	s := &Session{
		registry: params.Registry,
		privateKey: privateKey{
			Registry: params.Registry,
			Key:      params.PrivateKey,
		},
		isInit:    params.IsInit,
		log:       params.Logger,
		expiresAt: params.Now.Add(params.RejectAfter),
		hs:        hs,
		rp:        &replay.Filter{},
	}
	if s.isInit {
		s.initHelloTime = tai64.FromGoTime(params.Now)
		s.msgCache[0] = writeInitHello(nil, s.hs, &s.privateKey, s.initHelloTime)
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
//
//	if err != nil {
//			// handle err
//	}
//
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
	case 0, 1, 2, 3:
		if err := s.readHandshake(msg); err != nil {
			return false, nil, errors.Wrapf(err, "processing handshake message")
		}
		return false, s.writeHandshake(out), nil
	default:
		if !s.canReceive() {
			return false, nil, ErrEarlyData{State: s.hsIndex, Nonce: nonce}
		}
		out, err := s.cipherIn.Decrypt(out, uint64(nonce), msg.HeaderBytes(), msg.Body())
		if err != nil {
			return false, nil, ErrDecryptionFailure{Nonce: nonce, NoiseErr: err}
		}
		if !s.rp.ValidateCounter(uint64(nonce), MaxNonce) {
			return false, nil, nil
		}
		s.hsIndex = 8 // successfully received a packet
		return true, out, nil
	}
}

// Send encrypts ptext and appends the ciphertext to out, returning out.
// It is an error to call Send before the handshake has completed.
func (s *Session) Send(out, ptext []byte, now time.Time) ([]byte, error) {
	if err := s.checkExpired(now); err != nil {
		return nil, err
	}
	if !s.canSend() {
		return nil, errors.New("handshake has not completed")
	}
	if atomic.LoadUint64(&s.nonce) >= MaxNonce {
		return nil, errors.New("session has hit message limit")
	}
	nonce := atomic.AddUint64(&s.nonce, 1) - 1
	msg := newMessage(uint32(nonce))
	out = append(out, msg...)
	out = s.cipherOut.Encrypt(out, nonce, msg, ptext)
	return out, nil
}

// IsReady returns true if the session is ready to send data.
func (s *Session) IsReady() bool {
	return s.canSend() && s.canReceive()
}

func (s *Session) LocalKey() x509.PublicKey {
	return s.privateKey.Public().Key
}

func (s *Session) RemoteKey() x509.PublicKey {
	return s.remoteKey.Key
}

func (s *Session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *Session) IsInit() bool {
	return s.isInit
}

func (s *Session) InitHelloTime() tai64.TAI64N {
	return s.initHelloTime
}

func (s *Session) canSend() bool {
	return (s.isInit && s.hsIndex >= nonceRespDone) || (!s.isInit && s.hsIndex >= nonceInitDone)
}

func (s *Session) canReceive() bool {
	return s.hsIndex >= nonceInitDone
}

func (s *Session) checkExpired(now time.Time) error {
	if now.After(s.expiresAt) {
		return ErrSessionExpired{ExpiredAt: s.expiresAt}
	}
	if s.nonce >= MaxNonce {
		return errors.New("session has exceeded message limit")
	}
	return nil
}

func (s *Session) String() string {
	m0Hash := blake2b.Sum256(s.msgCache[0])
	return fmt.Sprintf("Session(init=%v, helloTime=%v m0Hash=%x)", s.isInit, s.initHelloTime, m0Hash[:4])
}

// writeHandshake writes the current handshake message to out.
func (s *Session) writeHandshake(out []byte) []byte {
	switch {
	case s.hsIndex >= 4:
		// handshake is over; we have received a message through the symmetric channel
		// from the other party.
		return nil
	case s.isInit && s.hsIndex == 0:
		if s.msgCache[0] == nil {
			panic("writeHandshake without init")
		}
		return append(out, s.msgCache[0]...)
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
	case !s.isInit && s.hsIndex == 3:
		if s.msgCache[3] == nil {
			panic("writeHandshake called before readHandshake")
		}
		return append(out, s.msgCache[3]...)
	default:
		return nil
	}
}

// readHandshake is idempotent. Each message can only affect the session once
func (s *Session) readHandshake(msg Message) error {
	nonce := msg.GetNonce()
	switch {
	case !s.isInit && s.hsIndex == 0 && nonce == nonceInitHello:
		res, err := readInitHello(s.registry, s.hs, &s.privateKey, msg)
		if err != nil {
			return err
		}
		s.remoteKey = res.RemoteKey
		s.initHelloTime = res.Timestamp
		s.msgCache[1] = res.RespHello
		s.cipherOut, s.cipherIn = res.CipherOut, res.CipherIn
		s.hsIndex = 1

	case s.isInit && s.hsIndex == 0 && nonce == nonceRespHello:
		res, err := readRespHello(s.registry, s.hs, &s.privateKey, msg)
		if err != nil {
			return err
		}
		s.msgCache[2] = res.InitDone
		s.cipherOut, s.cipherIn = res.CipherOut, res.CipherIn
		s.remoteKey = res.RemoteKey
		s.hsIndex = 2 // the initiator doesn't know if the server got the initDone yet.
	case !s.isInit && s.hsIndex == 1 && nonce == nonceInitDone:
		res, err := readInitDone(s.hs, &s.remoteKey, s.cipherIn, s.cipherOut, msg)
		if err != nil {
			return err
		}
		s.msgCache[3] = res.RespDone
		s.nonce = noncePostHandshake
		s.hsIndex = 3
	case s.isInit && s.hsIndex == 2 && nonce == nonceRespDone:
		if err := readRespDone(s.cipherIn, msg); err != nil {
			return err
		}
		s.hsIndex = 4
		s.nonce = noncePostHandshake
	case (s.isInit && nonce%2 == 1) || (!s.isInit && nonce%2 == 0):
		return nil
	default:
		return errors.New("message not for this session")
	}
	return nil
}

// writeInit writes an InitHello message to out using hs, and initHelloTime
func writeInitHello(out []byte, hs *noise.HandshakeState, privateKey *privateKey, initHelloTime tai64.TAI64N) []byte {
	msg := newMessage(0)
	tsBytes := initHelloTime.Marshal()
	var err error
	keyX509, sig := makeTAI64NAuthClaim(privateKey, initHelloTime)
	initHelloData := marshal(nil, &InitHello{
		Version:         1,
		TimestampTai64N: tsBytes[:],
		KeyX509:         keyX509,
		Sig:             sig,
	})
	initHelloData = appendUint16(initHelloData, uint16(len(initHelloData)))
	msg, _, _, err = hs.WriteMessage(msg, initHelloData)
	if err != nil {
		panic(err)
	}
	return append(out, msg...)
}

type initHelloResult struct {
	CipherOut, CipherIn noise.Cipher
	Timestamp           tai64.TAI64N
	RemoteKey           publicKey
	RespHello           []byte
}

// readInitHello
func readInitHello(reg x509.Registry, hs *noise.HandshakeState, privateKey *privateKey, msg Message) (*initHelloResult, error) {
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
	pubKey, err := verifyAuthClaim(reg, purposeTimestamp, hello.KeyX509, hello.TimestampTai64N, hello.Sig)
	if err != nil {
		return nil, errors.Wrapf(err, "validating InitHello")
	}
	// prepare response
	msg2 := newMessage(1)
	cb := hs.ChannelBinding()
	keyX509, sig := makeChannelAuthClaim(privateKey, cb)
	msg2, cs1, cs2, err := hs.WriteMessage(msg2, marshal(nil, &RespHello{
		KeyX509: keyX509,
		Sig:     sig,
	}))
	if err != nil {
		panic(err)
	}
	cipherOut, cipherIn := pickCS(false, cs1, cs2)
	return &initHelloResult{
		CipherOut: cipherOut,
		CipherIn:  cipherIn,
		Timestamp: timestamp,
		RemoteKey: pubKey,
		RespHello: msg2,
	}, nil
}

// respHelloResult is the result of processing a RespHello message
type respHelloResult struct {
	CipherOut, CipherIn noise.Cipher
	RemoteKey           publicKey
	InitDone            []byte
}

func readRespHello(reg x509.Registry, hs *noise.HandshakeState, privateKey *privateKey, msg Message) (*respHelloResult, error) {
	cb := append([]byte{}, hs.ChannelBinding()...)
	helloBytes, cs1, cs2, err := hs.ReadMessage(nil, msg.Body())
	if err != nil {
		return nil, err
	}
	respHello, err := parseRespHello(helloBytes)
	if err != nil {
		return nil, err
	}
	pubKey, err := verifyAuthClaim(reg, purposeChannelBinding, respHello.KeyX509, cb, respHello.Sig)
	if err != nil {
		return nil, err
	}
	cipherOut, cipherIn := pickCS(true, cs1, cs2)
	channelSig, err := sign(nil, privateKey, purposeChannelBinding, hs.ChannelBinding())
	if err != nil {
		return nil, err
	}
	msg2 := newMessage(nonceInitDone)
	msg2 = cipherOut.Encrypt(msg2, uint64(nonceInitDone), msg2, marshal(nil, &InitDone{
		Sig: channelSig,
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
	RemoteKey publicKey
	RespDone  []byte
}

func readInitDone(hs *noise.HandshakeState, pubKey *publicKey, cipherIn, cipherOut noise.Cipher, msg Message) (*initDoneResult, error) {
	ptext, err := cipherIn.Decrypt(nil, uint64(nonceInitDone), msg.HeaderBytes(), msg.Body())
	if err != nil {
		return nil, errors.Wrapf(err, "readInitDone")
	}
	initDone, err := parseInitDone(ptext)
	if err != nil {
		return nil, err
	}
	cb := hs.ChannelBinding()
	if err := verify(pubKey, purposeChannelBinding, cb, initDone.Sig); err != nil {
		return nil, err
	}
	respDone := newMessage(nonceRespDone)
	respDone = cipherOut.Encrypt(respDone, uint64(nonceRespDone), respDone.HeaderBytes(), nil)
	return &initDoneResult{
		RemoteKey: *pubKey,
		RespDone:  respDone,
	}, nil
}

func readRespDone(cipherIn noise.Cipher, msg Message) error {
	_, err := cipherIn.Decrypt(nil, uint64(nonceRespDone), msg.HeaderBytes(), msg.Body())
	return err
}

func makeChannelAuthClaim(privateKey *privateKey, cb []byte) ([]byte, []byte) {
	sig, err := sign(nil, privateKey, purposeChannelBinding, cb)
	if err != nil {
		panic(err)
	}
	pubKey := privateKey.Public()
	return x509.MarshalPublicKey(nil, &pubKey.Key), sig
}

func makeTAI64NAuthClaim(privateKey *privateKey, timestamp tai64.TAI64N) ([]byte, []byte) {
	tsBytes := timestamp.Marshal()
	sig, err := sign(nil, privateKey, purposeTimestamp, tsBytes[:])
	if err != nil {
		panic(err)
	}
	pubKey := privateKey.Public().Key
	return x509.MarshalPublicKey(nil, &pubKey), sig
}

func verifyAuthClaim(reg x509.Registry, purpose string, keyX509, data, sig []byte) (publicKey, error) {
	pubKey, err := x509.ParsePublicKey(keyX509)
	if err != nil {
		return publicKey{}, err
	}
	v, err := reg.LoadVerifier(&pubKey)
	if err != nil {
		return publicKey{}, err
	}
	if err := verify(v, purpose, data, sig); err != nil {
		return publicKey{}, err
	}
	return publicKey{Registry: reg, Key: pubKey}, nil
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCipher, inCipher noise.Cipher) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCipher = cs1.Cipher()
	inCipher = cs2.Cipher()
	return outCipher, inCipher
}

func appendUint16(x []byte, n uint16) []byte {
	x = append(x, uint8((n>>8)&0xff))
	x = append(x, uint8((n>>0)&0xff))
	return x
}

func sign(out []byte, privateKey *privateKey, purpose string, msg []byte) ([]byte, error) {
	// TODO: purpose
	presig, err := createPreSig(purpose, msg)
	if err != nil {
		return nil, err
	}
	return privateKey.Sign(out, presig[:])
}

func verify(publicKey x509.Verifier, purpose string, msg, sig []byte) error {
	presig, err := createPreSig(purpose, msg)
	if err != nil {
		return err
	}
	// TODO: purpose
	if !publicKey.Verify(presig[:], sig) {
		return errors.New("invalid signature")
	}
	return nil
}

func createPreSig(purpose string, msg []byte) (ret [64]byte, _ error) {
	if len(purpose) > math.MaxUint8 {
		return ret, fmt.Errorf("purpose is too long len=%d, max=%d", len(purpose), math.MaxUint8)
	}
	h, err := blake2b.NewXOF(64, nil)
	if err != nil {
		panic(err)
	}
	if _, err := h.Write([]byte{uint8(len(purpose))}); err != nil {
		return ret, err
	}
	if _, err := h.Write([]byte(purpose)); err != nil {
		return ret, err
	}
	if _, err := h.Write(msg); err != nil {
		return ret, err
	}
	if _, err := io.ReadFull(h, ret[:]); err != nil {
		return ret, err
	}
	return ret, nil
}
