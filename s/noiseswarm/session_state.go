package noiseswarm

import (
	"encoding/binary"
	"fmt"

	"github.com/brendoncarroll/go-p2p"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/replay"
	"google.golang.org/protobuf/proto"
)

type upwardRes struct {
	Up    []byte
	Resps []message

	Next state
	Err  error
}

type downwardRes struct {
	Down message

	Next state
	Err  error
}

type state interface {
	downward(in []byte) downwardRes
	upward(msg message) upwardRes
}

func newHandshakeState(initiator bool) *noise.HandshakeState {
	hsstate, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Initiator:   initiator,
		Pattern:     noise.HandshakeNN,
	})
	if err != nil {
		panic(err)
	}
	return hsstate
}

type awaitInitState struct {
	hsstate    *noise.HandshakeState
	privateKey p2p.PrivateKey
}

func newAwaitInitState(privateKey p2p.PrivateKey) *awaitInitState {
	return &awaitInitState{
		hsstate:    newHandshakeState(false),
		privateKey: privateKey,
	}
}

func (cur *awaitInitState) downward(in []byte) downwardRes {
	return downwardRes{
		Next: cur,
		Err:  errors.Errorf("cannot send before handshake is done"),
	}
}

func (cur *awaitInitState) upward(msg message) upwardRes {
	count := msg.getCounter()
	in := msg.getBody()
	var resps []message
	var outCS, inCS *noise.CipherState
	err := func() error {
		if count != countInit {
			return &ErrHandshake{
				Message: fmt.Sprintf("awaiting init but got non-init %d", count),
			}
		}
		_, _, _, err := cur.hsstate.ReadMessage(nil, in)
		if err != nil {
			return &ErrHandshake{
				Message: "noise errored",
				Cause:   err,
			}
		}
		counterBytes := [4]byte{}
		binary.BigEndian.PutUint32(counterBytes[:], countResp)
		out, cs1, cs2, err := cur.hsstate.WriteMessage(counterBytes[:], nil)
		if err != nil {
			return &ErrHandshake{
				Message: "noise errored",
				Cause:   err,
			}
		}
		if cs1 == nil || cs2 == nil {
			panic("no error and no cipherstates")
		}
		resps = append(resps, out)
		outCS, inCS = pickCS(false, cs1, cs2)
		// also send intro
		introBytes, err := signChannelBinding(cur.privateKey, cur.hsstate.ChannelBinding())
		if err != nil {
			return &ErrHandshake{
				Message: "could not sign the channel binding",
				Cause:   err,
			}
		}
		out = encryptMessage(outCS, countSigRespToInit, introBytes)
		resps = append(resps, out)
		return nil
	}()
	if err != nil {
		return upwardRes{Err: err, Next: newEndState(err)}
	}
	return upwardRes{
		Resps: resps,
		Next:  newAwaitSigState(outCS, inCS, cur.hsstate.ChannelBinding(), false),
	}
}

type awaitRespState struct {
	hsstate    *noise.HandshakeState
	privateKey p2p.PrivateKey
}

func newAwaitRespState(privateKey p2p.PrivateKey) *awaitRespState {
	return &awaitRespState{
		privateKey: privateKey,
		hsstate:    newHandshakeState(true),
	}
}

func (cur *awaitRespState) downward(in []byte) downwardRes {
	return downwardRes{
		Next: cur,
		Err:  errors.Errorf("cannot send before handshake is done"),
	}
}

func (cur *awaitRespState) upward(msg message) upwardRes {
	count := msg.getCounter()
	in := msg.getBody()
	var resps []message
	var outCS, inCS *noise.CipherState
	err := func() error {
		if count != countResp {
			return &ErrHandshake{
				Message: fmt.Sprintf("awaiting resp but got non-resp %d", count),
			}
		}
		_, cs1, cs2, err := cur.hsstate.ReadMessage(nil, in)
		if err != nil {
			return &ErrHandshake{
				Message: "noise errored",
				Cause:   err,
			}
		}
		if cs1 == nil || cs2 == nil {
			panic("no error and no cipherstates")
		}
		outCS, inCS = pickCS(true, cs1, cs2)
		// send intro
		introBytes, err := signChannelBinding(cur.privateKey, cur.hsstate.ChannelBinding())
		if err != nil {
			return &ErrHandshake{
				Message: "could not sign intro",
				Cause:   err,
			}
		}
		out := encryptMessage(outCS, countSigInitToResp, introBytes)
		resps = append(resps, out)
		return nil
	}()
	if err != nil {
		return upwardRes{
			Next:  newEndState(err),
			Resps: []message{makeNACK()},
			Err:   err,
		}
	}
	return upwardRes{
		Resps: resps,
		Next:  newAwaitSigState(outCS, inCS, cur.hsstate.ChannelBinding(), true),
	}
}

type awaitSigState struct {
	initiator      bool
	outCS, inCS    *noise.CipherState
	channelBinding []byte
}

func newAwaitSigState(outCS, inCS *noise.CipherState, channelBinding []byte, initiator bool) *awaitSigState {
	return &awaitSigState{
		outCS:          outCS,
		inCS:           inCS,
		channelBinding: channelBinding,
		initiator:      initiator,
	}
}

func (cur *awaitSigState) downward(in []byte) downwardRes {
	return downwardRes{
		Next: cur,
		Err:  errors.Errorf("cannot send while awaiting sig"),
	}
}

func (cur *awaitSigState) upward(msg message) upwardRes {
	count := msg.getCounter()
	in := msg.getBody()
	var remotePublicKey p2p.PublicKey
	err := func() error {
		switch {
		case count != countSigInitToResp && count != countSigRespToInit:
			return &ErrHandshake{
				Message: "awaiting sig, but got non-sig",
			}
		case cur.initiator && count == countSigInitToResp:
			fallthrough
		case !cur.initiator && count == countSigRespToInit:
			return &ErrHandshake{
				Message: "concurrent handshake",
			}
		}
		ptext, err := decryptMessage(cur.inCS, count, in)
		if err != nil {
			return &ErrHandshake{
				Message: "could not decrypt intro",
				Cause:   err,
			}
		}
		pubKey, err := verifyIntro(cur.channelBinding, ptext)
		if err != nil {
			return &ErrHandshake{
				Message: "intro was invalid",
				Cause:   err,
			}
		}
		remotePublicKey = pubKey
		return nil
	}()
	if err != nil {
		return upwardRes{
			Resps: []message{makeNACK()},
			Next:  newEndState(err),
			Err:   err,
		}
	}
	if remotePublicKey == nil {
		panic("public key is nil")
	}
	return upwardRes{
		Next: newReadyState(cur.outCS, cur.inCS, remotePublicKey),
	}
}

type readyState struct {
	outCS, inCS     *noise.CipherState
	outCount        uint32
	inFilter        *replay.Filter
	remotePublicKey p2p.PublicKey
}

func newReadyState(outCS, inCS *noise.CipherState, remotePublicKey p2p.PublicKey) *readyState {
	return &readyState{
		outCS:           outCS,
		inCS:            inCS,
		outCount:        countPostHandshake,
		inFilter:        &replay.Filter{},
		remotePublicKey: remotePublicKey,
	}
}

func (cur *readyState) downward(in []byte) downwardRes {
	count := cur.outCount
	cur.outCount++
	var next state = cur
	if count == countLastMessage {
		next = newEndState(ErrSessionExpired)
	}
	return downwardRes{
		Next: next,
		Down: encryptMessage(cur.outCS, count, in),
	}
}

func (cur *readyState) upward(msg message) upwardRes {
	count := msg.getCounter()
	in := msg.getBody()
	switch {
	case count < countPostHandshake:
		err := &ErrHandshake{Message: "handshake recieved in ready state"}
		return upwardRes{
			Err:  err,
			Next: newEndState(err),
		}
	case count == countLastMessage:
		return upwardRes{
			Next: newEndState(ErrSessionExpired),
			Err:  ErrSessionExpired,
		}
	}
	ptext, err := decryptMessage(cur.inCS, count, in)
	if err != nil {
		return upwardRes{
			Resps: []message{makeNACK()},
			Next:  cur,
			Err:   &ErrTransport{Message: "count not decrypt message", Num: count},
		}
	}
	if !cur.inFilter.ValidateCounter(uint64(count), MaxSessionMessages) {
		return upwardRes{
			Next: cur,
			Err: &ErrTransport{
				Message: "replayed counter",
				Num:     count,
			},
		}
	}
	return upwardRes{
		Next: cur,
		Up:   ptext,
	}
}

type endState struct {
	err error
}

func newEndState(err error) *endState {
	return &endState{err: err}
}

func (s *endState) downward(in []byte) downwardRes {
	return downwardRes{
		Next: s,
		Err:  s.err,
	}
}

func (s *endState) upward(msg message) upwardRes {
	var resps []message
	// only NACK if the message is not a NACK
	if msg.getCounter() != countLastMessage {
		resps = []message{makeNACK()}
	}
	return upwardRes{
		Next:  s,
		Resps: resps,
		Err:   s.err,
	}
}

func pickCS(initiator bool, cs1, cs2 *noise.CipherState) (outCS, inCS *noise.CipherState) {
	if !initiator {
		cs1, cs2 = cs2, cs1
	}
	outCS = cs1
	inCS = cs2
	return outCS, inCS
}

func encryptMessage(outCS *noise.CipherState, count uint32, ptext []byte) []byte {
	cipher := outCS.Cipher()
	counterBytes := [4]byte{}
	binary.BigEndian.PutUint32(counterBytes[:], count)
	return cipher.Encrypt(counterBytes[:], uint64(count), counterBytes[:], ptext)
}

func decryptMessage(inCS *noise.CipherState, count uint32, in []byte) ([]byte, error) {
	cipher := inCS.Cipher()
	counterBytes := [4]byte{}
	binary.BigEndian.PutUint32(counterBytes[:], count)
	return cipher.Decrypt(nil, uint64(count), counterBytes[:], in)
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

func makeNACK() message {
	countBytes := [4]byte{}
	binary.BigEndian.PutUint32(countBytes[:], countLastMessage)
	return countBytes[:]
}
