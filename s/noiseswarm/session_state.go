package noiseswarm

import (
	"encoding/binary"
	"time"

	"github.com/pkg/errors"
)

type upwardRes struct {
	Up    []byte
	Resps [][]byte

	Next state
	Err  error
}

type downwardRes struct {
	Down []byte

	Next state
	Err  error
}

type state interface {
	downward(s *session, in []byte) downwardRes
	upward(s *session, count uint32, in []byte) upwardRes
}

type awaitInitState struct{}

func (awaitInitState) downward(s *session, in []byte) downwardRes {
	return downwardRes{
		Next: awaitInitState{},
		Err:  errors.Errorf("cannot send before handshake is done"),
	}
}

func (awaitInitState) upward(s *session, count uint32, in []byte) upwardRes {
	if s.initiator {
		panic("dialer cannot be in awaitInit")
	}
	var resps [][]byte
	err := func() error {
		_, _, _, err := s.hsstate.ReadMessage(nil, in)
		if err != nil {
			return &ErrHandshake{
				Message: "noise errored",
				Cause:   err,
			}
		}
		counterBytes := [4]byte{}
		binary.BigEndian.PutUint32(counterBytes[:], countResp)
		out, cs1, cs2, err := s.hsstate.WriteMessage(counterBytes[:], nil)
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
		s.completeNoiseHandshake(cs1, cs2)
		// also send intro
		introBytes, err := signChannelBinding(s.privateKey, s.hsstate.ChannelBinding())
		if err != nil {
			return &ErrHandshake{
				Message: "could not sign the channel binding",
				Cause:   err,
			}
		}
		out = encryptMessage(s.outCS, countSigChannelBinding, introBytes)
		resps = append(resps, out)
		return nil
	}()
	if err != nil {
		return upwardRes{Err: err, Next: endState{}}
	}
	return upwardRes{
		Resps: resps,
		Next:  awaitSigState{},
	}
}

type awaitRespState struct{}

func (awaitRespState) downward(s *session, in []byte) downwardRes {
	return downwardRes{
		Next: awaitRespState{},
		Err:  errors.Errorf("cannot send before handshake is done"),
	}
}

func (awaitRespState) upward(s *session, count uint32, in []byte) upwardRes {
	if !s.initiator {
		panic("listener cannot be in awaitResp")
	}
	var resps [][]byte
	err := func() error {
		_, cs1, cs2, err := s.hsstate.ReadMessage(nil, in)
		if err != nil {
			return &ErrHandshake{
				Message: "noise errored",
				Cause:   err,
			}
		}
		if cs1 == nil || cs2 == nil {
			panic("no error and no cipherstates")
		}
		s.completeNoiseHandshake(cs1, cs2)
		// send intro
		introBytes, err := signChannelBinding(s.privateKey, s.hsstate.ChannelBinding())
		if err != nil {
			return &ErrHandshake{
				Message: "invalid intro signature",
				Cause:   err,
			}
		}
		out := encryptMessage(s.outCS, countSigChannelBinding, introBytes)
		resps = append(resps, out)
		return nil
	}()
	if err != nil {
		return upwardRes{
			Next: awaitRespState{},
			Err:  err,
		}
	}
	return upwardRes{
		Resps: resps,
		Next:  readyState{},
	}
}

type awaitSigState struct{}

func (awaitSigState) downward(s *session, in []byte) downwardRes {
	return downwardRes{
		Next: awaitSigState{},
		Err:  errors.Errorf("cannot send while awaiting sig"),
	}
}

func (awaitSigState) upward(s *session, count uint32, in []byte) upwardRes {
	err := func() error {
		if s.inCS == nil {
			return &ErrHandshake{
				Message: "intro before noise handshake completed",
			}
		}
		ptext, err := decryptMessage(s.inCS, countSigChannelBinding, in)
		if err != nil {
			return &ErrHandshake{
				Message: "could not decrypt intro",
				Cause:   err,
			}
		}
		remotePubKey, err := verifyIntro(s.hsstate.ChannelBinding(), ptext)
		if err != nil {
			return &ErrHandshake{
				Message: "intro was invalid",
				Cause:   err,
			}
		}
		s.completeHandshake(remotePubKey)
		return nil
	}()
	if err != nil {
		return upwardRes{
			Next: endState{err: err},
			Err:  err,
		}
	}
	return upwardRes{
		Next: readyState{},
	}
}

type readyState struct{}

func (readyState) downward(s *session, in []byte) downwardRes {
	count := s.outCount
	s.outCount++

	return downwardRes{
		Next: readyState{},
		Down: encryptMessage(s.outCS, count, in),
	}
}

func (readyState) upward(s *session, count uint32, in []byte) upwardRes {
	switch {
	case countLastMessage == countLastMessage:
		return upwardRes{
			Next: newEndState(ErrSessionExpired),
			Err:  ErrSessionExpired,
		}
	case count < countPostHandshake:
		return upwardRes{
			Next: readyState{},
			Err:  &ErrTransport{Message: "handshake message recieved", Num: count},
		}
	}
	ptext, err := decryptMessage(s.inCS, count, in)
	if err != nil {
		return upwardRes{
			Next: readyState{},
			Err:  &ErrTransport{Message: "count not decrypt message", Num: count},
		}
	}
	if !s.inFilter.ValidateCounter(uint64(count), MaxSessionMessages) {
		return upwardRes{
			Next: readyState{},
			Err: &ErrTransport{
				Message: "replayed counter",
				Num:     count,
			},
		}
	}
	s.lastRecv = time.Now()
	return upwardRes{
		Next: readyState{},
		Up:   ptext,
	}
}

type endState struct {
	err error
}

func newEndState(err error) endState {
	return endState{err: err}
}

func (s endState) downward(sess *session, in []byte) downwardRes {
	return downwardRes{
		Next: s,
		Err:  s.err,
	}
}

func (s endState) upward(sess *session, count uint32, in []byte) upwardRes {
	counterBytes := [4]byte{}
	binary.BigEndian.PutUint32(counterBytes[:], countLastMessage)
	nackBytes := counterBytes[:]
	return upwardRes{
		Next:  s,
		Resps: [][]byte{nackBytes},
		Err:   s.err,
	}
}
