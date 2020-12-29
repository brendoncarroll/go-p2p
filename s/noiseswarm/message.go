package noiseswarm

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

const (
	countInit          = uint32(0)
	countResp          = uint32(1)
	countSigInitToResp = uint32(2)
	countSigRespToInit = uint32(3)
	countPostHandshake = uint32(4)

	countLastMessage = uint32(MaxSessionMessages)
)

type direction uint8

const (
	directionInitToResp = direction(iota)
	directionRespToInit
)

const (
	counterMask   = uint32(0x7FFFFFFF)
	directionMask = uint32(0x80000000)
)

type message []byte

func newMessage(dir direction, count uint32) message {
	m := message(make([]byte, 4))
	m.setDirection(dir)
	m.setCounter(count)
	return m
}

func parseMessage(x []byte) (message, error) {
	if len(x) < 4 {
		return nil, errors.Errorf("message too short")
	}
	return message(x), nil
}

func (m message) getDirection() direction {
	if m[0]&0x80 > 0 {
		return directionRespToInit
	}
	return directionInitToResp
}

func (m message) setDirection(x direction) {
	const mask = uint8(0x80)
	switch x {
	case directionInitToResp:
		m[0] &= (^mask)
	case directionRespToInit:
		m[0] |= mask
	default:
		panic(x)
	}
}

func (m message) getCounter() uint32 {
	x := binary.BigEndian.Uint32(m[:4])
	x &= counterMask
	return x
}

func (m message) setCounter(x uint32) {
	x &= counterMask
	binary.BigEndian.PutUint32(m[:4], x)
}

func (m message) getBody() []byte {
	return m[4:]
}

func (m message) setBody(x []byte) []byte {
	return append(m[:4], x...)
}
