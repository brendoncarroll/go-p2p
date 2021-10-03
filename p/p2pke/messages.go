package p2pke

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

const MaxNonce = (1 << 31) - 1

const (
	nonceInitHello     = 0
	nonceRespHello     = 1
	nonceInitDone      = 2
	noncePostHandshake = 16
)

const purpose = "p2pke/sig-channel-binding"

type Direction uint8

const (
	InitToResp = Direction(iota)
	RespToInit
)

func (d Direction) String() string {
	switch d {
	case InitToResp:
		return "INIT->RESP"
	case RespToInit:
		return "RESP->INIT"
	default:
		panic("unknown direction")
	}
}

func marshal(out []byte, x proto.Message) []byte {
	data, err := proto.Marshal(x)
	if err != nil {
		panic(err)
	}
	return append(out, data...)
}

func unmarshal(data []byte, x proto.Message) error {
	return proto.Unmarshal(data, x)
}

func parseInitHello(data []byte) (*InitHello, error) {
	x := &InitHello{}
	if err := unmarshal(data, x); err != nil {
		return nil, err
	}
	return x, nil
}

func parseRespHello(data []byte) (*RespHello, error) {
	x := &RespHello{}
	if err := unmarshal(data, x); err != nil {
		return nil, err
	}
	return x, nil
}

func parseInitDone(data []byte) (*InitDone, error) {
	x := &InitDone{}
	if err := unmarshal(data, x); err != nil {
		return nil, err
	}
	return x, nil
}

type Message []byte

func newMessage(dir Direction, nonce uint32) Message {
	msg := make(Message, 4)
	msg.SetDirection(dir)
	msg.SetNonce(nonce)
	return msg
}

// ParseMessage
func ParseMessage(x []byte) (Message, error) {
	if len(x) < 4 {
		return nil, errors.Errorf("p2pke: too short to be message")
	}
	return x, nil
}

func (m Message) GetNonce() uint32 {
	x := binary.BigEndian.Uint32(m[:4])
	x &= 0x7FFF_FFFF
	return x
}

func (m Message) SetNonce(n uint32) {
	if n > MaxNonce {
		panic(n)
	}
	x := binary.BigEndian.Uint32(m[:4])
	y := (x & 0x8000_0000) | n
	binary.BigEndian.PutUint32(m[:4], y)
}

func (m Message) GetDirection() Direction {
	x := binary.BigEndian.Uint32(m[:4])
	x >>= 31
	if x == 0 {
		return InitToResp
	} else {
		return RespToInit
	}
}

func (m Message) SetDirection(dir Direction) {
	x := binary.BigEndian.Uint32(m[:4])
	var y uint32
	switch dir {
	case InitToResp:
		y = x & 0x7FFF_FFFF
	case RespToInit:
		y = x | 0x8000_0000
	default:
		panic(dir)
	}
	binary.BigEndian.PutUint32(m[:4], y)
}

func (m Message) HeaderBytes() []byte {
	return m[:4]
}

func (m Message) Body() []byte {
	return m[4:]
}
