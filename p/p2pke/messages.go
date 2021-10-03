package p2pke

import (
	"encoding/binary"
	"encoding/json"

	"github.com/pkg/errors"
)

const MaxNonce = (1 << 31) - 1

const (
	nonceInitHello     = 0
	nonceRespHello     = 1
	nonceAuthProof     = 2
	noncePostHandshake = 16
)

const purpose = "p2pke/sig-channel-binding"

type Direction uint8

const (
	InitToResp = Direction(iota)
	RespToInit
)

type InitHello struct {
	CipherSuites []string `json:"cipher_suites"`
	PSKHash      []byte   `json:"psk_hash,omitempty"`
}

type RespHello struct {
	CipherSuite string    `json:"cipher_suite"`
	PSKUsed     bool      `json:"psk_used"`
	AuthProof   AuthProof `json:"auth_proof"`
}

type AuthProof struct {
	KeyX509 []byte `json:"key_x509"`
	Sig     []byte `json:"sig"`
}

func marshal(out []byte, x interface{}) []byte {
	data, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	return append(out, data...)
}

func unmarshal(data []byte, x interface{}) error {
	return json.Unmarshal(data, x)
}

func parseInitHello(x []byte) (*InitHello, error) {
	var h InitHello
	if err := unmarshal(x, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func parseRespHello(x []byte) (*RespHello, error) {
	var h RespHello
	if err := unmarshal(x, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func parseAuthProof(x []byte) (*AuthProof, error) {
	var ap AuthProof
	if err := unmarshal(x, &ap); err != nil {
		return nil, err
	}
	return &ap, nil
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

func (m Message) GetNonce() uint32 {
	x := binary.BigEndian.Uint32(m[:4])
	x &= 0x7FFF_FFFF
	return x
}

func (m Message) NonceBytes() []byte {
	return m[:4]
}

func (m Message) Body() []byte {
	return m[4:]
}
