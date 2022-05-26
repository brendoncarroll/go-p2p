package p2pke

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

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
	if x.AuthClaim == nil {
		return nil, errors.New("InitHello missing AuthClaim")
	}
	return x, nil
}

func parseRespHello(data []byte) (*RespHello, error) {
	x := &RespHello{}
	if err := unmarshal(data, x); err != nil {
		return nil, err
	}
	if x.AuthClaim == nil {
		return nil, errors.New("RespHello missing AuthClaim")
	}
	return x, nil
}

func parseInitDone(data []byte) (*InitDone, error) {
	x := &InitDone{}
	if err := unmarshal(data, x); err != nil {
		return nil, err
	}
	if x.AuthClaim == nil {
		return nil, errors.New("InitDone missing AuthClaim")
	}
	return x, nil
}

type Message []byte

func newMessage(nonce uint32) Message {
	msg := make(Message, 4)
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
	return binary.BigEndian.Uint32(m[:4])
}

func (m Message) SetNonce(n uint32) {
	binary.BigEndian.PutUint32(m[:4], n)
}

func (m Message) HeaderBytes() []byte {
	return m[:4]
}

func (m Message) Body() []byte {
	return m[4:]
}

func (m Message) GetInitHello() (*InitHello, error) {
	data := m.Body()
	if len(data) < 32 {
		return nil, errors.New("too short to contain InitHello")
	}
	data = data[32:]
	return parseInitHello(data)
}

func PrettyPrint(msg Message) string {
	bw := &strings.Builder{}
	fmt.Fprintf(bw, "BEGIN MESSAGE %08x\n", msg.GetNonce())
	doHexDump := true
	switch msg.GetNonce() {
	case nonceInitHello:
		x, err := msg.GetInitHello()
		if err != nil {
			fmt.Fprintln(bw, "Invalid InitHello", err)
			break
		}
		doHexDump = false
		fmt.Fprintln(bw, x)
	}
	if doHexDump {
		d := hex.Dumper(bw)
		d.Write(msg.Body())
		d.Close()
	}
	fmt.Fprintf(bw, "END MESSAGE\n")
	return bw.String()
}
