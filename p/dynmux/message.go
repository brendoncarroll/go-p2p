package dynmux

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

const channelSize = 4

type Message []byte

func (m Message) Validate() error {
	if len(m) < channelSize {
		return errors.New("message too short")
	}
	return nil
}

func (m Message) GetChannel() uint32 {
	return binary.BigEndian.Uint32(m[:channelSize])
}

func (m *Message) SetChannel(x uint32) {
	if len(*m) < channelSize {
		*m = make(Message, channelSize)
	}
	binary.BigEndian.PutUint32((*m)[:channelSize], x)
}

func (m *Message) SetData(d []byte) {
	if len(*m) < channelSize {
		*m = make(Message, 4)
	}
	*m = append(*m, d...)
}

func (m Message) GetData() []byte {
	return m[channelSize:]
}

func newMuxReq(name string) Message {
	req := MuxReq{
		Name: name,
	}
	data, _ := json.Marshal(req)
	m := Message{}
	m.SetChannel(0)
	m.SetData(data)
	return m
}

func newMuxRes(sessionID uuid.UUID, name string, i uint32) Message {
	m := Message{}
	m.SetChannel(1)
	res := MuxRes{
		SessionID: sessionID,
		Name:      name,
		Index:     i,
	}
	data, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	m.SetData(data)
	return m
}

type MuxReq struct {
	Name string `json:"name"`
}

type MuxRes struct {
	SessionID uuid.UUID `json:"session_id"`
	Name      string    `json:"name`
	Index     uint32    `json:"index"`
}
