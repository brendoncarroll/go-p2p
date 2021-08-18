package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func uint16MuxFunc(cid channelID, x p2p.IOVec) p2p.IOVec {
	const size = 2
	c := cid.(uint16)
	header := [size]byte{}
	binary.BigEndian.PutUint16(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint16DemuxFunc(data []byte) (channelID, []byte, error) {
	const size = 2
	if len(data) < size {
		return 0, nil, errors.Errorf("too short to be uint16")
	}
	c := binary.BigEndian.Uint16(data[:size])
	var body []byte
	if len(data) > size {
		body = data[size:]
	}
	return c, body, nil
}

type uint16Mux struct {
	*muxCore
}

func NewUint16Mux(x p2p.Swarm) Uint16Mux {
	return uint16Mux{newMuxCore(x, uint16MuxFunc, uint16DemuxFunc)}
}

func (m uint16Mux) Open(c uint16) p2p.Swarm {
	return m.open(c)
}

type uint16AskMux struct {
	*muxCore
}

func NewUint16AskMux(x p2p.AskSwarm) Uint16AskMux {
	return uint16AskMux{newMuxCore(x, uint16MuxFunc, uint16DemuxFunc)}
}

func (m uint16AskMux) Open(c uint16) p2p.AskSwarm {
	return m.open(c)
}

type uint16SecureMux struct {
	*muxCore
}

func NewUint16SecureMux(x p2p.SecureSwarm) Uint16SecureMux {
	return uint16SecureMux{newMuxCore(x, uint16MuxFunc, uint16DemuxFunc)}
}

func (m uint16SecureMux) Open(c uint16) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type uint16SecureAskMux struct {
	*muxCore
}

func NewUint16SecureAskMux(x p2p.SecureAskSwarm) Uint16SecureAskMux {
	return uint16SecureAskMux{newMuxCore(x, uint16MuxFunc, uint16DemuxFunc)}
}

func (m uint16SecureAskMux) Open(c uint16) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}
