package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func uint32MuxFunc(cid channelID, x p2p.IOVec) p2p.IOVec {
	const size = 4
	c := cid.(uint32)
	header := [size]byte{}
	binary.BigEndian.PutUint32(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint32DemuxFunc(data []byte) (channelID, []byte, error) {
	const size = 4
	if len(data) < size {
		return 0, nil, errors.Errorf("too short to be uint32")
	}
	c := binary.BigEndian.Uint32(data[:size])
	var body []byte
	if len(data) > size {
		body = data[size:]
	}
	return c, body, nil
}

type uint32Mux struct {
	*muxCore
}

func NewUint32Mux(x p2p.Swarm) Uint32Mux {
	return uint32Mux{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func (m uint32Mux) Open(c uint32) p2p.Swarm {
	return m.open(c)
}

type uint32AskMux struct {
	*muxCore
}

func NewUint32AskMux(x p2p.AskSwarm) Uint32AskMux {
	return uint32AskMux{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func (m uint32AskMux) Open(c uint32) p2p.AskSwarm {
	return m.open(c)
}

type uint32SecureMux struct {
	*muxCore
}

func NewUint32SecureMux(x p2p.SecureSwarm) Uint32SecureMux {
	return uint32SecureMux{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func (m uint32SecureMux) Open(c uint32) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type uint32SecureAskMux struct {
	*muxCore
}

func NewUint32SecureAskMux(x p2p.SecureAskSwarm) Uint32SecureAskMux {
	return uint32SecureAskMux{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func (m uint32SecureAskMux) Open(c uint32) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}
