package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func uint64MuxFunc(cid channelID, x p2p.IOVec) p2p.IOVec {
	const size = 8
	c := cid.(uint64)
	header := [size]byte{}
	binary.BigEndian.PutUint64(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint64DemuxFunc(data []byte) (channelID, []byte, error) {
	const size = 8
	if len(data) < size {
		return 0, nil, errors.Errorf("too short to be uint64")
	}
	c := binary.BigEndian.Uint64(data[:size])
	var body []byte
	if len(data) > size {
		body = data[size:]
	}
	return c, body, nil
}

type uint64Mux struct {
	*muxCore
}

func NewUint64Mux(x p2p.Swarm) IntMux {
	return uint64Mux{newMuxCore(x, uint64MuxFunc, uint64DemuxFunc)}
}

func (m uint64Mux) Open(c uint64) p2p.Swarm {
	return m.open(c)
}

type uint64AskMux struct {
	*muxCore
}

func NewUint64AskMux(x p2p.AskSwarm) IntAskMux {
	return uint64AskMux{newMuxCore(x, uint64MuxFunc, uint64DemuxFunc)}
}

func (m uint64AskMux) Open(c uint64) p2p.AskSwarm {
	return m.open(c)
}

type uint64SecureMux struct {
	*muxCore
}

func NewUint64SecureMux(x p2p.SecureSwarm) IntSecureMux {
	return uint64SecureMux{newMuxCore(x, uint64MuxFunc, uint64DemuxFunc)}
}

func (m uint64SecureMux) Open(c uint64) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type uint64SecureAskMux struct {
	*muxCore
}

func NewUint64SecureAskMux(x p2p.SecureAskSwarm) IntSecureAskMux {
	return uint64SecureAskMux{newMuxCore(x, uint64MuxFunc, uint64DemuxFunc)}
}

func (m uint64SecureAskMux) Open(c uint64) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}
