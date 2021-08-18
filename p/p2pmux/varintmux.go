package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func varintMuxFunc(cid channelID, x p2p.IOVec) p2p.IOVec {
	c := cid.(uint64)
	header := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(header, c)
	header = header[:n]
	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, x...)
	return ret
}

func varintDemuxFunc(data []byte) (channelID, []byte, error) {
	c, n := binary.Uvarint(data)
	if n < 1 {
		return 0, nil, errors.Errorf("intmux: could not read message %q", data)
	}
	return c, data[n:], nil
}

// IntMux
type varintMux struct {
	*muxCore
}

func NewVarintMux(x p2p.Swarm) IntMux {
	return varintMux{newMuxCore(x, varintMuxFunc, varintDemuxFunc)}
}

func (m varintMux) Open(c uint64) p2p.Swarm {
	return m.open(c)
}

type varintAskMux struct {
	*muxCore
}

func NewVarintAskMux(x p2p.AskSwarm) IntAskMux {
	return varintAskMux{newMuxCore(x, varintMuxFunc, varintDemuxFunc)}
}

func (m varintAskMux) Open(c uint64) p2p.AskSwarm {
	return m.open(c)
}

type varintSecureMux struct {
	*muxCore
}

func NewVarintSecureMux(x p2p.SecureSwarm) IntSecureMux {
	return varintSecureMux{newMuxCore(x, varintMuxFunc, varintDemuxFunc)}
}

func (m varintSecureMux) Open(c uint64) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type varintSecureAskMux struct {
	*muxCore
}

func NewVarintSecureAskMux(x p2p.SecureAskSwarm) IntSecureAskMux {
	return varintSecureAskMux{newMuxCore(x, varintMuxFunc, varintDemuxFunc)}
}

func (m varintSecureAskMux) Open(c uint64) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}
