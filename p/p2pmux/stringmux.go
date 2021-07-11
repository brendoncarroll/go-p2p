package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

// StringMux
type stringMux struct {
	*muxCore
}

func NewStringMux(x p2p.Swarm) StringMux {
	return &stringMux{
		muxCore: newMuxCore(x, stringMuxFunc, stringDemuxFunc),
	}
}

func (m *stringMux) Open(c string) p2p.Swarm {
	return m.open(c)
}

// StringAskMux
type stringAskMux struct {
	*muxCore
}

func NewStringAskMux(x p2p.AskSwarm) StringAskMux {
	return &stringAskMux{
		muxCore: newMuxCore(x, stringMuxFunc, stringDemuxFunc),
	}
}

func (m *stringAskMux) Open(c string) p2p.AskSwarm {
	return m.open(c)
}

// StringSecureMux
type stringSecureMux struct {
	*muxCore
}

func NewStringSecureMux(x p2p.SecureSwarm) StringSecureMux {
	return &stringSecureMux{
		muxCore: newMuxCore(x, stringMuxFunc, stringDemuxFunc),
	}
}

func (m *stringSecureMux) Open(c string) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

// StringSecureAskMux
type stringSecureAskMux struct {
	*muxCore
}

func NewStringSecureAskMux(x p2p.SecureSwarm) StringSecureAskMux {
	return &stringSecureAskMux{
		muxCore: newMuxCore(x, stringMuxFunc, stringDemuxFunc),
	}
}

func (m *stringSecureAskMux) Open(c string) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}

func stringMuxFunc(cid channelID, x p2p.IOVec) p2p.IOVec {
	c := cid.(string)
	header := make([]byte, binary.MaxVarintLen64+len(c))
	n := binary.PutUvarint(header, uint64(len(c)))
	header = header[:n]
	header = append(header, []byte(c)...)

	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, x...)
	return ret
}

func stringDemuxFunc(x []byte) (channelID, []byte, error) {
	chanLength, n := binary.Uvarint(x)
	if n < 1 {
		return "", nil, errors.Errorf("stringmux: could not read message")
	}
	x = x[n:]
	if len(x) < int(chanLength) {
		return "", nil, errors.Errorf("stringmux: length smaller than message")
	}
	chanBytes := x[:chanLength]
	var msg []byte
	if int(chanLength) < len(x) {
		msg = x[chanLength:]
	}
	return string(chanBytes), msg, nil
}
