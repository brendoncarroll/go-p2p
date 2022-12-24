package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func NewUint16Mux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, uint16] {
	return mux[A, uint16]{newMuxCore[A, uint16, struct{}](ctx, x, uint16MuxFunc, uint16DemuxFunc)}
}

func NewUint16AskMux[A p2p.Addr](x p2p.Swarm[A]) AskMux[A, uint16] {
	return askMux[A, uint16]{newMuxCore[A, uint16, struct{}](ctx, x, uint16MuxFunc, uint16DemuxFunc)}
}

func NewUint16SecureMux[A p2p.Addr, Pub any](x p2p.Swarm[A]) SecureMux[A, uint16, Pub] {
	return secureMux[A, uint16, Pub]{newMuxCore[A, uint16, Pub](ctx, x, uint16MuxFunc, uint16DemuxFunc)}
}

func NewUint16SecureAskMux[A p2p.Addr, Pub any](x p2p.Swarm[A]) SecureAskMux[A, uint16, Pub] {
	return secureAskMux[A, uint16, Pub]{newMuxCore[A, uint16, Pub](ctx, x, uint16MuxFunc, uint16DemuxFunc)}
}

func uint16MuxFunc(c uint16, x p2p.IOVec) p2p.IOVec {
	const size = 2
	header := [size]byte{}
	binary.BigEndian.PutUint16(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint16DemuxFunc(data []byte) (uint16, []byte, error) {
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
