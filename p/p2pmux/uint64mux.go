package p2pmux

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/brendoncarroll/go-p2p"
)

func NewUint64Mux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, uint64] {
	return mux[A, uint64]{newMuxCore[A, uint64](x, uint64MuxFunc, uint64DemuxFunc)}
}

func NewUint64AskMux[A p2p.Addr](x p2p.Swarm[A]) AskMux[A, uint64] {
	return askMux[A, uint64]{newMuxCore[A, uint64](x, uint64MuxFunc, uint64DemuxFunc)}
}

func NewUint64SecureMux[A p2p.Addr](x p2p.Swarm[A]) SecureMux[A, uint64] {
	return secureMux[A, uint64]{newMuxCore[A, uint64](x, uint64MuxFunc, uint64DemuxFunc)}
}

func NewUint64SecureAskMux[A p2p.Addr](x p2p.Swarm[A]) SecureAskMux[A, uint64] {
	return secureAskMux[A, uint64]{newMuxCore[A, uint64](x, uint64MuxFunc, uint64DemuxFunc)}
}

func uint64MuxFunc(c uint64, x p2p.IOVec) p2p.IOVec {
	const size = 8
	header := [size]byte{}
	binary.BigEndian.PutUint64(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint64DemuxFunc(data []byte) (uint64, []byte, error) {
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
