package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func NewUint32Mux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, uint32] {
	return mux[A, uint32]{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func NewUint32AskMux[A p2p.Addr](x p2p.Swarm[A]) AskMux[A, uint32] {
	return askMux[A, uint32]{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func NewUint32SecureMux[A p2p.Addr](x p2p.Swarm[A]) SecureMux[A, uint32] {
	return secureMux[A, uint32]{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func NewUint32SecureAskMux[A p2p.Addr](x p2p.Swarm[A]) SecureAskMux[A, uint32] {
	return secureAskMux[A, uint32]{newMuxCore(x, uint32MuxFunc, uint32DemuxFunc)}
}

func uint32MuxFunc(c uint32, x p2p.IOVec) p2p.IOVec {
	const size = 4
	header := [size]byte{}
	binary.BigEndian.PutUint32(header[:], c)
	return append(p2p.IOVec{header[:]}, x...)
}

func uint32DemuxFunc(data []byte) (uint32, []byte, error) {
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
