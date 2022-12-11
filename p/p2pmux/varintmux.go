package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func NewVarintMux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, uint64] {
	return mux[A, uint64]{newMuxCore(ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintAskMux[A p2p.Addr](x p2p.Swarm[A]) AskMux[A, uint64] {
	return askMux[A, uint64]{newMuxCore(ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintSecureMux[A p2p.Addr](x p2p.Swarm[A]) SecureMux[A, uint64] {
	return secureMux[A, uint64]{newMuxCore(ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintSecureAskMux[A p2p.Addr](x p2p.Swarm[A]) SecureAskMux[A, uint64] {
	return secureAskMux[A, uint64]{newMuxCore(ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func varintMuxFunc(c uint64, x p2p.IOVec) p2p.IOVec {
	header := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(header, c)
	header = header[:n]
	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, x...)
	return ret
}

func varintDemuxFunc(data []byte) (uint64, []byte, error) {
	c, n := binary.Uvarint(data)
	if n < 1 {
		return 0, nil, errors.Errorf("intmux: could not read message %q", data)
	}
	return c, data[n:], nil
}
