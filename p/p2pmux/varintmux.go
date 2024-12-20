package p2pmux

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"go.brendoncarroll.net/p2p"
)

func NewVarintMux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, uint64] {
	return mux[A, uint64]{newMuxCore[A, uint64, struct{}](ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintAskMux[A p2p.Addr](x p2p.Swarm[A]) AskMux[A, uint64] {
	return askMux[A, uint64]{newMuxCore[A, uint64, struct{}](ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintSecureMux[A p2p.Addr, Pub any](x p2p.Swarm[A]) SecureMux[A, uint64, Pub] {
	return secureMux[A, uint64, Pub]{newMuxCore[A, uint64, Pub](ctx, x, varintMuxFunc, varintDemuxFunc)}
}

func NewVarintSecureAskMux[A p2p.Addr, Pub any](x p2p.Swarm[A]) SecureAskMux[A, uint64, Pub] {
	return secureAskMux[A, uint64, Pub]{newMuxCore[A, uint64, Pub](ctx, x, varintMuxFunc, varintDemuxFunc)}
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
