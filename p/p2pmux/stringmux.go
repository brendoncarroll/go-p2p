package p2pmux

import (
	"encoding/binary"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

func NewStringMux[A p2p.Addr](x p2p.Swarm[A]) Mux[A, string] {
	return mux[A,string]{newMuxCore[A, string](x, stringMuxFunc, stringDemuxFunc)}
}

func NewStringAskMux[A p2p.Addr](x p2p.AskSwarm[A]) AskMux[A, string] {
	return askMux[A, string]{newMuxCore[A, string](x, stringMuxFunc, stringDemuxFunc)}
}

func NewStringSecureMux[A p2p.Addr](x p2p.SecureSwarm[A]) SecureMux[A, string] {	
	return secureMux[A, string]{newMuxCore[A, string](x, stringMuxFunc, stringDemuxFunc)}
}

func NewStringSecureAskMux[A p2p.Addr](x p2p.SecureAskSwarm[A]) SecureAskMux[A, string] {
	return secureAskMux[A, string]{newMuxCore[A, string](x, stringMuxFunc, stringDemuxFunc)}
}

func stringMuxFunc(c string, x p2p.IOVec) p2p.IOVec {
	header := make([]byte, binary.MaxVarintLen64+len(c))
	n := binary.PutUvarint(header, uint64(len(c)))
	header = header[:n]
	header = append(header, []byte(c)...)

	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, x...)
	return ret
}

func stringDemuxFunc(x []byte) (string, []byte, error) {
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
