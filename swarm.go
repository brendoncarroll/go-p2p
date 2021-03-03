package p2p

import (
	"context"
	"io"
	"net"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type Message struct {
	Dst, Src Addr
	Payload  []byte
}

type AskHandler func(ctx context.Context, req *Message, w io.Writer)
type TellHandler func(msg *Message)

func NoOpAskHandler(ctx context.Context, req *Message, w io.Writer) {}

func NoOpTellHandler(msg *Message) {}

type Swarm interface {
	Teller

	LocalAddrs() []Addr
	MTU(ctx context.Context, addr Addr) int
	Close() error
	ParseAddr(data []byte) (Addr, error)
}

type IOVec = net.Buffers

// VecSize returns the total size of the vector in bytes if it were contiguous.
// It is the sum of len(v[i]) for all i
func VecSize(v IOVec) int {
	var total int
	for i := range v {
		total += len(v[i])
	}
	return total
}

func VecBytes(v IOVec) []byte {
	if len(v) == 0 {
		return nil
	}
	if len(v) == 1 {
		return v[0]
	}
	total := VecSize(v)
	ret := make([]byte, 0, total)
	for i := range v {
		ret = append(ret, v[i]...)
	}
	return ret
}

type Teller interface {
	Tell(ctx context.Context, addr Addr, data IOVec) error
	ServeTells(TellHandler) error
}

type Asker interface {
	Ask(ctx context.Context, addr Addr, data IOVec) ([]byte, error)
	ServeAsks(AskHandler) error
}

type AskSwarm interface {
	Swarm
	Asker
}

var (
	ErrPublicKeyNotFound = errors.Errorf("public key not found")
)

type Secure interface {
	PublicKey() PublicKey
	LookupPublicKey(ctx context.Context, addr Addr) (PublicKey, error)
}

type SecureSwarm interface {
	Swarm
	Secure
}

type SecureAskSwarm interface {
	Swarm
	Asker
	Secure
}

// LookupPublicKeyInHandler calls LookupPublicKey with
// an expired context, and panics on an error.  SecureSwarms must
// be able to return a PublicKey retrieved from memory, during the
// execution of an AskHandler or TellHandler.
// to lookup a public key outside a handler, use the swarms LookupPublicKey method
func LookupPublicKeyInHandler(s Secure, target Addr) PublicKey {
	ctx, cf := context.WithCancel(context.Background())
	cf()
	pubKey, err := s.LookupPublicKey(ctx, target)
	if err != nil {
		err = errors.Wrapf(err, "swarms must provide public key during callback")
		panic(err)
	}
	if pubKey == nil {
		panic("swarms must provide public key during callback. got nil")
	}
	return pubKey
}

// ServeBoth calls ServeTells and ServeAsks
func ServeBoth(s AskSwarm, th TellHandler, ah AskHandler) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		return s.ServeTells(th)
	})
	eg.Go(func() error {
		return s.ServeAsks(ah)
	})
	return eg.Wait()
}
