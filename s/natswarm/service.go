package natswarm

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/syncthing/syncthing/lib/nat"
	"github.com/syncthing/syncthing/lib/upnp"
)

type service struct {
	natDevs chan map[string]nat.Device
	ctx     context.Context
	cf      context.CancelFunc

	tcpMap map[string]net.TCPAddr
	udpMap map[string]net.UDPAddr
}

func newService() *service {
	s := &service{
		natDevs: make(chan map[string]nat.Device),
	}
	ctx := context.Background()
	s.ctx, s.cf = context.WithCancel(ctx)
	go s.run(ctx)
	return s
}

func (s *service) run(ctx context.Context) {
	go s.discoverLoop(ctx)
}

func (s *service) shutdown() {
	s.cf()
}

func (s *service) discoverLoop(ctx context.Context) {
	timeout := 3 * time.Second

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	natDevs := map[string]nat.Device{}
	for {
		natDevsNew := upnp.Discover(ctx, timeout, timeout)
		m := map[string]nat.Device{}
		for _, natDev := range natDevsNew {
			m[natDev.ID()] = natDev
		}
		if !sameKeys(natDevs, m) {
			log.Println("found new nat devices")
			natDevs = m
			s.natDevs <- natDevs
		}

		select {
		case <-ticker.C:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *service) mapAddr(x p2p.Addr) p2p.Addr {
	type HasTCP interface {
		GetTCP() net.TCPAddr
		SetTCP(net.TCPAddr)
	}
	type HasUDP interface {
		GetUDP() net.UDPAddr
		SetUDP(net.UDPAddr)
	}

	switch x1 := x.(type) {
	case HasTCP:
		tcpAddr := x1.GetTCP()
		s.tcpAddrs[tcpAddr.String()]
	case HasUDP:

	default:
		return x
	}
}

func (s *service) mapAddrs(xs []p2p.Addr) []p2p.Addr {
	ys := []p2p.Addr{}
	for _, x := range xs {
		y := mapAddr(x)
		ys = append(ys, y)
	}
	return ys
}

func sameKeys(a, b map[string]nat.Device) bool {
	for k := range a {
		if _, exists := b[k]; !exists {
			return false
		}
	}
	for k := range b {
		if _, exists := a[k]; !exists {
			return false
		}
	}
	return true
}
