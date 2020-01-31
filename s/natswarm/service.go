package natswarm

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/syncthing/syncthing/lib/nat"
	"github.com/syncthing/syncthing/lib/upnp"

	"github.com/brendoncarroll/go-p2p"
)

var log = p2p.Logger

/*
	service manages finding nats and forwarding ports

	Process lifetime is managed simply with context
	The tree looks like this:
		service/
		discoverLoop/		<- always looking for NATs
			natManager/ 	<- spawned with a new nat is found
				leasers/ 	<- spawned when a port needs mapping
*/
type service struct {
	swarm p2p.Swarm

	mu  sync.RWMutex
	nat nat.Device

	discoverCF, nmCF context.CancelFunc

	tcpMap map[string]net.TCPAddr
	udpMap map[string]net.UDPAddr
}

func newService(swarm p2p.Swarm) *service {
	s := &service{
		tcpMap:     make(map[string]net.TCPAddr),
		udpMap:     make(map[string]net.UDPAddr),
		swarm:      swarm,
		discoverCF: func() {},
		nmCF:       func() {},
	}
	s.run()
	return s
}

func (s *service) run() {
	ctx, cf := context.WithCancel(context.Background())
	s.discoverCF = cf
	go s.discoverLoop(ctx)
}

func (s *service) stop() {
	s.discoverCF()
	s.nmCF()
}

// discoverLoop discovers nats
func (s *service) discoverLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		timeout := time.Second
		natDevs := upnp.Discover(ctx, timeout, timeout)
		if len(natDevs) < 1 {
			continue
		}
		natDev := natDevs[0]
		natIP := natDev.GetLocalIPAddress()
		log.Debug("discovered nat")

		s.mu.Lock()
		if s.nat == nil || natDev.ID() != s.nat.ID() {
			s.clearMappings()
			s.nmCF()
			s.nat = natDev

			nm := natManager{
				service: s,
				nat:     s.nat,
				natIP:   natIP,
				period:  60 * time.Second,
			}
			ctx, cf := context.WithCancel(ctx)
			s.nmCF = cf
			go nm.run(ctx)

			log.Debug("replaced NAT manager")
		}
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *service) clearMappings() {
	log.Debug("clearing all mappings")
	for k := range s.tcpMap {
		delete(s.tcpMap, k)
	}
	for k := range s.udpMap {
		delete(s.udpMap, k)
	}
}

func (s *service) putTCP(local, external net.TCPAddr) {
	log.WithFields(logrus.Fields{
		"local_addr":    local.String(),
		"external_addr": external.String(),
	}).Debug("added tcp mapping")
	s.mu.Lock()
	s.tcpMap[local.String()] = external
	s.mu.Unlock()
}

func (s *service) putUDP(local, external net.UDPAddr) {
	log.WithFields(logrus.Fields{
		"local_addr":    local.String(),
		"external_addr": external.String(),
	}).Debug("added udp mapping")
	s.mu.Lock()
	s.udpMap[local.String()] = external
	s.mu.Unlock()
}

func (s *service) mapAddr(x p2p.Addr) p2p.Addr {
	s.mu.RLock()
	s.mu.RUnlock()
	switch x := x.(type) {
	case HasTCP:
		tcpAddr := x.GetTCP()
		mapped, exists := s.tcpMap[tcpAddr.String()]
		if !exists {
			return x.(p2p.Addr)
		}
		return x.MapTCP(mapped)
	case HasUDP:
		udpAddr := x.GetUDP()
		mapped, exists := s.udpMap[udpAddr.String()]
		if !exists {
			return x.(p2p.Addr)
		}
		return x.MapUDP(mapped)
	default:
		return x
	}
}

func (s *service) mapAddrs(xs []p2p.Addr) []p2p.Addr {
	ys := []p2p.Addr{}
	for _, x := range xs {
		ys = append(ys, x)
		y := s.mapAddr(x)
		if y != x {
			ys = append(ys, y)
		}
	}
	return ys
}
