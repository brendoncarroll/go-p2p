package natswarm

import (
	"context"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/syncthing/syncthing/lib/nat"
)

// natManager periodically lists
// all of the local addresses for the swarm
// and if the nat is on the same network adds a mapping
type natManager struct {
	service *service
	nat     nat.Device
	natIP   net.IP

	period  time.Duration
	leasers map[string]context.CancelFunc
}

func (nm *natManager) run(ctx context.Context) {
	log1 := log.WithFields(logrus.Fields{
		"nat_id": nm.nat.ID(),
	})
	log1.Info("NAT Manager starting")

	nm.leasers = make(map[string]context.CancelFunc)

	ticker := time.NewTicker(nm.period)
	defer ticker.Stop()

	nm.spawnLeasers(ctx)
	for {
		select {
		case <-ctx.Done():
			log1.Info("killing NAT manager")
			return
		case <-ticker.C:
			if err := nm.spawnLeasers(ctx); err != nil {
				log.Error("error while spawning leasers", err)
			}
		}
	}
}

func (nm *natManager) spawnLeasers(ctx context.Context) error {
	leaserPeriod := 30 * time.Second
	swarm := nm.service.swarm

	for _, addr := range swarm.LocalAddrs() {
		switch addr := addr.(type) {
		case HasTCP:
			tcpAddr := addr.GetTCP()
			if !sameNetwork(nm.natIP, tcpAddr.IP) {
				continue
			}
			k := "tcp" + tcpAddr.String()
			if _, exists := nm.leasers[k]; !exists {
				l := &leaser{
					nat:     nm.nat,
					service: nm.service,

					protocol:  nat.TCP,
					localIP:   tcpAddr.IP,
					localPort: tcpAddr.Port,

					period: leaserPeriod,
				}
				ctx, cf := context.WithCancel(ctx)
				nm.leasers[k] = cf
				go l.run(ctx)
			}

		case HasUDP:
			udpAddr := addr.GetUDP()
			if !sameNetwork(nm.natIP, udpAddr.IP) {
				continue
			}
			k := "udp" + udpAddr.String()
			if _, exists := nm.leasers[k]; !exists {
				l := &leaser{
					nat:     nm.nat,
					service: nm.service,

					protocol:  nat.UDP,
					localIP:   udpAddr.IP,
					localPort: udpAddr.Port,

					period: leaserPeriod,
				}
				ctx, cf := context.WithCancel(ctx)
				nm.leasers[k] = cf
				go l.run(ctx)
			}
		}
	}

	return nil
}

func sameNetwork(a, b net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		ipNet := addr.(*net.IPNet)
		if ipNet.Contains(a) && ipNet.Contains(b) {
			return true
		}
	}
	return false
}
