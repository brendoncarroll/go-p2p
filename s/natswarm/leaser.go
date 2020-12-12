package natswarm

import (
	"context"
	mrand "math/rand"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/syncthing/syncthing/lib/nat"
)

type leaser struct {
	nat     nat.Device
	service *service

	protocol  nat.Protocol
	localPort int
	localIP   net.IP

	period time.Duration
}

func (l *leaser) run(ctx context.Context) {
	log := log.WithFields(logrus.Fields{
		"local_ip":   l.localIP,
		"local_port": l.localPort,
		"period":     l.period,
	})
	log.Infoln("leaser starting")
	reqPort := randomPort()

	ticker := time.NewTicker(l.period)
	defer ticker.Stop()

	ttl := 2 * l.period
	timer := time.NewTimer(ttl)
	defer timer.Stop()

	l.renew(ctx, reqPort)
	for {
		select {
		case <-ctx.Done():
			log.Infoln("leaser terminating")
			return

		case <-timer.C:
			log.Warn("lease may have expired")

		case <-ticker.C:
			if err := l.renew(ctx, reqPort); err != nil {
				log.Error("error while renewing", err)
			}
			timer.Reset(ttl)
		}
	}
}

func (l *leaser) renew(ctx context.Context, reqPort int) error {
	ttl := 2 * l.period
	externalPort, err := l.nat.AddPortMapping(ctx,
		l.protocol, l.localPort, reqPort, "go-p2p", ttl)

	if err != nil {
		return err
	}
	externalIP, err := l.nat.GetExternalIPAddress(ctx)
	if err != nil {
		return err
	}

	switch l.protocol {
	case nat.TCP:
		local := net.TCPAddr{
			IP:   l.localIP,
			Port: l.localPort,
		}
		external := net.TCPAddr{
			IP:   externalIP,
			Port: externalPort,
		}
		l.service.putTCP(local, external)

	case nat.UDP:
		local := net.UDPAddr{
			IP:   l.localIP,
			Port: l.localPort,
		}
		external := net.UDPAddr{
			IP:   externalIP,
			Port: externalPort,
		}
		l.service.putUDP(local, external)

	default:
		panic("bad protocol")
	}
	return nil
}

func randomPort() int {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	maxPort := 1 << 15
	minPort := 10000
	return rng.Intn(maxPort-minPort) + maxPort
}

func once() chan struct{} {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	return ch
}
