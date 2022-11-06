package sshswarm

import (
	"context"
	"log"
	"net"
	"net/netip"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	swarm      *Swarm
	remoteAddr Addr
	localAddr  Addr
	shutdown   chan struct{}

	newChanReqs <-chan ssh.NewChannel
	reqs        <-chan *ssh.Request
	sconn       ssh.Conn
	pubKey      ssh.PublicKey
}

func newServer(s *Swarm, netConn net.Conn) (*Conn, error) {
	var pubKey ssh.PublicKey
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(md ssh.ConnMetadata, pk ssh.PublicKey) (*ssh.Permissions, error) {
			pubKey = pk
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(s.signer)

	sconn, newChans, reqs, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		return nil, err
	}
	if pubKey == nil {
		return nil, errors.New("pubkey not set after connection")
	}

	raddr := sconn.RemoteAddr().(*net.TCPAddr)
	rip, _ := netip.AddrFromSlice(raddr.IP)
	port := raddr.Port

	c := &Conn{
		swarm: s,
		remoteAddr: Addr{
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			IP:          rip,
			Port:        uint16(port),
		},
		localAddr: Addr{
			Fingerprint: ssh.FingerprintSHA256(s.signer.PublicKey()),
			IP:          s.LocalAddrs()[0].IP,
			Port:        uint16(netConn.LocalAddr().(*net.TCPAddr).Port),
		},
		shutdown: make(chan struct{}),

		newChanReqs: newChans,
		reqs:        reqs,
		sconn:       sconn,
		pubKey:      pubKey,
	}

	return c, nil
}

func newClient(s *Swarm, remoteAddr Addr, netConn net.Conn) (*Conn, error) {
	var pubKey ssh.PublicKey
	config := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.signer),
		},
		HostKeyCallback: func(host string, raddr net.Addr, pk ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(pk)
			if fp != remoteAddr.Fingerprint {
				return errors.New("Fingerprint does not match")
			}
			pubKey = pk
			return nil
		},
	}

	sconn, newChans, reqs, err := ssh.NewClientConn(netConn, netConn.RemoteAddr().String(), config)
	if err != nil {
		return nil, err
	}
	if pubKey == nil {
		return nil, errors.New("pubkey not set after connection")
	}

	c := &Conn{
		swarm:      s,
		remoteAddr: remoteAddr,
		shutdown:   make(chan struct{}),

		newChanReqs: newChans,
		reqs:        reqs,
		sconn:       sconn,
		pubKey:      pubKey,
	}

	return c, nil
}

func (c *Conn) loop(ctx context.Context) {
	resp := make([]byte, MTU)
	for {
		select {
		case req, ok := <-c.reqs:
			if !ok {
				return
			}
			ctx := context.TODO()
			msg := p2p.Message[Addr]{
				Src:     c.RemoteAddr(),
				Dst:     c.localAddr,
				Payload: req.Payload,
			}
			if req.WantReply {
				n, err := c.swarm.askHub.Deliver(ctx, resp, msg)
				if err != nil {
					log.Println(err)
				}
				ok := n >= 0
				if n < 0 {
					n = 0
				}
				if err := req.Reply(ok, resp[:n]); err != nil {
					logctx.Errorln(ctx, err)
				}
			} else {
				if err := c.swarm.tellHub.Deliver(ctx, msg); err != nil {
					logctx.Errorln(ctx, err)
				}
			}
		case ncr, ok := <-c.newChanReqs:
			if !ok {
				return
			}
			if err := ncr.Reject(ssh.Prohibited, "don't do that"); err != nil {
				logctx.Errorln(ctx, err)
			}
		case <-c.shutdown:
			return
		}
	}
}

func (c *Conn) Send(wantReply bool, payload []byte) ([]byte, error) {
	ok, resData, err := c.sconn.SendRequest("", wantReply, payload)
	if err != nil {
		return nil, err
	}
	if !wantReply {
		return nil, nil
	}
	if !ok {
		return nil, errors.Errorf("non-okay response")
	}
	return resData, nil
}

func (c *Conn) RemoteAddr() Addr {
	return c.remoteAddr
}

func (c *Conn) Close() error {
	err := c.sconn.Close()
	c.swarm.deleteConn(c)
	return err
}
