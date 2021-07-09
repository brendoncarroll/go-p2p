package sshswarm

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	swarm      *Swarm
	remoteAddr *Addr
	localAddr  *Addr
	shutdown   chan struct{}

	newChanReqs <-chan ssh.NewChannel
	reqs        <-chan *ssh.Request
	sconn       ssh.Conn
	pubKey      ssh.PublicKey
}

func newServer(s *Swarm, netConn net.Conn, af AllowFunc) (*Conn, error) {
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
	convertKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("public key not supported")
	}
	remoteID := p2p.NewPeerID(convertKey.CryptoPublicKey())
	if !af(remoteID) {
		return nil, errors.New("peer is not allowed")
	}

	raddr := sconn.RemoteAddr().(*net.TCPAddr)
	rip := raddr.IP
	port := raddr.Port

	c := &Conn{
		swarm: s,
		remoteAddr: &Addr{
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			IP:          rip,
			Port:        port,
		},
		localAddr: &Addr{
			Fingerprint: ssh.FingerprintSHA256(s.signer.PublicKey()),
			IP:          netConn.LocalAddr().(*net.TCPAddr).IP,
			Port:        netConn.LocalAddr().(*net.TCPAddr).Port,
		},
		shutdown: make(chan struct{}),

		newChanReqs: newChans,
		reqs:        reqs,
		sconn:       sconn,
		pubKey:      pubKey,
	}

	return c, nil
}

func newClient(s *Swarm, remoteAddr *Addr, netConn net.Conn) (*Conn, error) {
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

func (c *Conn) loop() {
	resp := make([]byte, MTU)
	for {
		select {
		case req := <-c.reqs:
			ctx := context.TODO()
			msg := p2p.Message{
				Src:     c.RemoteAddr(),
				Dst:     c.localAddr,
				Payload: req.Payload,
			}
			if req.WantReply {
				n, err := c.swarm.askHub.Deliver(ctx, resp, msg)
				if err != nil {
					log.Println(err)
				}
				if err := req.Reply(true, resp[:n]); err != nil {
					log.Println(err)
				}
			} else {
				if err := c.swarm.tellHub.Deliver(ctx, msg); err != nil {
					log.Println(err)
				}
			}
		case ncr := <-c.newChanReqs:
			if err := ncr.Reject(ssh.Prohibited, "don't do that"); err != nil {
				log.Println(err)
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
	if ok {
		return resData, nil
	}
	return nil, nil
}

func (c *Conn) RemoteAddr() *Addr {
	return c.remoteAddr
}

func (c *Conn) Close() error {
	err := c.sconn.Close()
	c.swarm.deleteConn(c)
	return err
}
