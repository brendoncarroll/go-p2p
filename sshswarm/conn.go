package sshswarm

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/swarmutil"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	swarm      *Swarm
	remoteAddr *Addr
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
	rip := raddr.IP
	port := raddr.Port

	c := &Conn{
		swarm: s,
		remoteAddr: &Addr{
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			IP:          rip,
			Port:        port,
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
	for {
		select {
		case req := <-c.reqs:
			ctx := context.TODO()
			msg := &p2p.Message{
				Src:     c.RemoteAddr(),
				Dst:     c.swarm.LocalAddr(),
				Payload: req.Payload,
			}
			if req.WantReply {
				buf := bytes.Buffer{}
				lw := &swarmutil.LimitWriter{W: &buf, N: MTU}
				c.swarm.handleAsk(ctx, msg, lw)
				resData := buf.Bytes()
				if err := req.Reply(true, resData); err != nil {
					log.Println(err)
				}
			} else {
				c.swarm.handleTell(msg)
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
