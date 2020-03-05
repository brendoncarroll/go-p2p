package celltracker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/c/httpcell"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/sha3"
)

const (
	MaxPayloadSize = 1 << 15

	CurrentHeader = httpcell.CurrentHeader
	SignerHeader  = "X-Signer"

	gracePeriod = time.Minute
)

type serverCell struct {
	publicKey ed25519.PublicKey

	mu      sync.Mutex
	mtime   time.Time
	payload []byte
}

func (c *serverCell) shouldEvict() bool {
	c.mu.Lock()
	mtime := c.mtime
	c.mu.Unlock()

	now := time.Now()
	return mtime.Add(gracePeriod).Before(now)
}

func (c *serverCell) get(ctx context.Context) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payload
}

func (c *serverCell) cas(ctx context.Context, believedHash, next []byte) (bool, []byte, error) {
	pubKey := [32]byte{}
	copy(pubKey[:], c.publicKey)
	_, valid := sign.Open(nil, next, &pubKey)
	if !valid {
		return false, nil, errors.New("invalid signature")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	actualHash := sha3.Sum256(c.payload)
	if bytes.Compare(believedHash, actualHash[:]) != 0 {
		return false, c.payload, nil
	}

	c.payload = next
	c.mtime = time.Now()
	return true, c.payload, nil
}

type Server struct {
	cells sync.Map
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Run(ctx context.Context) {
	s.evictLoop(ctx)
}

func (s *Server) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := s.evict(ctx)
			if count > 0 {
				log.Infof("evicted %d cells", count)
			}
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"path":    r.URL.Path,
		"method":  r.Method,
		"headers": r.Header,
	}).Info()
	switch r.Method {
	case http.MethodPut:
		s.handlePut(w, r)
	case http.MethodGet:
		s.handleGet(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := idFromPath(r)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("error parsing id from path"))
	}

	believedHashb64 := r.Header.Get(httpcell.CurrentHeader)
	believedHash, err := base64.URLEncoding.DecodeString(believedHashb64)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pubKey, err := keyFromReq(r)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	id2 := p2p.NewPeerID(pubKey)
	if !id2.Equals(id) {
		err = errors.New("public key does not match id")
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	proposed, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("couldn't read body"))
		return
	}
	if len(proposed) > MaxPayloadSize {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("body too large"))
	}

	c := s.loadOrStoreCell(pubKey)
	_, actual, err := c.cas(ctx, believedHash, proposed)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}
	if _, err := w.Write(actual); err != nil {
		log.Error(err)
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := idFromPath(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("error parsing id from path"))
	}

	c := s.loadCell(id)

	var data []byte
	if c != nil {
		if c.shouldEvict() {
			s.cells.Delete(id)
			c = nil
		} else {
			data = c.get(ctx)
		}
	}
	if _, err := w.Write(data); err != nil {
		log.Error(err)
	}
}

func (s *Server) loadCell(id p2p.PeerID) *serverCell {
	v, exists := s.cells.Load(id)
	if !exists {
		return nil
	}
	return v.(*serverCell)
}

func (s *Server) loadOrStoreCell(publicKey ed25519.PublicKey) *serverCell {
	id := p2p.NewPeerID(publicKey)
	c := &serverCell{
		publicKey: publicKey,
	}
	v, _ := s.cells.LoadOrStore(id, c)
	return v.(*serverCell)
}

func (s *Server) evict(ctx context.Context) (count int) {
	s.cells.Range(func(k, v interface{}) bool {
		cell := v.(*serverCell)
		if cell.shouldEvict() {
			s.cells.Delete(k)
			count++
		}
		return true
	})

	return count
}

func idFromPath(r *http.Request) (p2p.PeerID, error) {
	p := r.URL.Path[1:]
	data, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return p2p.PeerID{}, errors.Wrap(err, "error extracting peer id from path")
	}
	if len(data) != 32 {
		return p2p.PeerID{}, fmt.Errorf("wrong length for peer id: %d", len(data))
	}
	id := p2p.PeerID{}
	copy(id[:], data)
	return id, nil
}

func keyFromReq(r *http.Request) (ed25519.PublicKey, error) {
	pubKeyB64 := r.Header.Get(SignerHeader)
	pubKeyBytes, err := base64.URLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, err
	}
	pubKey, err := p2p.ParsePublicKey(pubKeyBytes)
	if err != nil {
		err = errors.Wrap(err, "not a valid public key")
		return nil, err
	}
	edPubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		err = errors.New("only ed25519 keys supported")
		return nil, err
	}
	return edPubKey, nil
}
