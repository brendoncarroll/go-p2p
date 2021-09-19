package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/multiswarm"
	"github.com/brendoncarroll/go-p2p/s/sshswarm"
	"github.com/spf13/cobra"
)

var log = p2p.Logger

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	rootCmd.AddCommand(testConnectCmd)
}

var rootCmd = &cobra.Command{
	Use:   "p2putil",
	Short: "P2P testing and diagnostics",
}

var testConnectCmd = &cobra.Command{
	Use:   "test-connect",
	Short: "Tool for testing connectivity",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)

		s1, err := sshswarm.New("0.0.0.0:", privKey, nil)
		if err != nil {
			return err
		}

		s3 := multiswarm.NewSecureAsk(map[string]p2p.SecureAskSwarm{
			"ssh": s1,
		})

		go func() error {
			ctx := context.TODO()
			buf := make([]byte, s3.MaxIncomingSize())
			for {
				var src, dst p2p.Addr
				n, err := s3.Receive(ctx, &src, &dst, buf)
				if err != nil {
					return err
				}
				if err := s3.Tell(ctx, src, p2p.IOVec{buf[:n]}); err != nil {
					return err
				}
				log.Println("MSG:", src, "->", dst, " ", buf[:n])
			}
		}()

		addrs := map[string]p2p.Addr{}
		for {
			for _, addr := range s3.LocalAddrs() {
				if _, exists := addrs[addr.String()]; !exists {
					fmt.Println("ADDR:", addr)
					addrs[addr.String()] = addr
				}
			}
			time.Sleep(time.Second)
		}
		return nil
	},
}
