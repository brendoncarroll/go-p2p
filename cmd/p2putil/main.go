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

		s3 := multiswarm.NewSecureAsk(map[string]multiswarm.DynSecureAskSwarm{
			"ssh": multiswarm.WrapSecureAskSwarm[sshswarm.Addr](s1),
		})

		go func() error {
			ctx := context.TODO()
			var msg p2p.Message[multiswarm.Addr]
			for {
				if err := p2p.Receive[multiswarm.Addr](ctx, s3, &msg); err != nil {
					return err
				}
				src, dst := msg.Src, msg.Dst
				if err := s3.Tell(ctx, src, p2p.IOVec{msg.Payload}); err != nil {
					return err
				}
				log.Printf("MSG: %v -> %v : %q", src, dst, msg.Payload)
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
	},
}
