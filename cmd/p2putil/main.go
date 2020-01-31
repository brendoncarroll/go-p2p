package main

import (
	"context"
	"fmt"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/natswarm"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
	"github.com/spf13/cobra"
	"github.com/syncthing/syncthing/lib/upnp"
)

var log = p2p.Logger

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	rootCmd.AddCommand(upnpCmd)
	rootCmd.AddCommand(testConnectCmd)
}

var rootCmd = &cobra.Command{
	Use:   "p2putil",
	Short: "P2P testing and diagnostics",
}

var upnpCmd = &cobra.Command{
	Use:   "upnp-list",
	Short: "UPnP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		timeout := 3 * time.Second

		log.Println("discovering nat devices...")
		natDevs := upnp.Discover(ctx, timeout/2, timeout)
		for _, natDev := range natDevs {
			localIP, err := natDev.GetExternalIPAddress()
			if err != nil {
				log.Error(err)
			}
			externalIP, err := natDev.GetExternalIPAddress()
			if err != nil {
				log.Error(err)
			}
			cmd.Println(localIP, externalIP, natDev.ID())
		}

		return nil
	},
}

var testConnectCmd = &cobra.Command{
	Use:   "test-connect",
	Short: "Tool for testing connectivity",
	RunE: func(cmd *cobra.Command, args []string) error {
		//_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		//s1, err := sshswarm.New("0.0.0.0:", privKey)
		s1, err := udpswarm.New("0.0.0.0:")
		if err != nil {
			log.Println(err)
		}
		s2 := natswarm.New(s1)
		s2.OnTell(func(m *p2p.Message) {
			log.Println("MSG:", m.Src, "->", m.Dst, " ", m.Payload)
		})

		addrs := map[string]p2p.Addr{}
		for {
			for _, addr := range s2.LocalAddrs() {
				if _, exists := addrs[addr.Key()]; !exists {
					fmt.Println("ADDR:", addr)
					addrs[addr.Key()] = addr
				}
			}
			time.Sleep(time.Second)
		}
	},
}
