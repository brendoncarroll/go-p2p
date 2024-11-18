package main

import (
	"context"
	"log"

	"github.com/spf13/cobra"
	"go.brendoncarroll.net/stdctx/logctx"
	"go.uber.org/zap"
)

var ctx = func() context.Context {
	ctx := context.Background()
	l, _ := zap.NewProduction()
	ctx = logctx.NewContext(ctx, l)
	return ctx
}()

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

var rootCmd = &cobra.Command{
	Use:   "p2putil",
	Short: "P2P testing and diagnostics",
}
