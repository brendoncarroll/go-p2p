package main

import (
	"context"
	"log"
	"os"

	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

var ctx = func() context.Context {
	ctx := context.Background()
	l := slog.New(slog.NewTextHandler(os.Stderr))
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
