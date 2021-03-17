package main

import (
	"net/http"

	"github.com/brendoncarroll/go-p2p/d/celltracker"
	"github.com/spf13/cobra"
)

var addr string

func init() {
	rootCmd.AddCommand(trackerCmd)

	trackerCmd.Flags().StringVar(&addr, "addr", "0.0.0.0:8000", "--addr=127.0.0.1:8000")
}

var trackerCmd = &cobra.Command{
	Use:   "cell-tracker",
	Short: "runs a cell-tracker server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cmd.ParseFlags(args); err != nil {
			return err
		}
		s := celltracker.NewServer()
		defer s.Close()

		return http.ListenAndServe(addr, s)
	},
}
