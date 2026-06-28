package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	flagPath    string
	flagLSK     string
	flagVerbose bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fhsm-key-manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagPath, "path", ".", "key root directory")
	root.PersistentFlags().StringVar(&flagLSK, "lsk", "00000000000000000000000000000000", "LSK hex (16 bytes) for 3DES; default all-zero")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "print progress to stderr")
	root.AddCommand(newVersionCmd())
	root.AddCommand(newPBOC1Cmd())
	root.AddCommand(newPBOC2Cmd())
	root.AddCommand(newRSACmd())
	root.AddCommand(newSM2Cmd())
	return root
}

func Execute() error { return newRootCmd().Execute() }

func parseLSK(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid lsk hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("lsk must be 16 bytes (32 hex chars), got %d bytes", len(b))
	}
	return b, nil
}
