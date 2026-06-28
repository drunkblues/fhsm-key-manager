package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, _ := json.MarshalIndent(map[string]string{"name": "fhsm-key-manager", "version": version}, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
}
