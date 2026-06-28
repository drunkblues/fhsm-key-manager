package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newECCCmd() *cobra.Command {
	c := &cobra.Command{Use: "ecc", Short: "Manage ECC keys (ecc/NNNN.ECC, store/retrieve only)"}
	c.AddCommand(eccGetCmd(), eccListCmd(), eccPutCmd(), eccDeleteCmd())
	return c
}

func eccGetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an ECC key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetECC(flagPath, idx)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func eccListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List ECC key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListECC(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.ECCMeta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func eccPutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an ECC key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.ECCKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid ecc json: %v", err)
			}
			if err := storage.PutECC(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func eccDeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an ECC key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteECC(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}
