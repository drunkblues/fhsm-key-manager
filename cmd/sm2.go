package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newSM2Cmd() *cobra.Command {
	c := &cobra.Command{Use: "sm2", Short: "Manage SM2 keys (sm2/NNNN.SM2)"}
	c.AddCommand(sm2GetCmd(), sm2ListCmd(), sm2PutCmd(), sm2DeleteCmd(), sm2GenCmd())
	return c
}

func sm2GetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an SM2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetSM2(flagPath, idx)
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

func sm2ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List SM2 key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListSM2(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.SM2Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func sm2PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an SM2 key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.SM2Key
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid sm2 json: %v", err)
			}
			if err := storage.PutSM2(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func sm2DeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an SM2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteSM2(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func sm2GenCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "gen", Short: "Generate an SM2 keypair (sm2p256v1)",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GenSM2(flagPath, idx)
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
