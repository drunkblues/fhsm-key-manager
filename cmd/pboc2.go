package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newPBOC2Cmd() *cobra.Command {
	c := &cobra.Command{Use: "pboc2", Short: "Manage PBOC2 symmetric keys (pboc2.key)"}
	c.AddCommand(pboc2GetCmd(), pboc2GetAllCmd(), pboc2ListCmd(), pboc2PutCmd(), pboc2DeleteCmd())
	return c
}

func pboc2GetCmd() *cobra.Command {
	var ty, idx, sub int
	c := &cobra.Command{
		Use: "get", Short: "Read a single PBOC2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			k, err := storage.GetPBOC2(flagPath, lsk, byte(ty), byte(idx), byte(sub))
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&idx, "index", 0, "index")
	c.Flags().IntVar(&sub, "subtype", 0, "subtype")
	return c
}

func pboc2GetAllCmd() *cobra.Command {
	return &cobra.Command{
		Use: "get-all", Short: "Read all PBOC2 keys (with plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			keys, err := storage.ReadAllPBOC2(flagPath, lsk)
			if err != nil {
				return err
			}
			if keys == nil {
				keys = []keymodel.PBOC2Key{}
			}
			keymodel.OutputJSON(keys)
			return nil
		},
	}
}

func pboc2ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List PBOC2 key metadata (no plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListPBOC2(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.PBOC2Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func pboc2PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write/update PBOC2 key(s) from stdin JSON (object or array)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var single keymodel.PBOC2Key
			if json.Unmarshal(raw, &single) == nil && single.Length != 0 {
				if err := storage.PutPBOC2(flagPath, lsk, single); err != nil {
					return err
				}
				keymodel.OutputJSON(map[string]int{"written": 1})
				return nil
			}
			var batch []keymodel.PBOC2Key
			if err := json.Unmarshal(raw, &batch); err != nil {
				return keymodel.NewError("INTERNAL", "invalid pboc2 json: %v", err)
			}
			for _, k := range batch {
				if err := storage.PutPBOC2(flagPath, lsk, k); err != nil {
					return err
				}
			}
			keymodel.OutputJSON(map[string]int{"written": len(batch)})
			return nil
		},
	}
}

func pboc2DeleteCmd() *cobra.Command {
	var ty, idx, sub int
	c := &cobra.Command{
		Use: "delete", Short: "Delete a PBOC2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			if err := storage.DeletePBOC2(flagPath, lsk, byte(ty), byte(idx), byte(sub)); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&idx, "index", 0, "index")
	c.Flags().IntVar(&sub, "subtype", 0, "subtype")
	return c
}
