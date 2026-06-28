package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newPBOC1Cmd() *cobra.Command {
	c := &cobra.Command{Use: "pboc1", Short: "Manage PBOC1 symmetric keys (pboc1.key)"}
	c.AddCommand(pboc1GetCmd(), pboc1GetAllCmd(), pboc1ListCmd(), pboc1PutCmd(), pboc1DeleteCmd())
	return c
}

func pboc1GetCmd() *cobra.Command {
	var b, ty, ver, idx int
	c := &cobra.Command{
		Use: "get", Short: "Read a single PBOC1 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			k, err := storage.GetPBOC1(flagPath, lsk, byte(b), byte(ty), byte(ver), byte(idx))
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&b, "block", 0, "block")
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&ver, "version", 0, "version")
	c.Flags().IntVar(&idx, "index", 0, "index")
	return c
}

func pboc1GetAllCmd() *cobra.Command {
	return &cobra.Command{
		Use: "get-all", Short: "Read all PBOC1 keys (with plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			keys, err := storage.ReadAllPBOC1(flagPath, lsk)
			if err != nil {
				return err
			}
			if keys == nil {
				keys = []keymodel.PBOC1Key{}
			}
			keymodel.OutputJSON(keys)
			return nil
		},
	}
}

func pboc1ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List PBOC1 key metadata (no plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListPBOC1(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.PBOC1Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func pboc1PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write/update PBOC1 key(s) from stdin JSON (object or array)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var single keymodel.PBOC1Key
			if json.Unmarshal(raw, &single) == nil && single.Length != 0 {
				if err := storage.PutPBOC1(flagPath, lsk, single); err != nil {
					return err
				}
				keymodel.OutputJSON(map[string]int{"written": 1})
				return nil
			}
			var batch []keymodel.PBOC1Key
			if err := json.Unmarshal(raw, &batch); err != nil {
				return keymodel.NewError("INTERNAL", "invalid pboc1 json: %v", err)
			}
			for _, k := range batch {
				if err := storage.PutPBOC1(flagPath, lsk, k); err != nil {
					return err
				}
			}
			keymodel.OutputJSON(map[string]int{"written": len(batch)})
			return nil
		},
	}
}

func pboc1DeleteCmd() *cobra.Command {
	var b, ty, ver, idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete a PBOC1 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			if err := storage.DeletePBOC1(flagPath, lsk, byte(b), byte(ty), byte(ver), byte(idx)); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&b, "block", 0, "block")
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&ver, "version", 0, "version")
	c.Flags().IntVar(&idx, "index", 0, "index")
	return c
}
