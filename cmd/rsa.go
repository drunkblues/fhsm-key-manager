package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newRSACmd() *cobra.Command {
	c := &cobra.Command{Use: "rsa", Short: "Manage RSA keys (rsa/NNNN.RSA)"}
	c.AddCommand(rsaGetCmd(), rsaListCmd(), rsaPutCmd(), rsaDeleteCmd(), rsaGenCmd())
	return c
}

func rsaGetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an RSA private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetRSA(flagPath, idx)
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

func rsaListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List RSA key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListRSA(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.RSAMeta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func rsaPutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an RSA key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.RSAKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid rsa json: %v", err)
			}
			if err := storage.PutRSA(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func rsaDeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an RSA key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteRSA(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func rsaGenCmd() *cobra.Command {
	var idx, modLen, exp int
	c := &cobra.Command{
		Use: "gen", Short: "Generate an RSA keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GenRSA(flagPath, idx, modLen, exp)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	c.Flags().IntVar(&modLen, "modlen", 2048, "modulus length in bits")
	c.Flags().IntVar(&exp, "exponent", 65537, "public exponent")
	return c
}
