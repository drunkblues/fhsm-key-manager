package cmd

import (
	"bytes"
	"testing"
)

func TestVersionOutputsJSON(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"name": "fhsm-key-manager"`)) {
		t.Errorf("unexpected output: %s", out.String())
	}
}
