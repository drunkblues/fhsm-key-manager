package cmd

import (
	"bytes"
	"encoding/json"
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
	var m map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out.String())
	}
	if m["name"] != "fhsm-key-manager" {
		t.Errorf("name=%q", m["name"])
	}
	if m["version"] == "" {
		t.Error("version empty")
	}
}
