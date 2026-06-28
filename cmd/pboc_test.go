package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func runCmd(t *testing.T, dir, lsk string, args ...string) (map[string]any, error) {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(append([]string{"--path", dir, "--lsk", lsk}, args...))
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := root.Execute()
	w.Close()
	os.Stdout = orig
	var out bytes.Buffer
	io.Copy(&out, r)
	r.Close()
	var m map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m)
	return m, err
}

func TestPBOC1CLIPutGet(t *testing.T) {
	dir := t.TempDir()
	lsk := "11111111111111111111111111111111"
	putJSON := `{"block":1,"type":2,"version":0,"index":1,"alg":0,"div":1,"exp":0,"length":16,"key":"aabbccddaabbccddaabbccddaabbccdd"}`
	tmp := filepath.Join(dir, "in.json")
	os.WriteFile(tmp, []byte(putJSON), 0644)
	orig := os.Stdin
	f, _ := os.Open(tmp)
	os.Stdin = f
	_, err := runCmd(t, dir, lsk, "pboc1", "put")
	os.Stdin = orig
	f.Close()
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	m, err := runCmd(t, dir, lsk, "pboc1", "get", "--block", "1", "--type", "2", "--version", "0", "--index", "1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if m["key"] != "aabbccddaabbccddaabbccddaabbccdd" {
		t.Errorf("key mismatch: %v", m["key"])
	}
}
