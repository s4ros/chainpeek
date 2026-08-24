package iptables

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFileLoader(t *testing.T) {
	l := FileLoader{Path: filepath.Join("..", "..", "testdata", "filter.rules")}
	res, err := l.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(FilterTable(res.Rules)) != 13 {
		t.Fatalf("got %d", len(FilterTable(res.Rules)))
	}
}

func TestFileLoaderMissing(t *testing.T) {
	_, err := (FileLoader{Path: "no-such-file"}).Load()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdLoader(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "..", "testdata", "filter.rules")
	dst := filepath.Join(dir, "iptables-save")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat <<'EOF'\n" + string(data) + "\nEOF\n"
	if err := os.WriteFile(dst, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := (CmdLoader{Name: dst}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(FilterTable(res.Rules)) != 13 {
		t.Fatal(len(FilterTable(res.Rules)))
	}
}

func TestCmdLoaderFailure(t *testing.T) {
	_, err := (CmdLoader{Name: "false"}).Load()
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*exec.ExitError); ok {
		return
	}
	// wrapped is fine; just require a non-nil error mentioning the command
}
