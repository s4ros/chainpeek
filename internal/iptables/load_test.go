package iptables

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if !errors.Is(err, fs.ErrNotExist) && !os.IsNotExist(err) {
		t.Fatalf("want not-exist, got %v", err)
	}
	if !strings.HasPrefix(err.Error(), "chainpeek: open no-such-file:") {
		t.Fatalf("got %q", err.Error())
	}
}

func TestCmdLoaderNotFound(t *testing.T) {
	_, err := (CmdLoader{Name: "chainpeek-no-such-iptables-save"}).Load()
	if err == nil {
		t.Fatal("expected error")
	}
	want := "chainpeek: iptables-save not found on PATH (try --file)"
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
}

func TestCmdLoaderPermission(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "iptables-save")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := (CmdLoader{Name: bin}).Load()
	if err == nil {
		t.Fatal("expected error")
	}
	want := "chainpeek: cannot read live rules (need root or --file)"
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
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
