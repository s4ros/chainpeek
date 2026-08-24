package main

import (
	"strings"
	"testing"
)

func TestParseHelp(t *testing.T) {
	o, err := parseArgs([]string{"--help"})
	if err != nil || !o.help {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseVersion(t *testing.T) {
	o, err := parseArgs([]string{"-v"})
	if err != nil || !o.version {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseFile(t *testing.T) {
	o, err := parseArgs([]string{"--file", "testdata/filter.rules"})
	if err != nil || o.file != "testdata/filter.rules" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseUnknown(t *testing.T) {
	_, err := parseArgs([]string{"--nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUsageReload(t *testing.T) {
	if strings.Contains(usage, "Refresh") {
		t.Fatal("usage should say Reload, not Refresh")
	}
	if !strings.Contains(usage, "Reload") {
		t.Fatal("usage should mention Reload")
	}
}
