package iptables

import (
	"os"
	"strings"
	"testing"
)

func TestParseTestdata(t *testing.T) {
	f, err := os.Open("../../testdata/filter.rules")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	filter := FilterTable(res.Rules)
	if len(filter) != 13 {
		t.Fatalf("filter rules=%d want 13", len(filter))
	}

	ssh := filter[3]
	if ssh.Chain != "INPUT" || ssh.Index != 4 || ssh.Dport.Start != 22 || ssh.Source != "10.0.0.0/8" || ssh.Action != ActionAllow || ssh.Comment != "SSH from office" {
		t.Fatalf("ssh rule: %+v", ssh)
	}

	rng := findDport(t, filter, 1024)
	if rng.Dport.End != 65535 || rng.Action != ActionDeny {
		t.Fatalf("range rule: %+v", rng)
	}

	rej := filter[8]
	if rej.Target != "REJECT" || rej.Action != ActionDeny {
		t.Fatalf("reject: %+v", rej)
	}

	var nat int
	for _, r := range res.Rules {
		if r.Table == "nat" {
			nat++
		}
	}
	if nat != 1 {
		t.Fatalf("nat rules=%d want 1", nat)
	}
}

func TestParseEmpty(t *testing.T) {
	res, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 0 {
		t.Fatalf("got %d", len(res.Rules))
	}
}

func TestParseSkipsJunk(t *testing.T) {
	in := "*filter\n:INPUT ACCEPT [0:0]\nthis is not a rule\n-A INPUT -j ACCEPT\nCOMMIT\n"
	res, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 {
		t.Fatalf("rules=%d warnings=%v", len(res.Rules), res.Warnings)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected warning for junk line")
	}
}

func TestParseSkipsMissingTarget(t *testing.T) {
	in := "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp\n-A INPUT -j ACCEPT\nCOMMIT\n"
	res, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 {
		t.Fatalf("rules=%d want 1 warnings=%v", len(res.Rules), res.Warnings)
	}
	if res.Rules[0].Target != "ACCEPT" {
		t.Fatalf("kept %+v", res.Rules[0])
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected warning for -A with no target")
	}
}

func TestParseComment(t *testing.T) {
	in := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		`-A INPUT -p tcp --dport 22 -m comment --comment "SSH from office" -j ACCEPT`,
		`-A INPUT -p tcp --dport 80 -m comment --comment http -j ACCEPT`,
		`-A INPUT -m comment --comment "say \"hi\"" -j ACCEPT`,
		`-A INPUT -j ACCEPT`,
		"COMMIT",
	}, "\n") + "\n"
	res, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 4 {
		t.Fatalf("rules=%d warnings=%v", len(res.Rules), res.Warnings)
	}
	if res.Rules[0].Comment != "SSH from office" {
		t.Fatalf("quoted comment=%q", res.Rules[0].Comment)
	}
	if strings.Contains(res.Rules[0].Extra, "comment") || strings.Contains(res.Rules[0].Extra, "SSH") {
		t.Fatalf("comment leaked into Extra: %q", res.Rules[0].Extra)
	}
	if res.Rules[1].Comment != "http" {
		t.Fatalf("bare comment=%q", res.Rules[1].Comment)
	}
	if res.Rules[2].Comment != `say "hi"` {
		t.Fatalf("escaped comment=%q", res.Rules[2].Comment)
	}
	if res.Rules[3].Comment != "" {
		t.Fatalf("missing comment should be empty, got %q", res.Rules[3].Comment)
	}
}

func TestSplitFields(t *testing.T) {
	got := splitFields(`-A INPUT --comment "SSH from office" -j ACCEPT`)
	want := []string{"-A", "INPUT", "--comment", "SSH from office", "-j", "ACCEPT"}
	if !equalStrings(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func findDport(t *testing.T, rules []Rule, start int) Rule {
	t.Helper()
	for _, r := range rules {
		if r.Dport.Start == start {
			return r
		}
	}
	t.Fatalf("no dport %d", start)
	return Rule{}
}

func TestParseTestdataChains(t *testing.T) {
	f, err := os.Open("../../testdata/filter.rules")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"INPUT", "FORWARD", "OUTPUT", "DOCKER", "DOCKER-USER", "PREROUTING", "POSTROUTING"}
	if !equalStrings(res.Chains, want) {
		t.Fatalf("Chains=%v want %v", res.Chains, want)
	}
}

func TestParseChains(t *testing.T) {
	in := strings.Join([]string{
		"*filter",
		":INPUT DROP [0:0]",
		":FORWARD DROP [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":DOCKER - [0:0]",
		"-A INPUT -j ACCEPT",
		"-A ORPHAN -j ACCEPT",
		"COMMIT",
		"*nat",
		":PREROUTING ACCEPT [0:0]",
		":INPUT ACCEPT [0:0]",
		":POSTROUTING ACCEPT [0:0]",
		":DOCKER - [0:0]",
		"-A POSTROUTING -j MASQUERADE",
		"COMMIT",
	}, "\n") + "\n"
	res, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"INPUT", "FORWARD", "OUTPUT", "DOCKER", "ORPHAN", "PREROUTING", "POSTROUTING"}
	if !equalStrings(res.Chains, want) {
		t.Fatalf("Chains=%v want %v", res.Chains, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
