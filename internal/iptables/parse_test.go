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
	if ssh.Chain != "INPUT" || ssh.Index != 4 || ssh.Dport.Start != 22 || ssh.Source != "10.0.0.0/8" || ssh.Action != ActionAllow {
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
