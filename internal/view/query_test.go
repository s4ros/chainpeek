package view

import (
	"testing"

	"github.com/s4ros/chainpeek/internal/iptables"
)

func sample() []iptables.Rule {
	return []iptables.Rule{
		{Chain: "INPUT", Index: 1, Dport: iptables.Port{Start: 80}, Action: iptables.ActionAllow, Raw: "a"},
		{Chain: "INPUT", Index: 2, Dport: iptables.Port{Start: 22}, Action: iptables.ActionAllow, Raw: "b"},
		{Chain: "OUTPUT", Index: 1, Dport: iptables.Port{Start: 443}, Action: iptables.ActionAllow, Raw: "c"},
		{Chain: "FORWARD", Index: 1, Action: iptables.ActionDeny, Raw: "d"},
		{Chain: "INPUT", Index: 3, Action: iptables.ActionDeny, Raw: "e"},
		{Chain: "MYCHAIN", Index: 1, Action: iptables.ActionAllow, Raw: "f"},
	}
}

func TestApplyChain(t *testing.T) {
	got := Apply(sample(), Query{Chain: "INPUT"})
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	for _, r := range got {
		if r.Chain != "INPUT" {
			t.Fatalf("chain %s", r.Chain)
		}
	}
}

func TestApplyChainAllKeepsUserChain(t *testing.T) {
	got := Apply(sample(), Query{})
	if len(got) != 6 {
		t.Fatalf("len=%d want 6 (includes MYCHAIN)", len(got))
	}
}

func TestApplyUserChain(t *testing.T) {
	got := Apply(sample(), Query{Chain: "MYCHAIN"})
	if len(got) != 1 || got[0].Raw != "f" {
		t.Fatalf("%+v", got)
	}
}

func TestApplyAction(t *testing.T) {
	got := Apply(sample(), Query{Action: ActionDeny})
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestApplyPortSort(t *testing.T) {
	got := Apply(sample(), Query{ByPort: true})
	want := []int{22, 80, 443, 1 << 30, 1 << 30, 1 << 30}
	for i, r := range got {
		if r.Dport.SortKey() != want[i] {
			t.Fatalf("i=%d key=%d want %d raw=%s", i, r.Dport.SortKey(), want[i], r.Raw)
		}
	}
}

func TestApplyDoesNotMutate(t *testing.T) {
	in := sample()
	_ = Apply(in, Query{ByPort: true, Chain: "INPUT"})
	if in[0].Raw != "a" || in[1].Raw != "b" {
		t.Fatal("input mutated")
	}
}
