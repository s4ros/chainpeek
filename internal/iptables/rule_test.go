package iptables

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Action{
		"ACCEPT":     ActionAllow,
		"accept":     ActionAllow,
		"DROP":       ActionDeny,
		"REJECT":     ActionDeny,
		"LOG":        ActionOther,
		"MASQUERADE": ActionOther,
		"MYCHAIN":    ActionOther,
		"":           ActionOther,
	}
	for target, want := range cases {
		if got := Classify(target); got != want {
			t.Errorf("Classify(%q)=%v want %v", target, got, want)
		}
	}
}

func TestPortSortKey(t *testing.T) {
	if (Port{Start: 22}).SortKey() != 22 {
		t.Fatal("single port key")
	}
	if (Port{Start: 1024, End: 65535}).SortKey() != 1024 {
		t.Fatal("range uses start")
	}
	if (Port{}).SortKey() != 1<<30 {
		t.Fatal("unset port sorts last")
	}
}
