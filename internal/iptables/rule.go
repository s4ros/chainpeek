// Package iptables parses iptables-save dumps into typed firewall rules.
package iptables

import "strings"

type Action int

const (
	ActionOther Action = iota
	ActionAllow
	ActionDeny
)

func Classify(target string) Action {
	switch strings.ToUpper(target) {
	case "ACCEPT":
		return ActionAllow
	case "DROP", "REJECT":
		return ActionDeny
	default:
		return ActionOther
	}
}

type Port struct {
	Start int
	End   int
}

func (p Port) SortKey() int {
	if p.Start == 0 {
		return 1 << 30
	}
	return p.Start
}

type Rule struct {
	Table       string
	Chain       string
	Index       int
	Protocol    string
	InIface     string
	OutIface    string
	Source      string
	Destination string
	Sport       Port
	Dport       Port
	Target      string
	Action      Action
	Extra       string
	Raw         string
}
