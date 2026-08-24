// Package view filters and sorts parsed iptables rules for the TUI.
package view

import (
	"sort"

	"github.com/s4ros/chainpeek/internal/iptables"
)

type ChainFilter int

const (
	ChainAll ChainFilter = iota
	ChainInput
	ChainOutput
	ChainForward
)

type ActionFilter int

const (
	ActionAll ActionFilter = iota
	ActionAllow
	ActionDeny
)

type Query struct {
	Chain  ChainFilter
	Action ActionFilter
	ByPort bool
}

func Apply(rules []iptables.Rule, q Query) []iptables.Rule {
	out := make([]iptables.Rule, 0, len(rules))
	for _, r := range rules {
		if !matchChain(r, q.Chain) || !matchAction(r, q.Action) {
			continue
		}
		out = append(out, r)
	}
	if q.ByPort {
		sort.SliceStable(out, func(i, j int) bool {
			di, dj := out[i].Dport.SortKey(), out[j].Dport.SortKey()
			if di != dj {
				return di < dj
			}
			si, sj := out[i].Sport.SortKey(), out[j].Sport.SortKey()
			if si != sj {
				return si < sj
			}
			return out[i].Index < out[j].Index
		})
	}
	return out
}

func matchChain(r iptables.Rule, f ChainFilter) bool {
	switch f {
	case ChainInput:
		return r.Chain == "INPUT"
	case ChainOutput:
		return r.Chain == "OUTPUT"
	case ChainForward:
		return r.Chain == "FORWARD"
	default:
		return true
	}
}

func matchAction(r iptables.Rule, f ActionFilter) bool {
	switch f {
	case ActionAllow:
		return r.Action == iptables.ActionAllow
	case ActionDeny:
		return r.Action == iptables.ActionDeny
	default:
		return true
	}
}
