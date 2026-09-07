package iptables

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ParseResult struct {
	Rules    []Rule
	Chains   []string
	Warnings []string
}

func Parse(r io.Reader) (ParseResult, error) {
	var res ParseResult
	sc := bufio.NewScanner(r)
	table := ""
	index := make(map[string]int)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
		case line == "COMMIT":
			table = ""
		case strings.HasPrefix(line, ":"):
			if table != "" {
				rest := strings.TrimPrefix(line, ":")
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					res.Chains = appendChain(res.Chains, fields[0])
				}
			}
		case strings.HasPrefix(line, "-A"):
			rule, ok := parseRule(table, line)
			if !ok {
				res.Warnings = append(res.Warnings, fmt.Sprintf("skipping malformed rule: %s", line))
				continue
			}
			res.Chains = appendChain(res.Chains, rule.Chain)
			key := table + "/" + rule.Chain
			index[key]++
			rule.Index = index[key]
			res.Rules = append(res.Rules, rule)
		default:
			if table != "" {
				res.Warnings = append(res.Warnings, fmt.Sprintf("skipping unexpected line: %s", line))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return ParseResult{}, err
	}
	return res, nil
}

func parseRule(table, line string) (Rule, bool) {
	fields := splitFields(line)
	if len(fields) < 2 {
		return Rule{}, false
	}
	r := Rule{
		Table: table,
		Chain: fields[1],
		Raw:   line,
	}
	var extra []string
	for i := 2; i < len(fields); i++ {
		f := fields[i]
		take := func() (string, bool) {
			if i+1 >= len(fields) {
				return "", false
			}
			i++
			return fields[i], true
		}
		switch f {
		case "-p", "--protocol":
			if v, ok := take(); ok {
				r.Protocol = v
			}
		case "-i":
			if v, ok := take(); ok {
				r.InIface = v
			}
		case "-o":
			if v, ok := take(); ok {
				r.OutIface = v
			}
		case "-s":
			if v, ok := take(); ok {
				r.Source = v
			}
		case "-d":
			if v, ok := take(); ok {
				r.Destination = v
			}
		case "-j":
			if v, ok := take(); ok {
				r.Target = v
			}
		case "--dport":
			if v, ok := take(); ok {
				r.Dport = parsePort(v)
			}
		case "--sport":
			if v, ok := take(); ok {
				r.Sport = parsePort(v)
			}
		case "--dports":
			if v, ok := take(); ok {
				first, rest, found := strings.Cut(v, ",")
				r.Dport = parsePort(first)
				if found {
					extra = append(extra, rest)
				}
			}
		case "--sports":
			if v, ok := take(); ok {
				first, rest, found := strings.Cut(v, ",")
				r.Sport = parsePort(first)
				if found {
					extra = append(extra, rest)
				}
			}
		case "--comment":
			if v, ok := take(); ok {
				r.Comment = v
			}
		case "-m":
			if v, ok := take(); ok && v != "comment" {
				extra = append(extra, "-m", v)
			}
		default:
			extra = append(extra, f)
		}
	}
	if r.Target == "" {
		return Rule{}, false
	}
	if r.Protocol == "" {
		r.Protocol = "all"
	}
	if r.Source == "" {
		r.Source = "0.0.0.0/0"
	}
	if r.Destination == "" {
		r.Destination = "0.0.0.0/0"
	}
	r.Action = Classify(r.Target)
	r.Extra = strings.Join(extra, " ")
	return r, true
}

// splitFields splits an iptables-save rule on whitespace, keeping
// double-quoted values (used by --comment) as a single field.
func splitFields(line string) []string {
	var fields []string
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if line[i] == '"' {
			i++
			var b strings.Builder
			for i < len(line) {
				if line[i] == '\\' && i+1 < len(line) {
					b.WriteByte(line[i+1])
					i += 2
					continue
				}
				if line[i] == '"' {
					i++
					break
				}
				b.WriteByte(line[i])
				i++
			}
			fields = append(fields, b.String())
			continue
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' {
			j++
		}
		fields = append(fields, line[i:j])
		i = j
	}
	return fields
}

func parsePort(v string) Port {
	a, b, ok := strings.Cut(v, ":")
	start, _ := strconv.Atoi(a)
	p := Port{Start: start}
	if ok {
		p.End, _ = strconv.Atoi(b)
	}
	return p
}

func FilterTable(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Table == "filter" {
			out = append(out, r)
		}
	}
	return out
}

func appendChain(dst []string, name string) []string {
	if name == "" {
		return dst
	}
	for _, c := range dst {
		if c == name {
			return dst
		}
	}
	return append(dst, name)
}
