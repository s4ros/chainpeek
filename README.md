# chainpeek

Interactive terminal UI for **iptables** firewall rules.

`chainpeek` loads the live ruleset (or an `iptables-save` dump), shows every
rule in a keyboard-driven table, and lets you filter by chain and action and
sort by port — without leaving the terminal.

```
  CHAIN    PROTO  DPORT       SOURCE          DESTINATION     TARGET
▸ INPUT    tcp    22          10.0.0.0/8      0.0.0.0/0       ACCEPT
  INPUT    tcp    80          0.0.0.0/0       0.0.0.0/0       ACCEPT
  INPUT    tcp    443         0.0.0.0/0       0.0.0.0/0       ACCEPT
  FORWARD  tcp    80          192.168.1.0/24  0.0.0.0/0       ACCEPT
  INPUT    all    -           0.0.0.0/0       0.0.0.0/0       REJECT
```

Status: interactive TUI is implemented. Use `--file` for dumps or run live with sudo.

## Name

**chainpeek** — peek through every link of your iptables chains.

## Requirements

- Go 1.25+
- Linux with `iptables-save` on `PATH` (for live mode)
- Root or `CAP_NET_ADMIN` to read the live ruleset (file mode needs neither)

## Build

```bash
make build    # bin/chainpeek
make test
```

Go is installed at `/usr/local/go/bin/go` on this machine. If `go` is not on
your `PATH`:

```bash
export PATH="/usr/local/go/bin:$PATH"
```

## Usage

```bash
sudo chainpeek                      # live iptables-save
chainpeek --file testdata/filter.rules
```

| Key | Action |
|-----|--------|
| `↑` / `k`, `↓` / `j` | Move selection |
| `c` / `Tab` | Focus / toggle chain dropdown |
| `1` | All chains |
| `2` / `3` / `4` | INPUT / OUTPUT / FORWARD |
| `a` / `d` / `f` | ALLOW / DENY / all actions |
| `p` | Toggle sort by destination port |
| `r` | Reload rules |
| `?` | Help |
| `q` | Quit |

The chain dropdown lists every `*filter` chain, including user-defined and empty ones. Shortcuts `1`–`4` always jump to ALL / INPUT / OUTPUT / FORWARD.

ALLOW is `ACCEPT`. DENY is `DROP` or `REJECT`.

## Layout

```
cmd/chainpeek/          CLI entrypoint
internal/iptables/      Parse iptables-save into typed rules
internal/view/          Filter (chain, action) and sort (port)
internal/tui/           Bubble Tea table
testdata/               Fixture dumps for tests and --file mode
docs/superpowers/       Design spec and implementation plan
```

## Docs

- [Design spec](docs/superpowers/specs/2026-08-24-chainpeek-design.md)
- [Implementation plan](docs/superpowers/plans/2026-08-24-chainpeek-implementation.md)

## License

MIT
