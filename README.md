# network-doctor

A terminal UI that diagnoses your network connectivity and tells you **where the
connection breaks** in plain English — not just a wall of tool output.

The home screen runs short, native, rootless probes as a small dependency graph,
then a diagnosis engine turns their combined state into a one-line verdict. The
left pane is the probe chain; the right pane is the diagnosis plus details for
the selected probe.

```
Network Doctor                Diagnosis

✓ Interface                   github.com:443 is reachable and responding.
✓ Internet (TCP egress)
✓ DNS github.com              HTTP github.com
✓ TCP github.com:443          PASS — HTTP 200 (responded)
✓ TLS github.com
✓ HTTP github.com

↑/↓ select · r rerun · q quit
```

## How it diagnoses

Probes form a **dependency graph with two paths**, so an unrelated failure never
hides a working one:

- **Direct-egress path** (independent of DNS): `Interface → Internet (TCP
  egress)`. Always runs, so "DNS is down but the internet is up" is diagnosable.
- **Target path** (needs the resolved IP): `Interface → DNS → TCP → protocol
  rows`.

Each row is one of four states: **✓ Pass**, **✗ Fail**, **⊘ Skip** (a
prerequisite failed), or **– N/A** (doesn't apply — e.g. DNS on an IP literal).

| Probe | Passes when | Notes |
|-------|-------------|-------|
| **Interface** | A non-loopback interface is up and running | |
| **Internet (TCP egress)** | A TCP connect to `1.1.1.1`/`8.8.8.8:443` succeeds | honestly "direct egress" — proxy-only networks can fail this |
| **DNS** | The host resolves to an IPv4 (system resolution) | IP-literal targets are N/A; all A records are retained |
| **TCP** | A TCP connect to the target port succeeds | tries each A record, pins the first that connects |
| **TLS** | The TLS handshake (SNI + cert verification) succeeds | bad/expired cert, clock skew, or MITM → Fail |
| **HTTP** | Any HTTP response (incl. 3xx/4xx/5xx) is received | HEAD against the pinned IP, redirects off, proxy off |
| **SSH/SMTP banner** | TCP connects (banner read best-effort) | bounded read; "connected but silent" still passes |

RTT is measured from the TCP-connect handshake (no ICMP, no root). The source IP
and interface are read from the winning connection's `LocalAddr`, with a
UDP-connect fallback (sends no packets) for path identity on failure. Every probe
is IPv4-only and bounded by a 4-second timeout.

## Install

Requires Go 1.26+. **Linux only.**

```sh
go install github.com/mplaczek99/network-doctor@latest
```

Or build from a clone:

```sh
git clone https://github.com/mplaczek99/network-doctor
cd network-doctor
go build -o network-doctor .
```

## Usage

```sh
network-doctor                  # generic local + internet diagnosis
network-doctor github.com       # diagnose the path to a host (→ TLS + HTTP)
network-doctor github.com:22    # port selects the protocol rows (→ SSH banner)
network-doctor https://host:80  # explicit scheme selects the protocol (→ TLS on :80)
```

The target parser has two independent axes: the **port** (explicit `:port` >
scheme default > 443) and the **protocol rows** (an explicit `http`/`https`
scheme wins; otherwise inferred from the port — `443/8443`→TLS+HTTP, `80`→HTTP,
`22`→SSH, `25/587`→SMTP). Hosts are validated against a strict allowlist; IPv6
literals are rejected (IPv4 only).

| Key | Action |
|-----|--------|
| `↑`/`↓` (`k`/`j`) | select a probe row |
| `r` | rerun the chain |
| `e` | export a sanitized markdown report |
| `q` / `Ctrl-C` | quit |

## Drill-down tools

Each row in the diagnosis is *evidence*; when you want proof, run a real tool as
a cancellable streaming job (one at a time). The contextual toolbox shows the
tools available for the current target with their hotkeys — missing binaries are
greyed out with an install hint. Output is bounded, sanitized (no terminal-escape
injection from a hostile server), and a few stable facts are extracted on
completion.

| Key | Tool | Command shape |
|-----|------|---------------|
| `i` | `ip route` | `ip route` |
| `s` | `ss` | `ss -tunp` |
| `p` | `ping` | `ping -c 4 -W 2 <host>` |
| `d` | `dig` | `dig +time=2 +tries=1 <host>` |
| `c` | `curl` | `curl -q -sS --head … -w '…' <url>` (locale-proof facts) |
| `t` | `traceroute` | `traceroute -w 2 -q 1 -m 20 <host>` |
| `m` | `mtr` | `mtr --report --report-cycles 5 <host>` |

`ip` and `ss` are target-independent; the rest need a host. Tools are run with an
argument slice (never a shell string), in their own process group (cancel kills
descendants too), unprivileged — on a permission error you get the command to
re-run with `sudo`, never an auto-escalation.

`--toolbox [<host>]` opens straight into the toolbox without auto-running the
chain (press `r` to run it). With no host, only the target-independent tools are
offered.

### Exit codes

| Situation | Exit |
|---|---|
| Chain completed, no failed row (Skips allowed) | `0` |
| Any failed row | `1` |
| Quit before the chain finished | `1` |
| Bad arguments / validation reject | `2` |

```sh
network-doctor github.com || echo "path to github is broken"
```

## Roadmap

Implemented: native DAG probes + diagnosis engine + two-pane UI (Phase 1),
cancellable streaming tool jobs with `ping`/`dig`/`curl` (Phase 2), and
`traceroute`/`mtr`/`ss`/`ip` + markdown export + `--toolbox` mode (Phase 3).

Still to come: `nmap`, multiple concurrent jobs, a `Warn` state, and an
mtr-parsed route-quality row. See `PLAN.md`.

## Built with

[Bubble Tea](https://github.com/charmbracelet/bubbletea),
[Bubbles](https://github.com/charmbracelet/bubbles), and
[Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Tests

```sh
go test ./...          # unit + DAG scheduler + parser + diagnosis
go test -race ./...    # concurrency
go test -fuzz=FuzzSanitize -fuzztime=10s   # terminal-escape sanitizer
```
