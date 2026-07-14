# Network Doctor

A terminal UI that diagnoses your network connectivity and tells you **where the
connection breaks** in plain English — not just a wall of tool output.

The home screen runs short, native, rootless probes as a small dependency graph,
then a diagnosis engine turns their combined state into a plain-English verdict
banner — on a failure it also shows the fix and suggests which drill-down tool
to press next. Below it, the left pane is the probe chain and the right pane is
detail for the selected probe.

```
Network Doctor  github.com:443  ·  Wi-Fi: HomeNet

✗ Cannot resolve github.com — DNS failure. (The general internet is reachable.)
  Fix: check /etc/resolv.conf / DNS
  Next: press d — DNS lookup (dig)
  Press f to try a fix (resolvectl flush-caches) — the checks restart to verify.

Checks                        Details — DNS github.com
✓ › Interface                 FAIL — no A records
✓   Internet (TCP egress)
–   Internet (env proxy)
✗   DNS github.com
⊘   TCP github.com:443
⊘   TLS github.com
⊘   HTTP github.com
⊘   HTTPS github.com

Dig deeper: [i] route table · [s] open sockets · [p] ping the host · [d] DNS lookup · …

↑/↓ pick a check · r restart · q quit
```

## How it diagnoses

Probes form a **dependency graph with independent branches**, so an unrelated
failure never hides a working one:

- **Direct-egress path** (independent of DNS): `Interface → Internet (TCP
  egress)`. Always runs, so "DNS is down but the internet is up" is diagnosable.
- **Proxy-egress path** (independent of both): `Interface → Internet (env
  proxy)`. The native probes deliberately bypass proxies, so this row reports
  the environment-configured proxy separately — a proxy-only corporate network
  reads as "online via proxy" instead of offline.
- **Plain HTTP path**: `Interface → DNS → HTTP :80`.
- **Selected target path**: `Interface → DNS → TCP → TLS → HTTPS` for secure
  web targets, or the applicable protocol row for other ports.

Each row is one of five states: **✓ Pass**, **! Warn** (reachable but degraded —
high latency, some addresses failing, ambiguous source interface), **✗ Fail**,
**⊘ Skip** (a prerequisite failed), or **– N/A** (doesn't apply — e.g. DNS on an
IP literal). A Warn never counts as a failure.

| Probe | Passes when | Notes |
|-------|-------------|-------|
| **Interface** | A non-loopback interface is up and running | |
| **Internet (TCP egress)** | A TCP connect to well-known anycast `:443` endpoints succeeds | IPv4 and IPv6 probed independently in parallel; either family passes, both are reported |
| **Internet (env proxy)** | The `HTTPS_PROXY`/`HTTP_PROXY` proxy grants a `CONNECT` tunnel | N/A when no proxy is configured; honors `NO_PROXY` |
| **DNS** | The host resolves to an IPv4 or IPv6 address (system resolution) | IP-literal targets are N/A; all A/AAAA records are retained |
| **TCP** | A TCP connect to the target port succeeds | races A/AAAA records Happy-Eyeballs style (RFC 8305), pins the winner |
| **TLS** | The TLS handshake (SNI + cert verification) succeeds | bad/expired cert, clock skew, or MITM → Fail |
| **HTTP** | Port 80 returns any HTTP response (incl. 3xx/4xx/5xx) | Independent HEAD after DNS, redirects off, proxy off |
| **HTTPS** | The selected TLS port returns any HTTP response | HEAD against the TLS-validated IP, redirects off, proxy off |
| **SSH/SMTP banner** | TCP connects (banner read best-effort) | bounded read; "connected but silent" still passes |

RTT is measured from the TCP-connect handshake (no ICMP, no root). The source IP
and interface are read from the winning connection's `LocalAddr`, with a
UDP-connect fallback (sends no packets) for path identity on failure. Every probe
is bounded by a 4-second timeout.

## Install

Runs on **Linux, macOS, and Windows**.

### Arch Linux (AUR)

The [`network-doctor`](https://aur.archlinux.org/packages/network-doctor)
package builds from source:

```sh
yay -S network-doctor    # or: paru -S network-doctor
```

Or by hand, without an AUR helper:

```sh
git clone https://aur.archlinux.org/network-doctor.git
cd network-doctor
makepkg -si
```

### macOS (Homebrew)

Installing with Homebrew avoids Gatekeeper's "unverified developer" prompt:

```sh
brew tap heymaikol/tap
brew install --cask network-doctor
```

### Everywhere else

Download a prebuilt binary from the [latest release](https://github.com/heymaikol/network-doctor/releases/latest), or install with Go 1.26+:

```sh
go install github.com/heymaikol/network-doctor@latest
```

Check what you're running with `network-doctor --version`.

Or build from a clone:

```sh
git clone https://github.com/heymaikol/network-doctor
cd network-doctor
go build -o network-doctor .
```

## Usage

```sh
network-doctor                  # generic local + internet diagnosis
network-doctor github.com       # diagnose the path to a host (→ HTTP + TLS + HTTPS)
network-doctor github.com:22    # port selects the protocol rows (→ SSH banner)
network-doctor https://host:80  # explicit scheme selects the protocol (→ TLS + HTTPS on :80)
network-doctor --json host      # headless: one JSON report on stdout (scripts, CI, bug reports)
```

`--timeout` overrides the per-check probe timeout; see `network-doctor --help`
for the default.

The target parser has two independent axes: the **port** (explicit `:port` >
scheme default > 443) and the **protocol rows** (an explicit `http`/`https`
scheme wins; otherwise inferred from the port — `443/8443`→HTTP+TLS+HTTPS, `80`→HTTP,
`22`→SSH, `25/587`→SMTP). Hosts are validated against a strict allowlist; IPv6
literals are accepted bare (`::1`) or bracketed with a port (`[::1]:443`).

| Key | Action |
|-----|--------|
| `↑`/`↓` (`k`/`j`) | select a probe row |
| `enter` | open the current tool job's output in a scrollable full-screen viewer |
| `r` | restart — opens a prompt to edit the `network-doctor` arguments (`enter` runs, `esc` backs out) |
| `f` | try an automatic fix for the first failed check, then restart the chain to verify |
| `y` / `w` | yank / write (copy / save) a report of the chain plus the completed tool output |
| `q` | quit |

**Auto-fix** (`f`, experimental): runs a mild, OS-specific remedy through the
same job pipeline as the drill-down tools — flush the DNS cache
(`resolvectl flush-caches` / `dscacheutil -flushcache` / `ipconfig /flushdns`)
for a DNS failure, `nmcli networking on` for a downed interface on Linux. No
sudo, no config rewrites. When the fix job ends, the whole chain restarts
automatically — that restart is the verification, labeled in the banner. Remote
failures (target TCP/TLS/HTTP) have no local fix and offer none. The fix
selection and verify flow are unit-tested; the fix commands themselves haven't
been exercised against real broken networks on every OS yet.

## Drill-down tools

Each row in the diagnosis is *evidence*; when you want proof, run a real tool as
a cancellable streaming job (one at a time). The contextual toolbox shows the
tools available for the current target with their hotkeys — missing binaries are
greyed out with an install hint. Output is bounded and sanitized (no
terminal-escape injection from a hostile server); the last 15 stdout lines are
included in reports after a tool finishes.

The same hotkeys map to each OS's built-in tools:

| Key | Linux | macOS | Windows |
|-----|-------|-------|---------|
| `i` | `ip route` | `netstat -rn` | `route print -4` |
| `s` | `ss -tunp` | `netstat -an -p tcp` | `netstat -ano` |
| `p` | `ping -c 4 -W 2` | `ping -c 4` | `ping -n 4 -w 2000` |
| `d` | `dig +time=2 +tries=1` | `dig +time=2 +tries=1` | `nslookup` |
| `c` | `curl … -w '…'` (concise summary) | same | `curl.exe` (bypasses the PowerShell 5.1 `curl` alias) |
| `c` (SSH target) | `ssh -v -o BatchMode=yes …` (bounded banner/handshake check) | same | same |
| `c` (SMTP target) | `openssl s_client -starttls smtp` | same | same |
| `t` | `traceroute -w 2 -q 1 -m 20` | same | `tracert -w 2000 -h 20` |
| `m` | `mtr --report --report-cycles 5` | same (via brew) | `pathping -h 20 -q 5 -p 100 -w 500` (own 90 s budget) |
| `n` | `nmap -sT -T2 -Pn` (the explicit target port, else top 100) | same | same |

`n` is the one tool that actively scans the target, so it's gated behind an
explicit confirmation showing the exact command before anything runs. It uses
a plain connect scan (no raw sockets, no root) with polite timing and no
version/OS detection — just enough to answer "is the port open?".

The `c` slot is protocol-aware: HTTP(S) and unknown-port targets get `curl`,
while SSH (port 22) and SMTP (ports 25/587) targets get a protocol-appropriate
handshake probe — never an HTTPS-oriented `curl` line. The SSH check uses a
throwaway known-hosts file (no prompts, no writes) and runs a bare `exit` if a
key happens to authenticate.

The routes/sockets tools are target-independent; the rest need a host. Tools are
run with an argument slice (never a shell string), in their own process group on
Unix (cancel kills descendants too), unprivileged — on a permission error you get
the command to re-run with `sudo`, never an auto-escalation. The displayed
command is copy-pasteable in a POSIX shell (Linux/macOS) or PowerShell (Windows;
cmd.exe paste is not supported).

`--toolbox [<host>]` opens straight into the toolbox without auto-running the
chain (press `r` to run it). With no host, only the target-independent tools are
offered.

### JSON output

`--json` runs the same probe DAG headless — no TUI — and prints one JSON
document to stdout:

```json
{
  "version": "1.2.3",
  "target": {"host": "github.com", "port": 443, "protocol": "tls+http"},
  "checks": [
    {"id": "dns", "name": "DNS github.com", "status": "PASS", "detail": "github.com → 140.82.113.3", "addrs": ["140.82.113.3"]}
  ],
  "summary": "All checks passed — github.com:443 looks healthy.",
  "ok": true
}
```

`status` is one of `PASS`, `WARN`, `FAIL`, `SKIP`, `N/A`. `target` is `null`
in generic (no-target) mode. Optional per-check fields (`fix`, `addrs`,
`selected_ip`, `source`, `iface`, `network`, `attempts`) are omitted when
empty. Field names and the status vocabulary are stable — safe to script
against. Exit codes follow the table below (`ok: false` ⇒ exit `1`).

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

## Platform support

All probes, the diagnosis engine, and the TUI are pure Go and identical on
Linux, macOS, and Windows. The platform-specific garnish (default gateway,
Wi-Fi SSID) uses the kernel directly on Linux (`/proc/net/route`, wireless
ioctl) and the OS's built-in commands elsewhere (`route`/`networksetup` on
macOS, `route print`/`netsh wlan` on Windows); when those fail the fields
degrade to empty rather than failing a probe.

**Windows localization caveat**: console tools emit the OEM code page, so
non-ASCII localized text in raw tool output shows as visible `?` replacement
characters, and ping fact extraction (`% loss`, `Average`) works on English
Windows only. Everything load-bearing (route table cells, the untranslated
`SSID` label, nslookup addresses) is parsed locale-independently.

## Roadmap

Implemented: native DAG probes + diagnosis engine + two-pane UI, cancellable
streaming tool jobs (`ping`/`dig`/`curl`/`traceroute`/`mtr`/`ss`/`ip`/`nmap`) +
a scrollable output viewer + `--toolbox` mode, the `Warn` state, proxy-aware
diagnosis, `--json` output, report copy/save, and an experimental `f`
auto-fix-and-verify hotkey.

Still to come: mtr-parsed route quality and multiple concurrent jobs.

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

## Development

The code is split by responsibility:

- `main.go` owns CLI arguments, process I/O, and application startup.
- `internal/diagnostic` owns target parsing, native probes, per-OS route/SSID
  lookups, and verdict logic without depending on terminal presentation.
- `internal/ui` owns Bubble Tea state, rendering, and tool jobs.
- `internal/textsafe` sanitizes untrusted remote and subprocess text shared by
  both layers.

The UI depends on diagnostics; diagnostics do not depend on the UI. Add network
semantics under `internal/diagnostic` and interaction or rendering behavior under
`internal/ui`.
