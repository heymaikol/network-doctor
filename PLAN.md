# Plan: network-doctor — unify external network tools behind a diagnosis-first TUI
_Locked via grill — by Claude + mplaczek. Revised after Codex round 1._

## Goal
Turn network-doctor from a flat in-process check list into a **command center**: a
diagnosis-first TUI whose home screen runs short, native, rootless, protocol-aware
probes ("where does the connection break?"), and whose external tools (ping, mtr,
traceroute, dig, curl, ss, ip) run as **cancellable streaming jobs** on demand for
proof/drill-down. The killer feature is the plain-English diagnosis, not raw tool
output. External tools produce *evidence*; native probes produce the *core
diagnosis*; the diagnosis engine *explains* it. We are not replacing ping/mtr/dig —
we are the layer that knows which one to run, when, and how to read it.

## Approach

### Architecture — three layers
1. **Native probes** (in-process Go, short, app-owned, rootless) — the chain + the
   sole input to the diagnosis. RTT = TCP-connect handshake time (no ICMP, no root,
   no parsing). DNS timing via `net.Resolver`, TLS timing via `tls.Dialer`.
2. **Tool adapters** (external, async streaming jobs) — wrap a CLI, stream output,
   extract a few stable typed `Fact`s after completion, keep bounded raw output.
   **Tool facts are display-only evidence; they never feed back into the home
   diagnosis** (simpler than a native-vs-tool precedence engine — addresses Codex's
   recomputation/provenance concern by removing the feedback path entirely).
3. **Diagnosis engine**: computes the verdict **only from current-generation native
   probe state**. First-fail ordering + combination rules (DNS ok + Internet TCP ok +
   Target TCP fail → "remote port/firewall/VPN").

### Native chain — dependency graph, not a linear skip
Probes form a DAG with **two distinct paths** so independent probes still run when an
unrelated sibling fails (fixes "DNS failure hides that the internet is up"):

- **Direct-egress path** (independent of DNS/target): `Interface up` → `Internet TCP`
  (direct egress, endpoint list, first connect wins). The egress source/interface is
  read from the **winning connection's `LocalAddr`** (not a separate pre-discovery
  against one endpoint — different endpoints can take different routes). Always runs so
  we can report "DNS broken, internet fine."
- **Target path** (needs the resolved IP, so it comes *after* DNS): `Interface up` →
  `DNS lookup` (resolves target) → `Target TCP` → protocol rows. The target
  source/interface is read from the winning Target-TCP connection's `LocalAddr`.

So the target path depends on DNS, and `Internet TCP` never depends on the target's
route — the two earlier-conflated nodes are split, and path identity is derived from the
actual successful connection rather than a pre-probe.

**IP-literal targets bypass DNS.** If the target is an IPv4 literal, the `DNS lookup`
row is `NotApplicable` (literal) and the resolved-IP state is seeded directly.

**Resolution & multiple A records.** For hostname targets, resolve once and **retain
all A records**; `Target TCP` tries each until one connects, then **pins the first
successful IP** for the protocol probes (TLS/HTTP) — a single unreachable CDN IP no
longer causes a false failure. To stop one dead IP eating the whole deadline, each
address gets a **per-destination time budget** within the overall `ctx` deadline
(budget ≈ deadline / addr-count, floored); staggered parallel ("happy eyeballs") dialing
is a later optimization. Same per-endpoint budgeting applies to the egress endpoint list.
SNI = original host; HTTP `Host` = original host.

**Path-specific source rows.** The egress path and target path can use *different*
interfaces (VPN split routing). When they differ, show path-specific source/interface
rows rather than one ambiguous shared row.

### Probe data contract (replaces the string-only `Result`)
The current `Result{Status, Detail, Fix}` can't carry multiple connection attempts, the
selected IP, source/interface, timings, or a failure class without parsing display
strings. Replace it with a structured, typed contract that the diagnosis engine and
renderer consume separately:
```go
type ProbeID string                 // stable node id, e.g. "dns","target_tcp"
type FailClass int                  // None|Timeout|Refused|NoRoute|DNSFail|TLSFail|...
type Attempt struct { IP net.IP; Dur time.Duration; Err error }
type ProbeResult struct {
    ID         ProbeID
    Status     Status                // Pass|Fail|Skip|NotApplicable
    Fail       FailClass
    Addrs      []net.IP              // DNS publishes all A records here
    SelectedIP net.IP               // Target TCP publishes the pinned IP
    Source     net.IP; Iface string // from winning conn LocalAddr / UDP fallback
    Attempts   []Attempt             // bounded per-address record (see below)
    RTT        time.Duration
    Detail     string                // human render text, derived — never parsed back
    Fix        string
}
```
- **Run state is Update-owned + snapshot-passed (no map race):** the
  `map[ProbeID]ProbeResult` for the current generation is read/written **only** inside
  `Update` (single goroutine). A probe's `tea.Cmd` closure captures an **immutable
  snapshot** of just the dependency outputs it needs (e.g. the resolved `Addrs`) — probe
  goroutines never touch the shared map while Update writes sibling results. A new
  generation (rerun) starts an empty map; stale results never leak (existing `generation`
  guard).
- **DAG scheduler — satisfaction is about required output, not row status:** each node
  declares dependency `ProbeID`s; a dep is **satisfied** when its required output is
  present, which is `Pass` **or** an applicable `NotApplicable` that still produced the
  output. So an IP-literal target (`DNS = NotApplicable` but `Addrs`/`SelectedIP` seeded)
  **does not block Target TCP**. A dep that `Fail`ed (no output) makes dependents `Skip`.
  An independent sibling is never blocked by an unrelated failure.
- **All-address failure:** `Attempts` keeps a **bounded** record per A record/endpoint
  (IP, duration, error). When *every* address fails, the summarized fallback path is
  chosen deterministically: the source/iface for the **first** address's UDP-connect
  fallback, with the per-address attempt list available in the detail pane.

**Coherent path (no fictitious healthy path) — single rule.** Path identity (source IP +
interface) for a destination is determined as:
1. **On a successful TCP connect** → read the winning `conn.LocalAddr()` (ground truth).
2. **On failure (or before any connect, incl. failed destinations where the diagnosis
   needs the path most)** → fall back to a UDP "connect" (`net.Dial("udp", dst)` sends no
   packets) and read its `LocalAddr`.
This one rule is used for both the egress path and the target path; there is no separate
pre-discovery node. `LocalAddr()` yields a source **IP** (and port), not an interface
name — map that source IP back to an interface via `net.Interfaces()`/`InterfaceAddrs()`;
represent "ambiguous (IP on multiple ifaces)" and "no match" as explicit states, not a
guessed name. Narrow claim: it models ordinary **destination-based** routing only —
no guarantee under TCP-specific policy rules or VRFs (netlink lookup = later upgrade).
On-link targets need no default route; `/proc/net/route`'s `defaultRoute()` is kept only
as supplementary display ("default route via X"), never a hard gate.

**Internet TCP probe.** Try a small ordered endpoint list (`1.1.1.1:443`,
`8.8.8.8:443`) — first connect wins. Labeled honestly as **"direct TCP egress"**, and
the diagnosis wording acknowledges that proxy-only/filtered networks can fail this while
real (proxied) connectivity works. Endpoints overridable via flag/env later.

Status enum = `Pass / Fail / Skip / NotApplicable` (Warn + mtr route-quality deferred).
`Skip` = a *prerequisite* failed (an independent probe is never Skipped because an
unrelated sibling failed). `NotApplicable` = the probe doesn't apply at all (e.g. DNS on
an IP literal, or a protocol row absent for this port) — distinct from a skipped-due-to-
failure row and not counted as a failure.

### Protocol rows
The chain follows the **two-path DAG** above (egress path: Interface→Internet TCP;
target path: Interface→DNS→Target TCP), not a single linear list. Protocol rows append
to the target path. Protocol selection: explicit scheme wins; otherwise infer from the
effective port:
- `:443 / :8443` → TLS handshake → HTTP HEAD
- `:80` → HTTP HEAD
- `:22` → SSH banner grab (native: connect, read first line)
- `:25 / :587` → SMTP banner grab (native, same shape)
- other → stop at Target TCP ("no protocol-specific check selected")

**Banner grabs** read under a hard deadline **and** a strict byte limit
(`io.LimitReader`, ~1 KB) so a hostile server streaming bytes without a newline can't
exhaust memory. "Connected but silent within the deadline" = Pass-TCP / banner-unknown.

Native **HTTP HEAD**: build the request from the parsed scheme/host/port against the
single resolved IP; a **fresh, non-reusing transport**, redirects disabled, proxy off,
and a conservative `MaxResponseHeaderBytes` (remote headers are attacker-controlled and
potentially large); treat any response (incl. 405 HEAD-not-allowed, 3xx) as "responded".

### Target parser (typed, table-driven, precedence-defined)
```go
type Target struct { Host string; IP net.IP; Port int; Scheme string; Proto Proto; PortExplicit bool; IsLiteral bool }
```
Two **independent** axes (Codex r2 fix — scheme must not be ignored):
- **Endpoint port:** explicit `:port` always wins; else scheme default
  (`https`→443, `http`→80); else bare host → 443.
- **Protocol of the protocol-rows:** an **explicit scheme selects the protocol**
  (`https`→TLS+HTTP, `http`→HTTP) regardless of port; only when there is **no scheme**
  is protocol inferred from the effective port (443/8443→TLS+HTTP, 80→HTTP, 22→SSH
  banner, 25/587→SMTP banner, else stop at Target TCP). So `https://host:80` → TLS+HTTP
  on port 80; `http://host:443` → plaintext HTTP on 443; `host:22` → SSH banner.

**Validate:** host = RFC-1123 hostname or IPv4 literal; **reject IPv6 literals**
(`ip.To4()==nil` → error, IPv6 is out of scope); port 1–65535; strict allowlist regex,
reject everything else. Nothing user-supplied is ever concatenated into a command string.

### Drill-down job model (one active job at a time, v1)
Lifecycle: `JobQueued → JobRunning → JobDone | JobFailed | JobCanceled | JobTimedOut`.
- `exec.CommandContext(ctx, name, args...)` — **arg slice, never a shell string.**
- **Process group:** `SysProcAttr{Setpgid: true}`; on cancel/timeout kill the whole
  group (`Kill(-pgid, SIGKILL)`) so descendants (e.g. `mtr-packet`) die too.
- **Single FIFO, terminal event guaranteed:** output lines and the terminal event travel
  on **one ordered channel** (not separate paths), so buffered final lines can't arrive
  after — and be discarded as stale relative to — the terminal message. Sequence: start
  two reader goroutines (stdout, stderr), `WaitGroup.Wait()` both to EOF, *then*
  `cmd.Wait()`, *then* enqueue **exactly one** terminal event last. Only **output** lines
  are droppable under overflow; the **terminal event is never dropped** — it uses a
  reserved slot / a guaranteed (blocking) send after queued output has drained, so a full
  queue can never leave a job stuck in `JobRunning`.
- **Terminal-state classification (centralized, exactly-once, success-wins):**
  `cmd.Wait() == nil` → **Done** (a process that exited 0 just as its deadline expired is
  not a timeout). Only when `Wait()` returns an error do we consult `context.Cause(ctx)`
  (Canceled vs DeadlineExceeded) + `ExitError.ExitCode()` → Failed/Canceled/TimedOut.
- **Bounded output + non-blocking overflow:** per-stream byte + line caps; use a
  byte-capped reader (not bare `bufio.Scanner`, whose 64 KB line limit errors on long
  lines) — truncate over-long lines and mark `…[truncated]`. Readers push into a
  **bounded non-blocking queue**: once a cap/queue is full the reader **keeps draining
  and discarding** bytes (incrementing a dropped-bytes counter) so it never blocks on
  send — a blocked reader would otherwise stall the child and prevent drain/terminal
  delivery (deadlock). Dropped count is surfaced in the pane. Guards against `ss`,
  hostile headers, noisy tools.
- **Message identity:** `ToolOutputMsg{JobID, Generation, Stream, Line}` carries
  stdout/stderr identity; the Bubble Tea `Update` loop is the **sole owner** of the
  bounded buffers and splits them into `ToolResult.Stdout/Stderr`. Stale-job messages
  (JobID/Generation mismatch) are dropped — mirrors the existing `generation` guard.
- **State-dependent keymap (non-blocking pending-action, never await in `Update`):**
  `Update` must never block waiting for a terminal event — it *is* the goroutine that
  consumes it (blocking = deadlock). Instead: a state-changing key pressed while a job
  runs **calls `cancel()` (non-blocking), stores a `pendingAction`, and returns
  immediately**; `Update` keeps consuming job output/terminal events; when the job's
  **terminal event** arrives, the stored `pendingAction` is executed. Actions:
  - another tool → `pendingAction = startTool(x)`;
  - `r` (rerun chain) → `pendingAction = rerun`; generation is bumped **only** when that
    action runs on the terminal event, never while a job is in flight;
  - `q`/`ctrl+c` → `pendingAction = quit` (`tea.Quit` emitted on the terminal event, so no
    orphan process is left).
  While a cancellation is pending, further state-changing keys **replace** the
  `pendingAction` (last write wins); the cancel is idempotent.
- Bounded command shapes + per-tool context timeout:
  - `ping -c 4 -W 2 <host>`
  - `traceroute -w 2 -q 1 -m 20 <host>`
  - `mtr --report --report-cycles 5 <host>` (report mode; never curses in our TUI)
  - `curl` for facts (arg slice): `curl -q -sS --head -o /dev/null --max-redirs 0
    --noproxy '*' --proto '=https,http' --connect-timeout 3 --max-time 10
    -w '%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n' <url>`.
    `LC_ALL=C` is **not** an argv token — set it via `cmd.Env = append(os.Environ(),
    "LC_ALL=C")`; the displayed `$ command` string shows `LC_ALL=C curl …` (shell-quoted
    for human display only). `-q` first ignores curlrc; `--write-out` = locale-proof facts.
  - `dig +time=2 +tries=1 <host>` / `resolvectl query <host>`
  - `ss -tunp` / `ip route`
  - `nmap -Pn -p <port> --host-timeout 10s <host>` — **deferred to a later phase**
- Job pane: exact `$ command`, elapsed timer, live (sanitized) output, then on
  completion an "Extracted:" facts block above bounded raw output + final status.

### Facts (typed, generation-scoped)
```go
type Confidence int // High | Medium | Low
type Fact struct {
    Key, Value string
    Confidence Confidence
    Source     string    // "dig","curl",...
    Target     string
    Generation int       // run generation this fact belongs to
    JobID      string
    At         time.Time
}
```
Extraction runs only after the command finishes; facts are replaced **atomically per
completed job** and discarded if their `Generation` no longer matches — stale reruns
can't contaminate the current view.

### Terminal-output safety (security)
All bytes that originate from external tools **or remote servers** (banners, `curl -v`,
`dig` of attacker-controlled records) are **sanitized before rendering**: strip C0/C1
control bytes and ANSI/OSC/CSI escape sequences so a malicious banner can't hijack the
terminal. Bounded *sanitized* text is what we keep; export is also sanitized text.

### Privilege model — unprivileged + hint (never sudo in v1)
Prefer root-free flags. On EPERM/"permission denied", show stderr + a copyable hint
("may need root: `sudo mtr ...`"). Never spawn sudo, never prompt for a password,
no `[S]` re-run in v1.

### UI
Two-pane: **Chain** (left, selectable) | **Diagnosis** (right, verdict + evidence).
Contextual bottom toolbox keyed to the selected row. Tool run opens a job pane.
Scrollable output via `bubbles/viewport`; keep `lipgloss`. Missing tools detected via
`exec.LookPath` → greyed out with an install hint.

### CLI / exit codes
`network-doctor` | `<host>` | `<host>:<port>` | `https://<host>` | `--toolbox [<host>]`.

**No argument preserves today's behavior.** Generic DAG (no target path): `Interface up`
is the only prerequisite, and `Internet TCP` (egress endpoint list) + `DNS lookup`
(probe host) are **siblings** that both depend solely on Interface — so an egress failure
never skips DNS, and vice-versa. The IP/source row is taken from the winning egress
connection's `LocalAddr` (or the UDP-connect fallback on failure); the default route is
supplementary display, not a hard node. No target-specific rows. A target adds the target path + protocol rows. `--toolbox <host>`
opens directly in toolbox mode (chain not auto-run), all tools available. `--toolbox`
**with no host** = local-tools-only mode: target-independent tools (`ip`, `ss`) enabled;
target-dependent tools (ping/dig/curl/mtr/traceroute) greyed out until a target is given.

**Exit-code table** (drill-down jobs never affect process exit):
| Situation | Exit |
|---|---|
| Chain completed, no `Fail` row (Skips allowed) | 0 |
| Any `Fail` row | 1 |
| Quit before the chain finished | 1 |
| `--toolbox` mode (no chain run) | 0 |
| Internal error (bad args, validation reject) | 2 |

### File layout (Go, single `main` package)
- `checks.go` → native probes: DAG scheduler + generation-scoped run state, `ProbeResult`
  contract (replaces string-only `Result`), multi-A-record resolution + per-address
  budgeting + IP pinning, hybrid path discovery (TCP `LocalAddr` on success, UDP-connect
  fallback on failure), banner grabs, protocol-aware builder.
- `route_linux.go` → keep `defaultRoute()` (now supplementary display only); ARP
  `gatewayReachable()` retired from the chain (repurpose later as a drill-down or delete).
- `target.go` (new) → typed parser + validation + precedence table.
- `jobs.go` (new) → job manager, `runTool`, reader goroutines, process-group kill,
  terminal-state classification, bounded buffers, messages.
- `tools.go` (new) → adapters, bounded command shapes, `LookPath`, fact extraction.
- `sanitize.go` (new) → control/ANSI-escape stripping for display + export.
- `diagnosis.go` (new) → engine (native state → verdict + evidence).
- `model.go` → rewrite: two-pane + toolbox + job pane; four-state rows
  (`Pass/Fail/Skip/NotApplicable`); viewport; state-dependent keymap; generation/JobID guards.
- `export.go` (new) → markdown report, mode `0600`, timestamped filename (no clobber),
  header warning it contains local network details. Tool/remote output is **double-safe**:
  control/ANSI sanitized **and** emitted as a **4-space-indented code block** (every
  untrusted line indented) rather than a ``` fence — a fence is breakable if the output
  contains its own closing fence, and a standalone `.md` can't enforce "raw HTML
  disabled". Indented code blocks have no closing delimiter to inject and render literally,
  so attacker output can't smuggle Markdown/HTML or remote-image beacons.
- Tests: keep `route_linux_test`; add table tests for target parsing/validation,
  diagnosis engine, fact extraction (fixture stdout). **Sanitization tests
  (security-critical):** table + fuzz cases for split/partial ANSI/OSC/CSI sequences,
  C0/C1 control bytes, over-long escape sequences, and malformed UTF-8 — assert no
  control bytes survive to display. **Highest-risk integration tests** via the
  `os/exec` helper-process pattern, run under `go test -race`: real subprocess
  cancel/timeout, process-group kill, pipe drain ordering, stale-message drop,
  byte/line caps + long-line truncation, and overflow without losing the terminal event.
  **DAG scheduler tests:** sibling independence (egress fails, DNS still runs),
  dependency skips, generation reset clears run state, per-address time budgeting,
  IP pinning on first success, and the all-address-failure fallback selection.
  **Keymap-during-job test:** `r`/new-tool/`q` while a job runs cancels-and-awaits it (no
  stale-dropped terminal event, no stuck `JobRunning`, no orphan process).

### Phasing
- **Phase 1** — native DAG scheduler + `ProbeResult` contract + multi-address resolution
  + hybrid path discovery + diagnosis engine + two-pane UI + exit-code table + target
  parser. No external tools.
- **Phase 2** — job manager (process group, drain ordering, bounds, sanitize) +
  adapters dig, curl, ping + job pane + `-race` integration tests.
- **Phase 3** — traceroute, mtr, ss, ip; markdown export; `--toolbox` mode.
- **Later** — nmap; multi-job list; Warn state + mtr route-quality row.

## Key decisions & tradeoffs
1. **Diagnosis-first, native-only diagnosis.** Verdict computed solely from native
   probes; tool facts are display-only evidence (no feedback path → no precedence engine).
2. **Dependency-graph chain, not linear skip.** Independent probes (esp. Internet TCP)
   run regardless of unrelated failures, so "DNS-only failure" is diagnosable.
3. **Resolve-all + pin-first + hybrid path discovery.** Retain all A records, try each
   (per-address budget), pin the first that connects and thread it through the protocol
   probes; path identity = winning `conn.LocalAddr` on success, UDP-connect fallback on
   failure. Avoids LB drift, single-dead-IP false failures, and fictitious paths.
4. **RTT via TCP-connect timing, not ICMP.** No root, no `ping` dep, no home-screen parsing.
5. **Streaming async jobs, one at a time (v1)**, with process-group kill, drain-before-wait,
   bounded buffers, and a state-dependent keymap.
6. **Parse little, sanitize always, keep bounded raw.** Facts best-effort post-completion;
   all tool/remote bytes sanitized before render to prevent terminal-escape injection.
7. **Unprivileged + hint, never auto-sudo. Arg-slice exec + strict target validation.**

## Risks / open questions
- **Flag portability** across distros: `ping -W` units (iputils seconds vs busybox),
  `traceroute`/`mtr` flag availability. Confirm on Arch; degrade with `LookPath` + hints.
- **Banner grabs:** servers that stay silent until spoken to — treat "connected but
  silent within deadline" as Pass-TCP / banner-unknown, not Fail.
- **UDP-connect path discovery** returns a route even when offline (no packets sent);
  use it for *path identity*, not as a reachability claim — reachability stays TCP-based.
- **Fact extraction fragility** across tool versions; raw (sanitized) output stays authoritative.

## Out of scope (v1)
- nmap; multiple concurrent jobs; jobs list view.
- Warn (`!`) status and mtr-parsed route-quality row.
- IPv6 (chain stays IPv4-only). macOS/Windows (Linux-only).
- Auto-sudo / privilege escalation / in-TUI password prompts.
- Curses/interactive tool modes embedded in our TUI (report mode only).
- Structured dashboards that parse every tool into fixed widgets.
