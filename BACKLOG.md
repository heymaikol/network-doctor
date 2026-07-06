# Development Backlog

This backlog is ordered by expected value: correctness and testability first,
then diagnostic quality, usability, and maintenance.

## Priority 1 — Correctness and Reliability

1. **Make probes dependency-injectable.** FIXED Replace direct calls to networking and
   operating-system functions with small interfaces or function fields. This
   will allow deterministic testing of dialing, DNS, interfaces, and HTTP
   without real network access. Start in `internal/diagnostic/checks.go`.

2. **Fix cancellation in `pathIdentity`.** FIXED Its UDP fallback uses `net.Dial`
   without the probe context, violating the bounded-probe contract. Use
   `DialContext` and pass the active context through the helper.

3. **Remove real sockets from unit tests.** FIXED Tests in
   `internal/diagnostic/checks_extra_test.go` bind loopback ports, and one test
   dereferences the listener without checking the error. Replace these with
   fake dialers and reserve actual socket tests for an optional integration
   suite.

4. **Refactor CLI parsing into a testable function.** FIXED Introduce a function such
   as `run(args, stdout, stderr) int`, then keep `main` responsible only for
   calling it and exiting. Reject extra positional arguments instead of
   silently ignoring everything after `flag.Arg(0)`.

5. **Add direct probe regression tests.** FIXED Cover cancellation, DNS errors, HTTP
   header limits, TLS failures, banner timeouts, malformed dependency results,
   and the 16-address attempt cap. See
   `internal/diagnostic/checks_probe_test.go`.

## Priority 2 — Diagnostic Quality

6. **Add a `Warn` state.** FIXED Use it for degraded-but-functional conditions such
   as high latency, ambiguous interfaces, direct egress blocked while another
   path works, missing service banners, and partial address failures.

7. **Add proxy-aware diagnosis.** FIXED The native probes deliberately disable
   proxies, which can make a functioning corporate or proxy-only network appear
   offline. Report direct and environment-proxy connectivity separately.
   Implemented as the `Internet (env proxy)` probe: a `CONNECT` tunnel request
   through the `HTTPS_PROXY`/`HTTP_PROXY` proxy (N/A when unset), with
   proxy-aware verdicts and egress downgrading. Env-var proxies only — PAC
   files and SOCKS are not detected.

8. **Add IPv6 and Happy Eyeballs support.** FIXED Targets accept IPv6 literals
   (bare or `[host]:port`), DNS resolves A + AAAA, the egress probe checks each
   family independently in parallel, and dials race interleaved addresses
   Happy-Eyeballs style (RFC 8305: IPv6 first, 250 ms stagger, first success
   wins and cancels the rest). Family-specific failures surface as warnings
   ("IPv6 unreachable, connected via IPv4"). Default-route/gateway garnish and
   nslookup fact extraction remain IPv4-only.

9. **Make drill-down tools protocol-aware.** FIXED Do not offer an HTTPS-oriented
   `curl` command for SSH and SMTP targets. Offer relevant commands such as
   `ssh -v`, `openssl s_client`, or a bounded protocol-specific banner check.
   The `c` slot now switches on the target protocol: SSH targets get a bounded
   `ssh -v` handshake check (BatchMode, throwaway known-hosts file, 3 s connect
   timeout), SMTP targets get `openssl s_client -starttls smtp`, and everything
   else keeps `curl`. The curl fact extractor requires the exact `-w` output
   shape so ssh/s_client output sharing the hotkey never mis-parses.

10. **Parse `mtr` and `pathping` output.** FIXED Produce a route-quality result
    showing packet loss, latency spikes, and the first suspicious hop while
    retaining the raw output as evidence. Both tools share the `m` hotkey, so
    the fact extractor parses `mtr --report` rows (unix) and pathping
    statistics rows (Windows, English-locale only like ping) into common hops
    and emits `dest_loss`, `worst_hop`, `latency_spike` (≥50 ms avg-RTT jump),
    and `suspect_hop`. Suspicion follows mtr-reading rules: intermediate loss
    that clears by the destination is ICMP deprioritization and is ignored; a
    trailing run of silent hops blames the run's first hop; destination loss
    blames the first hop where loss appears. The raw sanitized output remains
    the authoritative evidence.

## Priority 3 — Usability and Automation

11. ~~**Add `--json` or `--no-tui` output.**~~ FIXED: `--json` runs the probe
    DAG headless and prints a stable JSON report (`version`, `target`,
    `checks[]`, `summary`, `ok`); exit codes unchanged.

12. **Make timeouts and egress endpoints configurable.** FIXED Keep safe defaults but
    allow users to replace the four-second probe timeout and public direct-egress
    addresses.

13. **Add sanitized report export.** FIXED Once the checks finish, `y` copies
    the report to the clipboard via OSC 52 and `w` saves it as
    `network-doctor-YYYYMMDD-HHMMSS.txt` (mode 0600) in the working directory,
    with a one-line notice confirming the result. The plain-text report carries
    the target, a PASS/WARN/FAIL verdict with the diagnosis summary, per-probe
    status/detail/fix, source interface, connection attempts, and extracted
    tool facts. No ANSI styling, and every externally-influenced string passes
    `textsafe.Clean`, so the export is safe to paste into tickets. Clipboard
    copy reuses the already-vendored `go-osc52`; tmux/screen passthrough is not
    implemented.

14. **Design multiple concurrent tool jobs.** FIXED (design only — implementation
    not started). Define cancellation, output ownership, resource limits, and UI
    layout before implementing this. Keep the existing single-job behavior as the
    default. Decisions: per-job state moves from the flattened `model` fields
    into a `jobRun` struct (`runs []*jobRun` + focus index); the jobs.go layer
    (per-job channel, JobID+Generation identity, process groups) is already
    N-job safe, so all changes live in the model. Concurrency via `--jobs N`,
    default 1 (exact current semantics, pending/cancel path unchanged), ceiling
    4 because concurrent path probes congest the same route and skew each
    other's measurements. Cancellation: per-job context as today, `x` cancels
    the focused job, quit/rerun cancel the shared generation context, and
    `pendingAction` generalizes to fire when the live-job count reaches 0.
    Same-tool hotkey restarts that job; at the limit new tools queue (reusing
    `JobQueued`), dispatched on any terminal event; the fix flow (`f`) stays
    serialized since a fix mutates system state before the verify rerun. Output
    ownership: Update remains the single writer, done/output messages route by
    JobID lookup, one chained `waitForMsg` per job, and no cross-job
    interleaving ever — tail and viewport render only the focused job; facts
    extract per job, report keyed by toolKey with latest run winning. Limits:
    5000 lines/job, retain the last 8 terminal runs (evict oldest wholesale),
    channel buffer and per-tool timeouts unchanged. UI: a one-line job strip
    (status glyph + hotkey + elapsed) above the focused job's adaptive tail,
    `tab` cycles focus (also inside the viewport), new keys appear in the help
    bar only when more than one job exists, so N=1 renders exactly today's
    pane. Implementation order: extract `jobRun` (pure refactor, tests green) →
    route by JobID + live==0 pending → strip/focus/`tab`/`x` UI → `--jobs`
    flag, queue, retention.

15. **Add `nmap` integration.** FIXED Added as the `[n]` toolbox tool on every
    OS. It is the only tool marked `Confirm`: pressing `n` opens a gate showing
    the exact command and waits for `y` to run it — any other key, including
    esc, cancels without scanning; every other tool still launches on its
    hotkey. Conservative defaults, because a scan can trip the target's
    intrusion detection: `nmap -sT -T2 -Pn --host-timeout 90s`, then `-p <port>`
    when the target port is explicit (that port only) else `--top-ports 100`.
    `-sT` connect scan needs no root, so the shown command is exactly what runs
    at any privilege; `-T2` keeps the probe rate polite; `-Pn` skips redundant
    discovery of an already-reachable target; `--host-timeout` guarantees it
    ends and yields partial results before the 120 s job timeout. Deliberately
    no `-sS`/`-sV`/`-O`/`-A`. The fact extractor emits `open_ports` from the
    output (`open|filtered` and `closed` excluded); the raw sanitized output
    stays authoritative. The `Confirm` gate is a general `Tool` field reusable
    by any future advanced tool.

## Maintenance

16. **Repair the roadmap documentation.** FIXED `README.md` links to a nonexistent
    `PLAN.md`. Either create and maintain that plan or replace the link with this
    backlog.

17. **Pin CI to the module's Go version.** FIXED Change the main CI workflow from
    `go-version: stable` to `go-version-file: go.mod`, matching the release
    workflow and the repository's declared toolchain requirement.

## Current Verification Notes

- `go vet ./...` passes.
- `internal/ui` tests report 84.6% statement coverage.
- `internal/textsafe` tests report 100% statement coverage.
- The selected non-network `internal/diagnostic` tests report 41.5% statement
  coverage.
- The complete suite cannot run in restricted environments that deny loopback
  sockets, because several diagnostic tests currently bind or dial real local
  sockets. Priority 1, item 3 addresses this limitation.
