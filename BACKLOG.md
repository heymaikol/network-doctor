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

9. **Make drill-down tools protocol-aware.** Do not offer an HTTPS-oriented
   `curl` command for SSH and SMTP targets. Offer relevant commands such as
   `ssh -v`, `openssl s_client`, or a bounded protocol-specific banner check.

10. **Parse `mtr` and `pathping` output.** Produce a route-quality result showing
    packet loss, latency spikes, and the first suspicious hop while retaining
    the raw output as evidence.

## Priority 3 — Usability and Automation

11. **Add `--json` or `--no-tui` output.** Provide stable machine-readable
    results for scripts, monitoring, bug reports, and CI.

12. **Make timeouts and egress endpoints configurable.** Keep safe defaults but
    allow users to replace the four-second probe timeout and public direct-egress
    addresses.

13. **Add sanitized report export.** Allow users to copy or save the target,
    verdict, probe results, connection attempts, and extracted tool facts.

14. **Design multiple concurrent tool jobs.** Define cancellation, output
    ownership, resource limits, and UI layout before implementing this. Keep the
    existing single-job behavior as the default.

15. **Add `nmap` integration.** Treat this as an explicitly invoked advanced
    tool, show the exact command before running it, and use conservative scan
    defaults because scans can trigger security controls.

## Maintenance

16. **Repair the roadmap documentation.** FIXED `README.md` links to a nonexistent
    `PLAN.md`. Either create and maintain that plan or replace the link with this
    backlog.

17. **Pin CI to the module's Go version.** Change the main CI workflow from
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
