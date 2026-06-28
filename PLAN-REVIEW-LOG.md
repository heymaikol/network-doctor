# Plan Review Log: network-doctor — unify external network tools behind a diagnosis-first TUI
Act 1 (grill) complete — plan locked with the user. MAX_ROUNDS=5.

## Round 1 — Codex
- Sequential skip conflicts with diagnosis rules: a DNS failure skips the independent Internet TCP probe, preventing "DNS-only failure" diagnosis; fix: model explicit dependencies and run Internet TCP independently of DNS.
- Interface, IP, and route probes may pass using different interfaces, producing a fictitious healthy path; fix: identify the route-selected interface/source address and validate one coherent path.
- /proc/net/route ignores policy routing and VRFs, and a default route is unnecessary for an on-link target; fix: determine effective routing for each probe destination via netlink or a UDP-connect source/route lookup.
- Bare-host default-port behavior is undefined, while scheme/explicit-port conflicts such as https://host:80 are ambiguous; fix: define a typed target parser with explicit precedence and table-driven cases.
- Resolving separately in DNS, TCP, TLS, and HTTP probes can test different load-balanced addresses; fix: resolve once per run and pass the selected IP through probes while preserving SNI and HTTP Host.
- 1.1.1.1:443 is a single-provider reachability oracle and will falsely fail on proxy-only or selectively filtered networks; fix: classify it narrowly as direct TCP reachability or probe multiple configurable endpoints.
- "Raw output verbatim" permits external tools or remote servers to inject ANSI/OSC terminal control sequences; fix: sanitize control bytes before display while retaining bounded original bytes only for export.
- Captured stdout/stderr and Bubble Tea messages are unbounded, so ss, hostile HTTP headers, or noisy tools can exhaust memory and freeze the UI; fix: impose per-stream byte/line/message limits and visibly mark truncation.
- ToolOutputMsg lacks stdout/stderr identity, yet ToolResult requires separate streams; fix: add a stream field and make the Bubble Tea update loop the sole owner of bounded buffers.
- Pipe completion ordering is underspecified, allowing cmd.Wait()/done delivery before both readers drain their final output; fix: drain both pipes concurrently, wait for both readers, then emit exactly one terminal job message.
- CommandContext only guarantees termination of the direct process, not descendants; fix: launch jobs in their own process group and terminate the group on cancel or timeout.
- Job-state transitions do not define how user cancel versus deadline versus nonzero exit is classified; fix: centralize terminal-state selection using context cause, wait error, and exit status with exactly-once completion.
- Starting another job, rerunning the chain, closing the pane, and q/ctrl+c behavior conflict with the one-active-job rule; fix: specify a state-dependent key map and reject or explicitly cancel-and-await the old job.
- Facts are untyped strings without target, generation, timestamp, or job identity, so stale reruns can contaminate a new diagnosis; fix: scope typed facts to target and generation and replace facts atomically per completed job.
- The planned curl -vI command does not provide a stable total-time field and parsing depends on locale/version; fix: use curl -q --write-out with a machine-readable format and force LC_ALL=C.
- User curl configuration can alter the supposedly bounded invocation; fix: put -q first and explicitly constrain protocols, redirects, proxy behavior, and output.
- Native HTTP HEAD behavior is undefined for redirects, unsupported HEAD responses, connection reuse, and non-default ports; fix: use a fresh configured transport, disable redirects/reuse, and build requests from the parsed scheme/host/port.
- Toolbox facts can change the diagnosis, but the plan does not define recomputation, conflict precedence, or evidence provenance; fix: define deterministic native-versus-tool evidence precedence and recompute only from current-generation data.
- Exit semantics are missing for Skip, toolbox-only mode, failed jobs, canceled jobs, and early pane closure; fix: publish an explicit exit-code table and test every terminal UI state.
- Export may disclose socket ownership, local addresses, routes, and raw remote output, with no permission or overwrite policy; fix: create reports with mode 0600, require explicit overwrite, and warn or redact sensitive sections.
- The test plan omits the highest-risk behavior: real subprocess cancellation, pipe draining, stale messages, scanner limits, and oversized output; fix: add helper-process integration tests and run them under go test -race.

VERDICT: REVISE

### Claude's response
Accepted nearly all 21 findings; rewrote PLAN.md v2. Notable changes + the few where I took a simpler path:

ACCEPTED as-is:
- Dependency-graph chain (Internet TCP independent of DNS) — replaces linear skip.
- Single resolution per run; chosen IP threaded through TCP/TLS/HTTP; SNI/Host preserved.
- Typed table-driven target parser with explicit precedence (explicit port > scheme default); validation regex.
- ANSI/OSC/control-byte sanitization before render (tools AND remote banners) — new sanitize.go.
- Bounded per-stream byte/line caps + max in-flight messages; byte-capped reader (not bare bufio.Scanner's 64KB line cap) + truncation marker.
- ToolOutputMsg gains {JobID, Generation, Stream}; Update loop sole owner of bounded buffers.
- Drain-both-readers (WaitGroup) → cmd.Wait() → exactly-one terminal message.
- Process group (Setpgid) + kill(-pgid) on cancel/timeout to reap descendants (mtr-packet).
- Centralized terminal-state classification via context.Cause + wait error + exit code, exactly-once.
- State-dependent keymap: new tool while running = cancel-and-await; q/ctrl+c cancels running job first (no orphan).
- Typed generation-scoped Facts (Target/Generation/JobID/At); atomic per-job replace; stale dropped.
- curl facts via LC_ALL=C curl -q -sS -w '<machine format>' --max-redirs 0 --noproxy '*' --proto '=https,http'.
- Native HTTP HEAD: fresh non-reusing transport, redirects off, from parsed scheme/host/port; 405/3xx = responded.
- Explicit exit-code table (0 pass / 1 fail or early quit / 0 toolbox / 2 internal); Skip != failure on its own.
- Export: mode 0600, timestamped (no clobber), sanitized, header warning about local network disclosure.
- Helper-process integration tests under go test -race for cancel/timeout/drain/stale-msg/caps.

ACCEPTED but with a SIMPLER resolution than Codex proposed:
- "Coherent path / policy-routing / VRF": adopted the lightweight UDP-connect source/route lookup (net.Dial udp → LocalAddr) Codex offered as the alternative, instead of full netlink. Reports the kernel-chosen iface/source for the destination; defaultRoute() demoted to supplementary display, not a hard gate for on-link targets.
- "1.1.1.1:443 single oracle": kept a tiny ordered endpoint list (1.1.1.1:443, 8.8.8.8:443, first-wins) labeled honestly as "direct TCP egress"; diagnosis wording acknowledges proxy-only/filtered nets. Not fully configurable in v1 (flag/env deferred).
- "Toolbox facts change diagnosis — define precedence/recompute": removed the feedback path entirely — diagnosis is computed ONLY from current-generation native probe state; tool facts are display-only evidence. Simpler than a native-vs-tool precedence engine and matches the locked layering.

REJECTED: none outright.

## Round 2 — Codex
Most prior findings addressed. Remaining material issues:
- DAG inconsistent: path discovery needs resolved IP yet precedes DNS; Internet TCP shouldn't depend on target route; fix: separate target-path and direct-egress-path nodes, target path depends on DNS.
- IP literals have no defined DNS/dependency behavior; fix: bypass DNS for IPv4 literals, seed resolved-IP directly.
- Explicit schemes semantically ignored (https://host:80 → plaintext, http://host:443 → TLS); fix: explicit scheme selects protocol, port selects only endpoint; infer protocol from port only when no scheme.
- net.IP accepts IPv6 despite out-of-scope; fix: reject literals where To4() is nil.
- UDP route discovery doesn't model TCP policy rules / VRFs; fix: narrow the claim or use TCP-specific/netlink lookup.
- No-argument generic-chain behavior disappeared from the CLI spec; fix: preserve it or define no-target as usage error.
- Banner reads memory-unbounded if server streams without newline; fix: deadline + strict byte-limited reader.
- Native HTTP response headers remotely controlled/large; fix: set conservative MaxResponseHeaderBytes.
- LC_ALL=C can't be an exec arg-slice token; fix: set via cmd.Env, shell-quote only the display string.
- Bounded streaming overflow undefined; blocked reader sends could prevent drain/terminal delivery; fix: bounded nonblocking queue, keep draining/discarding after caps, report dropped output.

VERDICT: REVISE

### Claude's response
Accepted all 9 — targeted edits to PLAN.md v3:
- Split the DAG into a direct-egress path (Interface→egress discovery→Internet TCP, DNS-independent) and a target path (Interface→DNS→target-path discovery→Target TCP→protocol rows); target-path discovery now correctly follows DNS.
- IPv4-literal targets: DNS row = Skip (N/A), resolved-IP seeded directly.
- Target parser now has two independent axes: explicit scheme selects protocol; port selects endpoint; port-inference only when no scheme. https://host:80 → TLS+HTTP on 80; http://host:443 → plaintext on 443.
- Reject IPv6 literals (To4()==nil → error).
- UDP route discovery claim narrowed to ordinary destination-based routing; no VRF/TCP-policy guarantee (netlink = later upgrade).
- Restored no-arg generic local+internet chain in the CLI spec.
- Banner grabs: hard deadline + io.LimitReader (~1KB).
- Native HTTP HEAD: conservative MaxResponseHeaderBytes on the dedicated transport.
- curl: LC_ALL=C via cmd.Env (not argv); display string shell-quoted for humans only.
- Streaming: bounded non-blocking queue; readers keep draining+discarding after caps (dropped-bytes counter shown) so a full queue can't deadlock drain/terminal delivery.

REJECTED: none.

## Round 3 — Codex
Prior findings mostly addressed. Remaining/new:
- Multiple A records resolved once but only one chosen IP tested → false failures; fix: retain all A records, try each for Target TCP, pin first successful IP for protocol probes.
- Egress path discovery targets one endpoint while Internet TCP may succeed against another via a different route; fix: report path per attempted endpoint or use the successful connection's local address.
- Shared Interface/IP row ambiguous when target and egress use different interfaces (VPN split routing); fix: show path-specific source/interface rows.
- Queue ordering doesn't guarantee buffered output reaches Bubble Tea before the terminal message; fix: single FIFO with terminal event enqueued last.
- --toolbox [<host>] permits no host but plan says tools run against the parsed target; fix: define local-tools-only no-target toolbox or require a target.
- curl adapter dropped -I/--head, so it does a GET (large transfer); fix: add --head.
- Skip is prereq-failure but also used for IP-literal DNS N/A; fix: add NotApplicable state.
- "Base" ordering still puts route before DNS despite target route discovery needing the resolved IP; fix: replace linear list with the two-path DAG ordering.

VERDICT: REVISE

### Claude's response
Accepted all 7 — edits to PLAN.md v4:
- Resolution: retain all A records, Target TCP tries each, pins first successful IP for protocol probes.
- Dropped separate egress pre-discovery; egress and target source/iface now derived from the winning connection's LocalAddr.
- Path-specific source/interface rows when egress and target paths differ (VPN split routing).
- Streaming: output + terminal event on one ordered FIFO, terminal enqueued last (no stale-drop of final lines).
- --toolbox with no host = local-tools-only (ip/ss enabled; target-dependent tools greyed until a target is given).
- curl fact invocation restored --head (evidence-only, no large GET).
- Added NotApplicable state (distinct from Skip); IP-literal DNS row = NotApplicable; not counted as failure.
- Removed the stale linear "Base:" ordering; protocol-rows section now references the two-path DAG explicitly.

REJECTED: none.

## Round 4 — Codex
Most round-3 findings addressed. Remaining:
- Bounded nonblocking FIFO can drop its terminal event when full → job stuck running; fix: reserve capacity / guaranteed terminal send after queued output drains.
- Sequential address attempts can consume the whole deadline on the first dead A record/endpoint; fix: staggered parallel dialing or per-address time budgets.
- Path discovery contradictory: some sections use successful TCP LocalAddr, others still specify UDP-connect; fix: TCP LocalAddr on success + per-destination UDP fallback on failure, remove stale alternatives.
- Successful-connection-only path reporting gives no source/interface evidence for failures (where diagnosis needs it most); fix: bounded route/source discovery for failed destinations.
- No-target generic chain still promises an IP/route row though direct-egress path has no separate route node; fix: define the exact generic DAG + row sources.
- File layout still says "tri-state"; fix: Pass/Fail/Skip/NotApplicable.
- Unresolved toolbox open question contradicts the new local-tools-only mode; fix: remove the stale open question.
- Terminal sanitization is security-critical but has no tests; fix: table/fuzz tests for split ANSI/OSC, C0/C1, long sequences, malformed UTF-8.

VERDICT: REVISE

### Claude's response
Accepted all 8 — edits to PLAN.md v5:
- FIFO: terminal event never dropped — reserved slot / guaranteed send after output drains; only output lines are droppable. No more stuck JobRunning.
- Per-destination time budget (~deadline/addr-count) for both target A records and egress endpoints; staggered parallel marked as later optimization.
- Unified path-discovery rule: success → conn.LocalAddr; failure/pre-connect → UDP-connect fallback; one rule for egress + target; removed stale UDP-only phrasing.
- Failed destinations still get path identity via the UDP-connect fallback (evidence where diagnosis needs it most).
- Specified the exact no-target generic DAG (Interface→Internet TCP→DNS to probe host) with row sources; default route = supplementary display, not a node.
- File layout updated to four-state (Pass/Fail/Skip/NotApplicable).
- Removed the stale --toolbox open question (now defined as local-tools-only mode in the CLI section).
- Added security-critical sanitization tests (table+fuzz: split ANSI/OSC/CSI, C0/C1, over-long sequences, malformed UTF-8) and an overflow-keeps-terminal-event integration test.

REJECTED: none.

## Round 5 — Codex (MAX_ROUNDS reached)
Round-4 findings largely addressed. Remaining:
- DAG has no concrete execution/data contract; DNS must publish addresses, Target TCP the pinned IP/source; fix: typed ProbeResult outputs, dependency IDs, Update-owned generation-scoped run state.
- Existing Result schema can't represent multiple attempts/selected IP/source/timings/failure classes without parsing display strings; fix: structured probe evidence + separately rendered detail text.
- No-target chain shows Internet TCP → DNS while calling DNS independent → could skip DNS after egress failure; fix: make DNS and Internet TCP siblings depending only on Interface.
- All-address-fail UDP fallback selection ambiguous across multiple destination routes; fix: bounded per-address attempt record + explicit fallback choice.
- File layout & key decisions still describe UDP-only discovery and "one IP"; fix: update to the final hybrid, multi-address rule.
- Markdown export sanitizes terminal controls but not Markdown/HTML/remote-image injection; fix: escaped code blocks, raw HTML disabled.
- Tests omit the DAG scheduler + multi-address selection; fix: add sibling independence, dependency skips, generation resets, per-address budgeting, pinning, all-address failure.

VERDICT: REVISE

### Claude's response
Accepted all 7 — final edits to PLAN.md:
- Added a "Probe data contract" section: typed ProbeResult (ID, Status, FailClass, Addrs, SelectedIP, Source/Iface, Attempts, RTT, derived Detail/Fix) replacing string-only Result; Update-owned generation-scoped map[ProbeID]ProbeResult; DAG scheduler with declared dependency IDs.
- Fixed the no-target DAG: DNS and Internet TCP are now siblings depending only on Interface (egress failure no longer skips DNS).
- All-address failure: bounded per-address Attempt record; deterministic fallback summary (first address's UDP-connect path), full attempt list in detail pane.
- Reworded Key decision #3, file layout, and phasing to the hybrid TCP-first + multi-address rule (removed "UDP-only"/"one IP").
- Export hardened against Markdown/HTML/remote-image injection: sanitized AND fenced code blocks with raw HTML disabled.
- Added DAG-scheduler + multi-address tests (sibling independence, dependency skips, generation reset, per-address budgeting, IP pinning, all-address failure).

REJECTED: none. Loop terminated at MAX_ROUNDS=5; every round's findings were incorporated. Remaining critiques were incremental spec-detail, not opposing positions — see Resolution.

## Round 6 — Codex (user requested rounds past MAX)
Round-5 findings addressed; new material issues:
- DAG runs nodes only when deps are Pass, so an IP literal's DNS=NotApplicable blocks Target TCP; fix: separate resolution-output node or treat applicable NotApplicable deps as satisfied.
- "Update-owned" run state may be read by probe goroutines while Update writes siblings → map race; fix: pass immutable dependency snapshots into each probe command.
- LocalAddr() gives source IP+port, not interface name; fix: map source IP to interface, represent ambiguous/no-match explicitly.
- Fenced Markdown injectable if attacker output contains the closing fence; standalone report can't enforce raw-HTML-disabled; fix: dynamically longer fences or indent every untrusted line as code.
- Terminal classification has no precedence when a process exits successfully as its context expires; fix: Wait()==nil → Done, consult context.Cause only on Wait error.

VERDICT: REVISE

### Claude's response
Accepted all 5:
- Dependency satisfaction redefined around required OUTPUT, not row status: Pass or applicable-NotApplicable-with-output satisfies dependents; IP-literal DNS=NotApplicable (Addrs/SelectedIP seeded) no longer blocks Target TCP; Fail (no output) → dependents Skip.
- Map race removed: shared map read/written only in Update; each probe's tea.Cmd closure captures an immutable snapshot of just its dependency outputs.
- Path discovery: LocalAddr gives source IP; map IP→iface via Interfaces/InterfaceAddrs; ambiguous and no-match are explicit states.
- Export: switched from ``` fences to 4-space-indented code blocks (no closing delimiter to inject); dropped the unenforceable "raw HTML disabled" claim.
- Terminal classification: Wait()==nil → Done (success wins over a simultaneous deadline); context.Cause consulted only on Wait error.

REJECTED: none.

## Round 7 — Codex
Round-6 findings addressed. One material lifecycle gap:
- Pressing r during an active tool job is undefined; bumping the shared generation can stale-drop its terminal event and leave job state stuck; fix: disable r while a job runs or cancel-and-await it before rerunning, and test the transition.

VERDICT: REVISE

### Claude's response
Accepted. State-dependent keymap now requires cancel-and-await before any state-changing key while a job runs: r cancels-and-awaits the job FIRST, then bumps generation + restarts the chain (never bump generation mid-job); new-tool and q/ctrl+c already covered. Added a keymap-during-job test (r/new-tool/q cancels-and-awaits, no stale terminal event, no stuck JobRunning, no orphan).

REJECTED: none.

## Round 8 — Codex
Stale-generation gap addressed; one concurrency clarification:
- cancel-and-await must not block Bubble Tea's Update (which consumes the terminal event); fix: store a pending action, return immediately, keep consuming job events, execute on the matching terminal event, with defined handling for additional keys while cancellation is pending.

VERDICT: REVISE

### Claude's response
Accepted. Replaced "cancel-and-await" with a non-blocking pending-action model: a state-changing key while a job runs calls cancel() (non-blocking), stores pendingAction, returns immediately; Update keeps consuming events; pendingAction (startTool/rerun/quit) executes on the job's terminal event; generation bumped only when rerun runs (never mid-job); further keys replace pendingAction (last-write-wins), cancel idempotent. Update never blocks → no deadlock.

REJECTED: none.

## Round 9 — Codex
The pending-action model resolves the round-eight deadlock and generation lifecycle issue. No new material flaws found; the plan is sound enough to implement.

VERDICT: APPROVED

---
CONVERGED at round 9. Findings per round: 21, 9, 7, 8, 7, 5, 1, 1, 0. Total 49 raised, 49 incorporated, 0 rejected outright (3 resolved with a simpler path than Codex proposed).
