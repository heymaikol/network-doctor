# PID namespace supervisor: research and prototype (WIP)

Status: work in progress. Draft pull request for review.

This directory holds the design research for running each producer in its own PID namespace. It contains the contract that defines the design (v6.1, revision R6 final-2), a scratch Go harness that exercises the channel, admission, and close rules, and the sanitized run record for that harness.

Nothing here is wired into the supervisor. The harness is a separate Go module (`frame61`) that no package in the repository imports. `go build ./...`, `go test ./...`, and `./scripts/check` at the repository root do not build or run it. The production supervisor under `contrib/frr-correlation/supervisor` is unchanged.

## Contents

| Path | What it is |
|---|---|
| `contract-v6.1.md` | Design contract: topology, admission, channel framing, descriptor ownership, close ladder, test plan, gates, disposition tables. |
| `src/frame61/` | Scratch harness and prototype (Go, module `frame61`, Linux only). Parser, receiver, and drain functions (`parseWire`, `decodeInt`, `decodeStr`, `objectMembers`, `receiveOne`, `drain`, `poisonDrain`). Decision and status rules (`decide`, `decidePost`, `statusGate`). Close-status rule (`commitExit`, `commitDrain`). Unit, stop-suite, and fuzz tests. |
| `out/frame-r6-final2/` | Sanitized run record for R6 final-2: commands, results, label summaries, scan output, and the logs of the runs listed under Tests. |
| `CHECKLIST.md` | Draft-start gates and production merge gates, each with its status. |

## Not published here

- Raw matrix output (it holds kernel process identifiers).
- Host metadata.
- Historical R3 to R5 evidence and diffs.
- Python helper tools, including the scratch chain runner.
- A red-run source copy and its shim.
- Source archives.

The contract cites some of these. Those references point to material outside this branch. They are not evidence for this branch.

## Naming

"Issue 390" is an internal label from the design review. It is not GitHub issue 390, which tracks BGP work. This branch does not close, reference, or change that issue.

## Existing and reusable pieces

Base files the contract's slices extend, at commit `153e7236`:

- `contrib/frr-correlation/supervisor/namespace_linux.go` (holds the base `killGroup` call at line 292 that slice 4 removes).
- `contrib/frr-correlation/supervisor/child_linux.go` (group signals at lines 275, 278, 287 that slice 4 removes).
- `contrib/frr-correlation/supervisor/fds_linux.go` (descriptor helpers).

`launcher_linux.go` and `init_linux.go` do not exist at base. The contract's slices 3 and 4 create them.

Harness pieces that a later production package could reuse after review:

- Channel parser and receiver: `parseWire`, `decodeInt`, `decodeStr`, `objectMembers`, `receiveOne`, `drain`, `poisonDrain`, `recvNB`. They use the record count rule, the bounded receive, and the sticky poison state from the contract (3.2, A40).
- Status rules: `decide`, `decidePost`, `statusGate`, `commitExit`, `commitDrain`. The final ExitStatus is frozen at the first Close (6.1).

These functions live in `package main` of the harness. Moving them into a production package needs a review, GOOS-testable tables, and the seams the contract names.

## Tests

Run on 2026-11-04 in this publication, from the published copy:

```
GOTOOLCHAIN=go1.27.3 GOPROXY=off CGO_ENABLED=0 GOFLAGS=-buildvcs=false
go version go1.27.3 linux/amd64
```

| Step | Result |
|---|---|
| `gofmt -l .` | No output. |
| `go vet .` | No output. |
| `go build -o /dev/null .` | Pass. |
| Unit suite (`go test -count=1 -v .`) | 43 top-level entries (41 `Test` and 2 `Fuzz` functions; the fuzz targets run their seed corpora only). 52 subtests. 95 PASS lines. 0 FAIL. `TestMain` is not a test. |
| Stop suite (`-run '^TestStopRunCase$'`) | 1 top-level entry and 8 subtests. 9 PASS lines. 0 FAIL. |

Recorded in `out/frame-r6-final2/RUN-INFO.txt`, not re-run in this publication:

- 47-row matrix: 47 of 47 pass, 0 label differences against the frozen R6 summary. The matrix does not call `commitExit`, so it is not evidence for the commit rule.
- `TestR6FinalUnknownIsFrozen`: the 5 subtests pass on this candidate. Its red run against the R6 baseline used a scratch shim, which is not published. The two mutants (final store removed, freeze removed) fail as expected.
- Arm64: compile and vet only. Execution not run.

Not run anywhere: `-fuzz` runs, the 150-seed differential oracle, race runs, 32-bit build, and every production test listed in `CHECKLIST.md`.

## Known limitations

1. Not production code. The harness is scratch test code. No slice is merged, and the supervisor does not call it.
2. Linux only. The harness has no non-Linux stubs. Arm64 is compile and vet only. There is no 32-bit build.
3. Real-socket tests. Since commit a356a15b, the socket tests carry the `integration` build tag, as AGENTS.md requires. The default `go test .` runs the six untagged tests only. Production slices must meet the same rule.
4. Process-number signals. The harness calls `Process.Kill()` on its own child processes (`main.go` lines 854 and 1235). That is `exec.Cmd` cleanup, not a process-number signal to a producer. The base supervisor still signals by process number and by process group (`namespace_linux.go` lines 289 to 292, `child_linux.go` lines 275, 278, and 287). Slice 4 removes those paths. The contract forbids a process-number signal in any production code, and this branch adds none.
5. Owner notice D9 is open. The process identifier in the notice is removed from this branch, and the original stays in restricted storage. The notice text changed from the carried wording. The contract's 0.3 change record lists each change.
6. Host residual D11. A producer in the namespace shares the host procfs view. Cross-uid visibility is predicted, not measured.
7. Documentation status. The contract header was corrected in this branch. It states that the branch publishes scratch evidence for review and clears no gate.
8. Reviewer attributions (B, C, D) in the contract were not re-verified in this publication.
9. Kernel tunables from the test host appear in contract text (`kernel.pid_max`, `user.max_user_namespaces`). They are host configuration values, not process identifiers.

## Draft-start gates (contract 17.1)

- (a) PENDING: focused changed-lines review of R6 final-2 by reviewers B and C.
- (b) PENDING: independent review in contract section 20.
- (c) Met for draft-start readiness only (R6-1).

Draft implementation status is NOT CLEARED. This pull request publishes existing scratch code for review. It does not clear gate (a) or (b).

## Production merge gates: NOT RUN

Every production and Tier B test is NOT RUN. The list is in `CHECKLIST.md`. It includes T-CL0, T-ZAP-ORDER, T-CLOSE-BOUND, T-CLOSE-LIVE, T08, T-FINAL-COMMIT, T-T2-POLL, T-CL7-RELEASE, T-CL6-JOIN, arm64 execution, and the slice 1 integration and race gates.

## Authorization

No deployment, release, tag, or merge is authorized by this branch or this pull request.

## Sanitization

- The incident process identifier is not in the current tree. Commits 98c0d511 through 4ea69f82 carry the earlier wording, including the pseudonymous label. The history is not rewritten.
- The working-copy folder name is removed from the contract's S4 wording.
- Historical diffs are not published.
- Host paths, user names, session identifiers, addresses, and credentials were scanned for. None were found. Credential pointers in the logs are replaced with `creds:<pointer>` (see `RUN-INFO.txt`).
- Dash scan (em dash and en dash): none.
