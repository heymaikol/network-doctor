# Checklist: PID namespace supervisor (contract v6.1, R6 final-2)

Status words:

- RUN HERE: run on the branch in this round, on 2026-11-05, against the Go source as of commit a356a15b. No Go file has changed since then.
- SOURCE-VERIFIED: checked by reading the branch source. Not run.
- NOT PUBLISHED: cited in the contract and held outside this branch. Not evidence for this branch.
- RECORDED: from `out/frame-r6-final2/`, not re-run here.
- PENDING, OPEN, NOT RUN, NOT CLEARED: as the contract states.

Nothing on this list is checked off by this pull request, except where the status says RUN HERE.

## 1. Draft-start gates (contract 17.1)

- [ ] (a) PENDING. Focused changed-lines review of R6 final-2 by reviewers B and C.
- [ ] (b) PENDING. Independent review in contract section 20, scope (i) to (v).
- [x] (c) MET for draft-start readiness only (R6-1). E10 label acceptance does not extend to slice merges.

Draft implementation status: NOT CLEARED until gates (a) and (b) pass. This pull request publishes existing scratch code for review.

## 2. Specification checks (contract section 20, CS1 to CS9)

| ID | Check | Status in this branch |
|---|---|---|
| CS1 | gofmt, go vet, unit suite, stop suite, build | RUN HERE on 2026-11-05: gofmt clean; vet clean (default and integration tags); build pass; integration-tagged suite 43 top-level (41 Test, 2 Fuzz), 52 subtests, 95 PASS, 0 FAIL; default build 6 top-level (4 Test, 2 Fuzz), 35 subtests, 41 PASS, 0 FAIL; stop suite 9 PASS, 0 FAIL; race with CGO_ENABLED=1 and the integration tag: ok, no data race. arm64 compile and vet: RECORDED. arm64 execution: NOT RUN. |
| CS2 | `TestR6FinalUnknownIsFrozen`: green on the candidate, red on the R6 baseline, mutants red | Green: RUN HERE (integration-tagged suite, 5 subtests PASS). Red run and mutants: RECORDED, not re-run here. The red run used a scratch shim that is NOT PUBLISHED. The mutant logs (out/frame-r6-tests/mutation-a-log.txt, mutation-b-log.txt) are NOT PUBLISHED; whether they ran on the candidate source is not verified in this round. |
| CS3 | 47-row matrix, 47 of 47, 0 label differences | RECORDED. Not re-run here. The matrix does not call `commitExit` and is not evidence for CS2. |
| CS4 | Owner notice (0.3) changed from the carried text, identifier removed | Text corrected with a change record in the contract. Status: OPEN, tied to CS9. |
| CS5 | Field scan: no process-identifier label followed by a value, no incident identifier, no host name, no dashes | RUN HERE on the published tree: no incident identifier; no process-identifier label followed by 3 or more digits; no host or user paths; no em or en dashes. Recorded scan: `out/frame-r6-final2/scan.txt`. |
| CS6 | Tier A and E10 rows cite E10-R6 (47 rows) | Contract text. Not re-verified here. |
| CS7 | No advisor call is cited as evidence | Contract text. |
| CS8 | E10 acceptance met for draft-start readiness only. Production T-ADM-FRAMING NOT RUN. | Status as stated. |
| CS9 | D9 owner notice | OPEN. Maintainer action. |

## 3. Production test requirements (contract section 20, CP1 to CP7)

None of these has been run. The scratch harness is not evidence for them.

- [ ] CP1. Slice 5, 5 runs: T-T2-POLL (`TestStopT2ReadinessPoll`). NOT RUN.
- [ ] CP2. Slice 5: T-CL7-RELEASE. Release only after CleanupComplete. A later Close returns the retained sticky error. Pidfd slots are invalid after release, so a later Close sends no signal. NOT RUN.
- [ ] CP3. Slice 5: T-CL6-JOIN. One joint watcher-join deadline of 1 s. A watcher not joined by then is Lost. NOT RUN.
- [ ] CP4. Slice 5: full production cleanup tests T-CL0, T-ZAP-ORDER, T-CLOSE-BOUND, T-CLOSE-LIVE, and T08. NOT RUN.
- [ ] CP5. Slice 6: T-FINAL-COMMIT, the production form of S2. NOT RUN.
- [ ] CP6. Slices 3 to 5: arm64 execution of the production tests. NOT RUN.
- [ ] CP7. Slice 1: production T-ADM-FRAMING and T32. NOT RUN.

Also added in R6 final-2 and not run: TestCloseCommitIsFrozenAtCL0a and TestCloseWatcherJoinSharesOneDeadline (slice 5). Both are named in the contract and do not exist yet.

## 4. Tier A scratch results (contract 12.2 and 17.1)

Scratch PASS from earlier rounds, not re-run in R6 final-2: T-N8, T-CAP-INH, T32, T-PTRACE-GO, T-PTRACE. T-ADM-FRAMING: label-level PASS on E10-R6 (admission framing only). Production form: NOT RUN.

## 5. Slice merge gates (contract 17.2 and 17.3)

Every slice merge gate is NOT RUN. The slice list is in the contract. Slice 0 is decisions only.

| Slice | Scope (short) | Mandatory tests before merge | Status |
|---|---|---|---|
| 0 | Decisions D2, D9, D10, D12, D13 to D18 | None (no code) | NOT RUN |
| 1 | Channel framing, count rule, creds, class a and b records, drain (A40) | Framing rows of T-ADM-FRAMING except init_pidfd_not_sender and producer_not_child; production T32; production T-ADM-FRAMING with the 47-row E10-R6 set; T-DRAIN-UNIT (cases a to k and m to q; case l is in T-T2-POLL); differential parser oracle and seed runs of TestR6IntegerGrammarMatchesRefParse and FuzzParseWireAgreement; arm64 compile of the channel files | NOT RUN |
| 2 | pidfd admission primitives, PIDFD_GET_INFO wrapper, namespace fds | T-A-ADM rootless part, fail-closed tests, T120 | NOT RUN |
| 3 | Namespace launch and init (`launcher_linux.go`, `init_linux.go`, both new) | T-N8, T-CAP-INH, T-PTRACE (with the drift guard), T-PTRACE-GO, T-GETFD, T-HOST-REACH-D, T-SIG-INIT; negative: fork-only path absent (S21). Before the first production merge of slices 3 and 4 together: T-DEATH (5 runs) and T-ORPHAN. | NOT RUN |
| 4 | Launcher hardening, Pdeathsig, removal of base group and PID-number signal paths | T-DEATH (5 runs), T-HOLDER, T-HELPER, T-HOLDER-KILL-GROUP-ABSENT, T-ORPHAN | NOT RUN |
| 5 | Lifecycle: Done, Lost, Stop, Close CL0 to CL7, watcher, mutex, Start(ctx) | T-DONE, T-CL0, T-WATCH (T07), T08, T-CLOSE-BOUND, T-ZAP-ORDER, T-CLOSE-LIVE, T-STOP, T-REENTRY, T-DRAIN-FLOOD, T-CTX, T-NO-BYPASS (slice 5 part), T-T2-POLL, T-CL7-RELEASE, T-CL6-JOIN, TestCloseCommitIsFrozenAtCL0a, TestCloseWatcherJoinSharesOneDeadline | NOT RUN |
| 6 | Admission order, sender credentials, post-admission status | T06b, T-ADM-ORDER, T-A-ADM (userns part), T-ADM-PPID, T-SENDER, T-STATUS-POST, T-DRAIN-STATUS, T-STOP-KNOWN, T-FINAL-COMMIT, T-NO-BYPASS (slice 6 part) | NOT RUN |
| 7 | RLIMIT policy | T-LAUNCH-LIMIT, T-RL-AGG, T-F6b. Blocked by D2 and D12. | NOT RUN |
| 8 | Lease and metadata | T-LEASE, T-HOST-REACH same-uid rows. Cross-uid rows deferred. | NOT RUN |

T117 is listed in contract 12.2 (Tier B) and is NOT RUN. Slices 3 and 4 merge as one change set, because slice 3 starts L without Pdeathsig.

## 6. Repository checks for any production slice

- [ ] `./scripts/check` passes (gate A).
- [ ] `./scripts/check --race` for launcher or channel changes (gate C).
- [ ] Real-socket tests carry the `integration` build tag and stay loopback-only (gate B, AGENTS.md). The harness in this branch does not yet (see README, limitation 3).
- [ ] No em dashes in tracked text (`TestNoEmDashInTrackedTextFiles`).
- [ ] Commit subjects are short and imperative, with no Conventional Commit prefix. No attribution trailers.
- [ ] `CGO_ENABLED=0`. Go 1.27.3 through the module.
- [ ] OS behavior in build-tagged or platform-suffixed files.
- [ ] No process-number signal in any production code (contract 0.2 and section 15 S9).
- [ ] No exported path reaches Running without checks 1 to 10 (T-NO-BYPASS).
- [ ] `--help` keeps standard `fs.PrintDefaults` formatting. Version injection through `-ldflags "-X main.version=..."` is preserved.

## 7. Remaining independent-review scope (contract section 20, not complete)

- [ ] (i) Changed-lines re-review of R6 final-2 by B and C (gate (a)).
- [ ] (ii) The six Tier A gates of 12.2, not re-run in R6 final-2 except the 47-row matrix.
- [ ] (iii) The full Close ladder in 6.4, including the pidfd(L)-missing branch and the required-exit set.
- [ ] (iv) The full STOP list (section 15).
- [ ] (v) The maintainer decisions in section 16 (R6-1 scope, decision 13, R6-5, D2, D9, D12).

## 8. Authorization

No deployment, release, tag, or merge is authorized by this checklist or the pull request.
