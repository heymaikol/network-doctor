# Contract v6.1: per-producer PID namespace (issue 390)

Status: DESIGN with scratch evidence. Published for review as draft PR #462 (branch research/pidns-supervisor). The branch adds no production code: the frame61 harness is scratch test code that nothing in the repository imports. No merge, tag, release or deployment is authorized.
Base: commit 153e723644a5db0099e7339a3bc5e652073030f7 (contrib/frr-correlation/supervisor and capture). Integration base, verified in the 88ac correction: origin/main and `git ls-remote origin refs/heads/main` (2026-11-04) are both 153e723644a5db0099e7339a3bc5e652073030f7. The local main branch at 6c593708 is 139 commits behind origin/main and is not the integration base.
Supersedes: contract v6 (contract-v6.md). Revision R4 applies the R3 changed-lines corrections (maintainer request 88ac, R4 round) on top of R3. Section 13.11 lists each reviewer B and C finding on R3 and its R4 disposition; section A row A49 lists the R4 text changes. Revision R5 applies one focused correction on R4: the blocking-receive fix (MSG_DONTWAIT and a bounded EINTR retry), the finished reviewer B and C changed-lines findings, and the stress-test findings. Section 13.12 lists each finding and its R5 disposition; section A row A50 lists the R5 text changes; section 16 lists the R5 decisions. Sections 13.9 to 13.11 and section A rows A36 to A49 keep the earlier rounds. Sections not restated here are unchanged from v6. Revision R6 applies one corrective pass on R5 (maintainer request 88ac, R6 round): two reproduced harness bugs (drain classification of descriptor count and flags; a sticky observation error), the contract corrections they expose (integer rule, EOF rule, readiness poll placement, the W3 move, the release rule of CL7, the joint watcher deadline), and a rebuilt bundle. Section 13.13 lists each R6 bug and review item with its R6 disposition; section A row A51 lists the R6 text changes; section 16 lists the R6 decisions. Read section A first.
Start status: T-N8, T-CAP-INH, T32 and the per-thread capability oracle (T-PTRACE-GO, scratch form) have scratch PASS results. T-ADM-FRAMING has kernel-fact PASS and label-level PASS on the R6 build: the 47-row E10-R6 matrix matches the expected labels in every row (E10-R6, out/frame-rerun-r6, one run). The final-2 candidate reproduces the frozen R6 labels with 0 differences (out/frame-r6-final2/label-comparison-r6.txt). The 33-row E10-R4 run and the E10-R5 run are history (12.1). E10 label acceptance is MET for draft-start readiness only (R6-1). E10-R5 measures admission framing only, not the drain path (section 12.1; 18.2 item 18). Production T-ADM-FRAMING is still the slice 1 merge gate. Section 12.2, Tier A.
Implementation status: NOT CLEARED. The draft-start blockers are in section 17.1: gate (a), the B and C changed-lines re-review of R6 final (B and C returned REVISE on R6); gate (b), the independent review in section 20; gate (c) is met for draft-start readiness only (R6-1). Slice 7 is also blocked by D2 and D12. The scratch harness exists (src/frame61, test code only). No production draft has been started.
Evidence archives: the R3 to R6 bundles named in section 0.6 are held outside this branch. They are not evidence for this branch.

---

## A. Changes from v6

Basis codes. Each row names the evidence it rests on.

- E9: out/evidence61_v61.txt lines 3 to 11 (chain table, 9 cases x 5 runs, 45 rows in out/chain/results.normalized.jsonl).
- E9b: out/evidence61_v61.txt lines 13 to 27 (P fd set after exec).
- E11: out/evidence61_v61.txt lines 29 to 39 (sender credentials and ppid across namespaces).
- E10: out/evidence61_v61.txt lines 41 to 66 (frame decision table, 23 of 23) and the record-level flags block from line 68 (frame/results.normalized.jsonl, 23 rows).
- E12: out/gocaps/run1.txt to run5.txt (per-thread CapBnd oracle, go1.27.3, inside a user namespace, 5 runs).
- E13: out/gocaps/plain_shell_negative/run1.txt to run5.txt (same oracle outside a user namespace; drop refused with EPERM).
- RB-P1 to RB-P6: reviewer B probes (review-v6.md section 2). Reviewer evidence, not re-run in v6.1.
- RC-Y1, RC-Y5, RC-Y6: reviewer C results (issue-390-v6-acceptance-review.md sections 4 and 6). Reviewer evidence, not re-run in v6.1.
- DESIGN: design change. No measurement in v6.1.
- RB61-P4 and RB61-P5: reviewer B probes of this round. P4: pidfd_getfd of I's channel fd from P, and readlink of I's fd entry through /proc, with and without the bounding drop (EPERM, EACCES, and the breach control). P5: a record sent by P through a channel fd it holds, with pid(I) credentials (breach control only). Reviewer evidence, not re-run in revision R2, not in the bundle. A sub-probe that read a host PID other than I's is excluded and not cited.
- E10-R2: out/frame-rerun-d15 (bounded rerun of two E10 cases with the D15 labels, this round). Measured in this round.
- E10-R5, E10-R5-REP and the R5 control: out/frame-rerun-r5 (R5 harness, fresh build and supplementary root build; section 12.1). Measured in this round: label, fd and counter evidence only.
- R5 unit and fuzz runs of the frozen frame61 harness: out/frame-r5-tests (section 12.2, Tier A).
- The access rule that governs pidfd_getfd and /proc fd reads is recalled, not read from kernel source (section 4.2).

| # | v6 location | v6.1 change | Basis |
|---|---|---|---|
| A1 | 2.2, channel child end in P | P holds no channel after exec. FD_CLOEXEC is set on the channel child end in I before the fork of P, and P is exec'd. Fork without exec is forbidden. | E9 lines 3 to 5 (P_has_channel 5, 0, 5). E9 line 5: fork without exec leaks the channel 5 of 5. |
| A2 | 2.2, channel child end in I | I keeps its channel child end until the status record is sent or I exits. It is no longer closed after the producer record. The status record needs the channel. | DESIGN. E10 lines 43 and 44 (status from I reaches D as KNOWN). |
| A3 | 3.1, P has no pidfd for I | P can obtain a pidfd for PID 1 with pidfd_open(1). Admission is unaffected, because D takes pidfd(I) only from the channel. T-SIG-INIT (slice 3) covers signals from P. | E9 column P_pidfd1_open_ok: 5 of 5 in every exec variant. |
| A4 | 3.2, control buffer CMSG_SPACE(4) | Control buffer is 64 bytes on amd64: SCM_CREDENTIALS (SO_PASSCRED) plus SCM_RIGHTS for up to 4 fds. Sizes are computed with CmsgSpace in Go, not hard-coded. The v6 size rejects every valid init with CTRUNC. | E10 line 45 (init_one_fd_v6_buf24: CLOSE:ctrunc). E10 line 46 (init_one_fd_buf56: ACCEPT_INIT). |
| A5 | 3.2, fd count guard | The count rule decides. Each message has an exact required fd count. Any other count is rejected, and CTRUNC or TRUNC is also rejected. Without creds, two fds fit in CMSG_SPACE(4) with no CTRUNC (RC-Y2, reviewer measurement, not re-run). So CTRUNC alone is not the guard. | E10 lines 47 to 52: count rejects 2 and 3 fds at 64 bytes (CLOSE:count). CTRUNC: 3 fds at 56 bytes (line 50), 5 fds at 64 bytes (line 52). With creds, 2 fds at 24 bytes also give CTRUNC (line 47). Kernel closes undelivered fds: pipe EOF 2 of 2, 3 of 3, 5 of 5. |
| A6 | 3.2 and 3.4, status with fd | After the producer record, a status with any descriptor is an unexpected descriptor: full Close (D15 class a). Before the producer record it is an admission failure. | E10 line 60 (pipe EOF 1 of 1) recorded UNKNOWN:status_shape under the superseded expectation. Rerun in R2 (E10-R2): UNKNOWN:status_shape observed, CLOSE:status_fd expected, FAIL on label. Rerun in R3 (E10-R3): CLOSE:status_fd observed, PASS on actual classification; fd count 7 before and 7 after; pipe EOF 1 of 1. E10 line 59 (early status: CLOSE:early_status). E10 lines 78 to 81 (CTRUNC and TRUNC flags): CLOSE. |
| A7 | 3.2 and 3.4, control and repeated records after admission (RC-Y8, D15 as the maintainer states it) | After admission, a duplicate producer or an init record is class (a): full Close. A status record is class (b), ExitStatus Unknown and no Close, only when it is malformed, has an unknown kind, has a V other than 1, or repeats a valid status, AND its type field decodes to status (R5: a status candidate has exactly one member named type, matched by exact name after unescape, whose value is the string status), AND its SCM_CREDENTIALS pid is pid(I), AND it has no descriptor, AND it is not truncated. Any other record after admission is class (a), including a record that does not parse and whose type field does not decode to status (R4 decision 8). Before admission, an unexpected record is an admission failure and runs Close. | E10 line 62 (duplicate producer): recorded UNKNOWN:late_record under the superseded expectation. Rerun in R2 (E10-R2): UNKNOWN:late_record observed, CLOSE:late_record expected, FAIL on label. Rerun in R3 (E10-R3): CLOSE:late_record observed, PASS on actual classification. E10 line 63 (repeated status with exact creds): UNKNOWN:after_terminal, action UNKNOWN, as class (b). E10 line 75 (1 descriptor, UNKNOWN x2) matches these two cases by descriptor count and is superseded with them. |
| A8 | 3.2 and 3.3, sender credentials | SO_PASSCRED on the D end, verified by getsockopt readback before any launch (a zero readback is CLOSE:passcred_unverified; E10-R5 row passcred_readback_zero). The SCM_CREDENTIALS pid must equal pid(I) for init, and pid(I) for the producer record (C25, check 10). Missing credentials is a rejection. | E10 line 56 (no passcred: CLOSE:nocreds; the R4 row init_no_passcred is replaced in R5 by passcred_readback_zero). E10 line 54 (pidfd not from the sender: CLOSE:creds_pidfd). E11 columns creds(I)==pid(I) and creds(P)==pid(I): 5 of 5 in ok variants. Cosmetic item of reviewer B (C25 cited). |
| A9 | 3.3, check 4 | Read PIDFD_GET_INFO only after the returned mask has bits 0 and 1 set ((mask and 3) == 3). Offsets: mask at 0, pid at 16, tgid at 20, ppid at 24 (kernel returned mask 0x7). | E11 lines 31 to 33 (mask_I and 3 == 3 and mask_P and 3 == 3, 5 of 5). RC-Y6. |
| A10 | 3.3, namespace comparison method | Comparison is by st_dev and st_ino of the namespace fds returned by the ioctls, for both sides. Fail closed on ENOTTY or EINVAL from any ioctl or PIDFD_GET_INFO. | DESIGN. Comparison method not measured (C16). Gate T-A-ADM. |
| A11 | 3.4 and 6.1, ExitStatus | Known only when exactly one valid status record arrives after admission and no other record arrives on the channel. Unknown when a class (b) record arrives (A7), when a drain overflows or meets an observation error (A40), or when no status arrives. A class (a) record runs Close and leaves ExitStatus Unknown. Replaces "Known only when a valid status arrives". | E10 lines 43 and 44 (KNOWN). E10 line 63 (repeated status: UNKNOWN:after_terminal, class b with exact creds). RB-F2 and RB-C7. Drain rule: DESIGN (A40). |
| A12 | 3.5, exec requirement | P is exec'd. The fd set after exec is stdio plus no channel and no pidfd(I). Fork without exec is a stop condition (S21). | E9 line 4 (exec1: channel 0 of 5). E9 line 5 (exec0: channel 5 of 5, pidfd(I) 5 of 5, CapPrm19 set 5 of 5, attach OK 5 of 5). RC-Y3. |
| A13 | 4.1 R3, refusal | I refuses to start when CapInh or CapAmb is nonzero, or when CapBnd bit 19 is set after the drop. Refusal happens before any init record. | E9 lines 6 to 8 (refused_before_init 5 of 5, P_ran 0, L exit 2). E9 lines 9 to 11 (breach controls with refusal off: P CapPrm19 set, attach OK 5 of 5). RC-Y4. |
| A14 | 4.1 R5, channel and pidfd to P | D never gives P the channel or any pidfd. P can still create its own pidfd for PID 1 (A3). | E9 column P_pidfd1_open_ok. |
| A15 | 4.1 R6, forking thread | Drop, assert, and fork happen on one locked thread. The assertion reads CapBnd of that thread before the fork and refuses if bit 19 is set. Go is the init language (D13). | E12: locked thread after drop and its fork show 000001fffff7ffff. Undropped threads show 000001ffffffffff (5 of 5 runs, go1.27.3). E13: plain shell drop EPERM (control). |
| A16 | 4.2, ptrace matrix | Python chain rows added: attach EPERM with the drop, attach OK in breach controls. Same-user-namespace condition added to the recalled commoncap rule. | E9 column attach: EPERM 5 of 5 in ok variants, OK 5 of 5 in inh, amb and nobnd breach controls. RB-F10, RC-Y11. |
| A17 | 4.3, T-CAP-INH | Scratch PASS. Production gate remains Tier B (slice 3). | E9 lines 6 to 8. |
| A18 | 5.3, P1 | I's own limit does not bound the ancestor count in U0. The ancestor count uses the limit in force when U0 was created. D must not lower RLIMIT_NPROC before it creates H0. P1 (own-level only) remains. Aggregate policy is open (D2, D12) and blocks slice 7. | RC-Y5 (rlimit A/B: before EAGAIN 10 of 10, after OK 10 of 10). E6 in v6 section 5.1. |
| A19 | 6.1, Lost and Reaped | Lost covers any pidfd error other than EINTR, including ENOTTY, EINVAL and ESRCH before exit. Reaped is observed only for D's own children. POLLHUP on a non-child is not Reaped. | DESIGN. RC-Y7 (POLLHUP on I observed in E1 and E2 raw). RB-C18. |
| A20 | 6.2 S1, helper paths | Helpers are opened, verified on the same descriptor (regular file, owner root, no group or world write), and executed by descriptor. Verification and execution use one object. | DESIGN. RB-C19, RB-N15. Gate T-HELPER. |
| A21 | 6.2, Start context | Start takes a context. Cancellation before pidfd(L) exists runs Close. After Running, Close uses fixed deadlines and ignores the context (D17). | DESIGN. RB-N16, RB-C3. |
| A22 | 6.2 S5, Pdeathsig | Pdeathsig SIGKILL is set on L before the exec of nsenter. The creator thread is locked for L's lifetime. The producer gets no Pdeathsig (D5 revised). I dies with L through unshare --kill-child. | RB-P6: one run per mode, through nsenter. L and I dead within 0.1 s of creator death. Gate T-DEATH (slice 4). |
| A23 | 6.3, Stop | Unchanged steps. Stop and Close serialize on one mutex. A Stop that starts after Close returns an error and sends no signal. | DESIGN. RB-F12. |
| A24 | 6.4 CL0, no pidfd(H0) | New step, revised in R4 (decision 5): CL0 does not return at once. It skips CL1 and the H0 wait of CL5, continues CL2 to CL4 on held pidfds, and returns ErrCleanupIncomplete with H0 unobserved. No PID-number signal, no killGroup. | DESIGN. RB-F7, RB-C10. |
| A25 | 6.4 CL2, no pidfd(P) | Producer not held, on every branch (A41): P is listed as Unobserved in the error. Close returns nil only when every member D holds is observed (D14) and no drain overflow was read (A40). | DESIGN. RB-F6, RB-C9. RB-F6: G and P observed no later than I in 45 member comparisons (R-ORD), at millisecond resolution. |
| A26 | 6.4, no pidfd(I) (rejected init) | CL2 does not wait for I. CL3 is skipped. CL4 sends SIGKILL to L through pidfd(L). SIGTERM is never a kill step. | RC-Y1: SIGKILL L ends L, I and P within 3 s, 5 of 5. SIGTERM to L ends none of them within 3 s, 5 of 5. S16. |
| A27 | 6.4 CL7, descriptor retention | One rule (R4 decision 6): on any failure Close releases no descriptor a retry needs, and it retains every valid descriptor and state item needed for retry. Unexpected received descriptors are closed at once. On complete cleanup it releases everything. Complete cleanup means every condition of the nil rule in 6.4 holds, including no drain overflow or observation error recorded at T2 or CL0a (R5). After an overflow or observation error, the R5 reading kept descriptors until process exit. That reading is superseded for CleanupComplete by R6-2 (section 6.4 CL7): descriptors are released on CleanupComplete, and Close still returns the sticky error. Reviewer C R-D1 asked for this release (section 16, R6-2). | DESIGN. RB-F8, RB-C11. |
| A28 | 6.4 CL6 and 6.6, watcher | Watcher waits are poll slices of 100 ms on the pidfd plus a cancel pipe. Join deadline 1 s. Base watch() (waitid on pidfd) is not reused. | DESIGN. RB-N12, RB-C17, RC-Y9. Gate T-WATCH. |
| A29 | 10.1 and 10.4 | Helper paths and descriptor exec as in A20. base release() killGroup and PID-number kill are removed (namespace_linux.go lines 289 to 292). Shape measured: ppid(I) == pid(L), so nsenter does not insert a wrapper for this shape. | E11 column ppid(I)==pid(L): 5 of 5. RB-F11. |
| A30 | 12.1 header note (carried E1 and E2 rows are verbatim v6) | E1 H0 exit: 0.1 to 0.2 ms after its KILL. E2: P and G exit within 1.8 ms of KILL I. P2 was already a zombie before the trigger (0 to 0.1 ms), so it is excluded from the 1.8 ms claim. | RB-N1 and RB-C1, RB-C24 (re-read of the v6 claims; the raw files were not re-run in v6.1). |
| A31 | 14, unverified claims | Removed as verified: pidfd_open(1) from P (E9), sender credential pid (E11), ppid of I in the launch shape (E11). Added: P can signal I with pidfd(1) (T-SIG-INIT), counts of ancestor limits, host-metadata residual. | E9, E11, RB-P4 (sender translation, one run). |
| A32 | 15, STOP conditions | S14 to S20 from reviewer C. New S21 to S23. | Section 15. |
| A33 | 16, decisions | D5 revised (Pdeathsig on L, not on P). New D11 to D17. D11 and D12 carried from reviewer B. | Section 16. |
| A34 | 12.2, gates | Restated with tiers A, B and C. Start blockers are Tier A. Production tests are Tier B and are required before the merge of the slice that adds them. | Section 12.2. |
| A35 | 13, dispositions | Full tables for reviewer B (N1 to N17, ADV-1 to ADV-6, F1 to F12, C1 to C25) and reviewer C (X1 to X5, Y1 to Y12, S14 to S20). | Section 13. |
| A36 | 2.1, 2.2, 3.1, 3.5, 4.1 (R1, R2, R3, R6), S4 | Channel exclusion has two controls. Control 1: FD_CLOEXEC with exec (A1). Control 2: the capability invariants that keep pidfd_getfd, /proc/<I>/fd and attach refused for P. The four rules of control 2 are load-bearing together: R1 drops bit 19 from I's bounding set; R2 keeps it in I's permitted and effective sets, so the permitted-subset rule fails for P; R3 refuses inheritable or ambient bit 19 and a bounding bit 19 after the drop, so P's permitted set lacks bit 19; R6 applies the drop on the forking thread, so P's bounding set lacks it. pidfd_getfd and /proc/<I>/fd are named in 2.1, 3.1 and S4. | RB61-P4 (reviewer B, not re-run, not in bundle). Recalled: the access rule for pidfd_getfd and /proc fd reads (section 4.2). Gate T-GETFD (slice 3). |
| A37 | 2.2, 3.3 check 4 and check 10, 12.2 T-SENDER | A record from L is rejected by check 10: its SCM_CREDENTIALS pid is pid(L), not pid(I). Check 4 is not a sender check. It accepts pidfd(I) from L, because ppid(I) equals pid(L). The earlier text of 2.2 named check 4 as the rejecting check; that was wrong. | DESIGN. Reviewer B SB4. Gate T-SENDER including L (slice 6). |
| A38 | 4.1 R2, 12.2 T-PTRACE drift guard | I's CapPrm and CapEff bit 19 must stay 1. R2 is load-bearing: it is not only a prohibition. T-PTRACE asserts I's CapPrm and CapEff bit 19 are 1, and P's CapBnd and CapPrm bit 19 are 0, in the same run as the attach result. | Reviewer B SB2 and MB8. E9 formula and E9 attach column (existing). Gate T-PTRACE drift guard (slice 3). |
| A39 | 3.2, 3.4, A7, A11, 16 D15, 18.2 | The D15 qualifier is applied the same way in each place: class (b) only with exact creds, no descriptor and no truncation. The "Final form" and "two readings" wording is removed, and the maintainer statement of D15 is recorded as the rule. | Reviewer C reasons 4 and 5, items 11 and 12. Maintainer D15 statement (this round). Text change. |
| A40 | 3.2, 3.4, 6.3 (T2), 6.4 (CL0a) | Bounded, non-blocking drain of the channel parent end at T2 and at Close entry. Every drain receive uses MSG_DONTWAIT (R4 decision 1). A drain accepts at most 8 complete records (R4 decision 2): a ninth record is overflow. Zero-length and truncated records count toward the eight (R5). EINTR returns are capped at 8 per drain (approved in R5); a ninth EINTR return is overflow. EINTR and EAGAIN do not count as records. EAGAIN or EOF ends a clean drain. A drain makes at most 17 recvmsg calls. Any other recvmsg error ends the drain as an observation error (ErrObservation; name confirmation open at 18.2 item 16): no status is accepted from that drain. A readiness poll error other than EINTR, and POLLNVAL, at the T2 readiness wait are observation errors too (CL0a has no readiness wait). Overflow and observation errors give ExitStatus Unknown even if a valid status is among the records read. Records that are truncated, carry an unexpected descriptor, or have bad creds are class (a). Received fds are closed at once, except the required pidfd of an accepted init or producer record, which D keeps. | DESIGN. Reviewer B SB7, MB2, D-B, D-C, D-E and D-G. Tests: T-DRAIN-UNIT (slice 1), T-DRAIN-FLOOD (slice 5), T-DRAIN-STATUS (slice 6). E10-R5 does not exercise the drain (A50). |
| A41 | 6.4 CL0, CL2, CL4, Close nil rule, D14, 7.3 | One Unobserved rule (R5, Option Y, consistent with D14). Unobserved lists each member D started and does not hold a pidfd for: P whenever pidfd(P) is not held; H0, I and L when started and pidfd not held. I counts as started once L is started. A never-started H0 is not listed. This holds with or without pidfd(I), and in the CL2 skip branch. Close never returns nil while Unobserved is not empty. CL4 polls Done(L) with a zero timeout before it signals, so a retry sends no signal to a member already Done. A timed-out wait stays in Lost for the Close call in which it timed out. | DESIGN. Reviewer C reasons 1, 3 and 9 (items 8 and 9); reviewer C R-D3. Option Y is for B and C review (section 16, R5 item 4). Gates T08, T06b and T-CL0. |
| A42 | 6.3 (T2), 6.4 (CL0a) | Stop and Close drain rules (A40). When T2 reads a class (a) record, Stop stops reading, runs Close, and returns ErrProtocolViolation wrapping Close's result; Stop never returns nil in that case. CL0a runs once, on the first Close entry; a later Close call does not repeat it. Once Close is running, a class (a) record found by any read changes no step. | DESIGN. Reviewer B SB7 and the maintainer rule (D15). Gates T-REENTRY and T-DRAIN-FLOOD. |
| A43 | 12.2 (T06b, T07, T08, T-STATUS-POST, T-ZAP-ORDER), 6.6 | Named tests with names, setup, triggers and assertions (section 12.2). Watcher return values Done, Cancelled, Deadline and Error are defined in 6.6. T-ZAP-ORDER obtains pidfd(G) and pidfd(P) through a test-only socketpair, separate from the production channel: P opens pidfd(G) on its own child and sends it out with SCM_RIGHTS. D cannot pidfd_open G by pid inside N, and /proc lookups are prohibited. | Reviewer C reasons 1, 2, 6 and 7; items 8, 10 and 14. Text change. |
| A44 | 17.1, 17.2, 17.3 | Slice ordering corrected. Slice 1 framing uses an injected identity interface and never calls PIDFD_GET_INFO; the two rows that need real identity (init_pidfd_not_sender, producer_not_child) move to slice 6. The launch of L through nsenter and unshare moves to slice 3. Pdeathsig, helper verification and the base removals stay in slice 4. Status-dependent tests move to slice 6. T120 moves to slice 2. | Reviewer C reasons 6 and 7; items 13 and 15. Text change. |
| A45 | 12.1, 12.2 Tier A, 18.1, 18.2, bundle | E10 expectations for status_with_fd_after_producer and duplicate_producer changed to CLOSE:status_fd and CLOSE:late_record (D15). Bounded rerun of these two cases: both FAIL on the label; fd counts and pipe EOF unchanged. Tier A wording narrowed to 21 of 23 at the action level. Harness change: FRAME61_CASES filter, off by default. decide() is unchanged in R2 (R3 changes it; A48). | out/frame-rerun-d15 (E10-R2). Reviewer C reasons and item 16. Measured for the two cases only; the other 21 cases were not rerun in this round. |
| A46 | 13.9, 13.10 | Disposition tables for reviewer B SB1 to SB7 and MB1 to MB15, and reviewer C reasons 1 to 7, items 8 to 16 and two correction items. | Sections 13.9 and 13.10. |
| A47 | 18.1 item 5; bundle src/tools/bundle61.py; bundle out/chain/results.normalized.jsonl | The bundle normalizer mapped only keys whose name contains `pid`, so 60 host `tgid` values (thread-group ids at or above 65536) stayed raw in the chain normalized file. R2 adds `tgid` to the rule, regenerates the chain file from the same raw results, and leaves the frame file byte-identical. Earlier archive copies held by reviewer sessions still contain the raw values; they are not edited. | Found in R2 by a key walk over the normalized rows, after 18.1 item 5 claimed PASS. Bundle change, no protocol change. |
| A48 | 3.4, 6.4, 12.2, 13.8, 13.9, 13.10, 16, 17.1, 17.2, 17.3, 18.1, 18.2; bundle src/frame61/main.go, README, out/frame-rerun-r3 | Revision R3 (request 88ac). (1) decidePost in src/frame61/main.go: a status record with a descriptor after the producer returns CLOSE:status_fd, and a repeated producer record returns CLOSE:late_record (D15 class a). A record that does not parse is a status candidate: UNKNOWN:malformed (class b) only with creds pid(I), no descriptor and no truncation; otherwise class (a). Records after a valid status now pass the same gates: a non-status record, or a record with a descriptor, truncation or foreign creds, returns CLOSE. Before R3 these returned UNKNOWN:after_terminal. No harness row exercises either change. (2) Bounded rerun of the two cases only: status_with_fd_after_producer PASS (actual ACCEPT_INIT, ACCEPT_PRODUCER, CLOSE:status_fd; pipe EOF 1 of 1; fd 7 to 7); duplicate_producer PASS (actual ACCEPT_INIT, ACCEPT_PRODUCER, CLOSE:late_record; fd 7 to 7). (3) Testable full bounded cleanup: 6.4 paragraph and T-CLOSE-BOUND (12.2, slice 5). (4) Duplicate T120 removed from 17.3. (5) 13.10 reason 6 restated to the corrected slice sequence. (6) O-CL0 reviewed: semantics unchanged; recommendation in 18.2 item 9. (7) 17.1 no longer implies independent review. (8) Check 1 stays PARTIAL. (9) Identity audit of the normalized rows (pid, ppid, tgid, creds_pid, NSpid, L_pid, chan_ino, Uid): values under pid keys are 0, 1 and 2 (namespace-local; I is pid 1, P is pid 2) or normalized pid#N. A host pid below 65536 would pass the normalizer unmapped; none appears. Reviewer B and C scratch copies still hold 60 raw tgid values each; they are not edited and need replacement. (10) Overflow reported as a protocol violation (3.4; 18.2 item 13). (11) R3 approvals recorded in section 16. (12) Correction-pass edits to the R3 text applied before the final rebuild. A42 (class a: Close runs, then ErrProtocolViolation) and 3.4 (overflow: no Close) differ by scope; they do not conflict. | Maintainer request 88ac. No production code, PR, merge, release or deployment. No B or C signoff. |
| A49 | 3.2 (Receive, class a and b, drain), 3.3 check 10, 3.4 rows 344, 347 to 350 and the rules, 6.3 T2 and T3, 6.4 CL0, CL0a, CL5, CL7, nil rules and worst case, 6.6, 12.2 (T-CL0 new; T07, T08, T06b, T-ZAP-ORDER, T-ADM-FRAMING, T-STATUS-POST, T-DRAIN-UNIT, T-DRAIN-STATUS, T-DRAIN-FLOOD, T-CLOSE-BOUND, T-SENDER), 13.11, 0.6, 15 (S26, S27), 16 (D15 and the R4 block), 17.1, 17.2, 17.4, 18.1, 18.2 items 8 to 15, 19 | Revision R4 (maintainer request 88ac, R4 round; section 16 R4 block). (1) Non-blocking drain: every receive on the channel parent end uses MSG_DONTWAIT (decision 1; E15). (2) Drain counts records: 8 accepted, ninth overflow; EINTR capped at 8 with a ninth EINTR as overflow (value proposed, maintainer sets it); EAGAIN or EOF ends a clean drain; at most 17 recvmsg calls per drain (decision 2; R3-1, R3-2, D1). (3) Stop overflow at T2: T3 runs, then ErrProtocolViolation joined with any Lost; never nil (decision 3; R3-3, D2). (4) Close overflow at CL0a: safe cleanup continues; ErrProtocolViolation, joined with ErrCleanupIncomplete when cleanup cannot be proven; never nil (decision 4; R3-4, D3). (5) Missing pidfd(H0): CL0 does not return; CL2 to CL4 run on held pidfds; ErrCleanupIncomplete; no PID-number or group signal (decision 5; R3-5, D4). (6) Retention: every valid descriptor and state item needed for retry is retained on incomplete cleanup; unexpected received descriptors are closed at once; release only after proven complete cleanup (decision 6; D5). (7) C16 stays namespace identity; sender-credential verification is C25 (decision 7; R3-7, D6). (8) Post-status classification: class (b) only for a record whose type field decodes to status, with exact creds, no descriptor and no truncation; all other records are class (a); an unparseable record that does not identify a status is class (a) (decision 8; R3-8, D7; the R3-8 row (f) expectation is superseded). (9) T-CL0 added; T-ZAP-ORDER built through a test-only constructor; merge gates and run counts on T07, T08, T-DRAIN-UNIT, T-DRAIN-FLOOD, T-DRAIN-STATUS, T-CLOSE-BOUND and T-CL0 (decisions 9 and 10; R3-6, R3-9, D8, D9). (10) T06b asserts descriptor retention; T-STATUS-POST rows (g) to (l) and the aggregate assertion; watcher cancellation defined for T07 (6.6). (11) Slices 3 and 4: prerequisite and merge rule (decision 11; D11). (12) Evidence: the old E10 labels for rows 60 and 62 are marked superseded; E10-R4 (33 rows) on the R4 build; E15 drain probe; the R3 full-suite runs are reviewer evidence, not author-bundle evidence (decision 12; R3-10, D10). (13) Start gate (c) replaced by the recorded maintainer acceptance; the duplicated sentence is removed (decision 13; 17.1). Still open for the maintainer: the EINTR attempt budget value (proposed 8) and the run counts (proposed in 12.2). | R4 changes are text and harness only. No production code, commit, PR, merge, tag, release or deployment. No B or C signoff until the R4 changed lines are reviewed. |
| A50 | 0.6, 3.2, 3.3, 3.4, 6.1, 6.3, 6.4, 7.3, 12.1, 12.2, 13.12, 14, 15, 16, 17.1, 17.2, 17.4, 18.1, 18.2, 19, 20 | Revision R5 (one focused correction on R4; no new contract version family). (1) Blocking receive removed. Every receive on the channel parent end uses MSG_DONTWAIT. Admission is a poll with the admission deadline, then a non-blocking receive. EAGAIN after a readable poll polls again. Admission allows at most 17 recvmsg calls, EAGAIN included, and at most 8 EINTR returns from recvmsg (approved); the ninth is a rejection (CLOSE:budget). Poll EINTR is retried only inside the deadline and does not count. No change disables Go preemption. (2) Strict grammar and the EOF rule (3.2): valid UTF-8, one JSON object, duplicate member names after unescape rejected, allowed names only, null rejected, integers only; v must be an integer, and its value is checked as shape (class b), not grammar. EOF is a zero-byte result with SCM_CREDENTIALS present, no ancillary data, and neither MSG_TRUNC nor MSG_CTRUNC. Any other zero-length result is a record. (3) Status candidate (3.2): exactly one member named type whose value is the string status, matched by exact name after unescape, computed before the duplicate-name check; truncated or invalid-UTF-8 payloads are not candidates, and a case variant such as TYPE is not a candidate. Class (b) also covers a candidate with V not 1. (4) Observation error (ErrObservation; name confirmation open at 18.2 item 16): a drain receive error other than EAGAIN, EINTR or EOF, a readiness poll error other than EINTR, and POLLNVAL. It never accepts a status and never lets Stop or Close return nil (S28). (5) Unobserved follows Option Y (A41). (6) CL7: complete cleanup is every nil condition of 6.4. After an overflow or observation error, descriptors are retained until process exit (R5 reading; reviewer C R-D1 asks otherwise; section 16, R5 item 5). (7) Admission rows: the R4 row init_no_passcred is replaced by passcred_readback_zero; 15 rows are new (section 12.2, T-ADM-FRAMING). Escaped names are covered by TestParseWireEscapedNames and escaped seeds in FuzzParseWireAgreement; the E10 row init_escaped_type_name has a plain payload and is misnamed (disclosed, not renamed). (8) CALL_BOUND is unreachable while the record and EINTR caps hold; production maps it to overflow when written (proposed). (9) E10-R5 measures admission framing only. Drain, overflow, observation error, V not 1 and recvmsg EINTR exhaustion are covered by the seam and fuzz tests only. (10) Slices 3 and 4 land as one change set (17.2). (11) Findings: section 13.12. | Evidence: E10-R5 and E10-R5-REP (section 12.1); seam, unit and fuzz runs on the frozen harness (section 12.2 Tier A, section 18.1). Reviewer B and C changed-lines review of R5 is pending (17.1 gate (a)). |
| A51 | 0.4, 0.6, 3.2, 3.4, 6.1, 6.3, 6.4, 6.6, 7.3, 12.1, 12.2, 13.12, 13.13, 16, 17.1, 17.2, 17.4, 18.1, 18.2, 19, 20 | Revision R6 (corrective pass on R5; no new contract version family; maintainer request 88ac, R6 round). (1) Drain classification (bug 1): the drain erased the descriptor count and the MSG_TRUNC and MSG_CTRUNC flags before classification, so T2 could accept a status that carried a descriptor, or a truncated status, as Known. The drain keeps them through classification, and T2 and the post-admission decision (decidePost) share one status gate (3.4, 6.3). (2) Sticky observation error and overflow (bug 2): an observation error followed by a valid status restored Known. The drain state is now poisoned at the first observation error or overflow. A later drain on the handle returns POISONED with zero recvmsg calls, and the decision is UNKNOWN:observed (3.4, 6.1, 6.3, 6.4 CL0a). (3) Integer rule (3.2): an integer must fit the Go int of the build target, and -0 is rejected. (4) EOF rule (3.2): EOF is a zero-byte receive with verified SO_PASSCRED, no ancillary data and neither TRUNC flag; without verified credentials every zero-length receive is a record (A8). The R5 wording mixed credential presence with ancillary data; R6 states the same rule with the verified-readback condition. (5) Readiness poll (3.2, 6.3): the T2 readiness wait is the only poll in the drain path; POLLNVAL and a poll error other than EINTR are observation errors there. (6) W3 move (6.4 CL2 and CL4b): the P wait runs after CL4 in every branch, and the I wait runs only when pidfd(I) is held. R5 waited on P only inside the held-I branch, so a held pidfd(P) with pidfd(I) not held was never waited on. (7) Release (6.4 CL7, A27): descriptors are released on CleanupComplete even when a protocol or observation error is recorded; Close still returns that error and never returns nil. This is the R6-2 maintainer decision and it accepts reviewer C R-D1. (8) Join (6.6, CL6): one 1 s deadline covers all watchers together, not one per watcher. The worst case stays at 26 s. (9) ErrObservation is a separate sentinel (R6-3). (10) Incident record: 18.2 item 24, counts only. (11) Harness: src/frame61 is the R6 source. Evidence: section 12.1 (E10-R6), section 12.2 Tier A (R6 row), section 18.1 (R6 results). Not run: production T-DRAIN-UNIT, production T-ADM-FRAMING, T-T2-POLL, T-CL0, T08 subcase (c), the W3 and W6 cases of T-CLOSE-BOUND, and the differential oracle. | Evidence: out/frame-r6-tests (unit, red, mutation and fuzz logs); out/frame-rerun-r6 (matrix labels and the comparison with E10-R5). Reviewer B and C changed-lines review of R6 is pending (17.1 gate (a)). |
| A52 | 3.2, 3.4, 6.1, 6.3, 6.4, 12.2, 13.13, 16, 17.1, 17.2, 18.1, 18.2, 19, 20 | Revision R6 final correction (maintainer request 88ac, final round; B and C returned REVISE on R6; no new contract version family). (1) One commit rule, commitExit, for T2 and CL0a; CL0a is the commit point of the first Close; UNKNOWN is sticky; a poisoned handle is never KNOWN (6.1, 6.3, 6.4). (2) CL0 continues through CL4b and CL5 to CL7; pidfd(L)-missing branch across CL3, CL4 and CL5; required-exit set H0, L, I, P; G excluded by design; T08 and T-CL0 defined (6.4, 12.2). (3) CALL_BOUND normative: ErrObservation at the receive-call ceiling without a conclusive result; ninth record and ninth EINTR stay ErrProtocolViolation (3.4, 6.3, 13.13, 16, 18.2). (4) R6-1 MET for draft-start readiness only; the 47-row E10-R6 matrix replaces the 33-row reference; differential parser oracle named as a slice 1 gate (16, 17.1, 17.2, 18.2 item 8). (5) Architecture-neutral poll and recvmsg for Linux amd64 and arm64; R6 scratch execution is amd64 only; arm64 compile and vet; no 386 obligations (3.2, 17.2, 18.2 item 30, 19). (6) T-T2-POLL named TestStopT2ReadinessPoll with a readiness-timeout case; one joint 1 s watcher join; slice 5 and 6 lists aligned with 12.2; A27 superseded wording (A27, 6.6, 12.2, 17.2). (7) Incident disclosure: 0.3 and 18.2 item 24 consistent; text-scan counts separated from other-session counts and from unverified claims; no reviewer attribution without evidence; D9 OPEN (18.2 item 24). (8) Section 20 lists the remaining independent-review scope and is not marked complete (20). (9) Budgets are per receive and per drain: the receive-call ceiling restarts at each receive (receiveOne); the drain ceiling spans one drain (records, EINTR returns and the terminal call); EAGAIN ends a drain without repoll (3.4, 6.3; TestR6BudgetPerReceiveRestarts, TestR6BudgetDrainEndsOnFirstEAGAIN, TestDrainCallCeiling). (10) runCase treats CLOSE as terminal: no later step is launched, no later receive is made and no later record is decided; the observation-error stop is unchanged (harness only; TestR6CloseIsTerminalInRunCase and D's stop suite). | Evidence: out/frame-r6-frozen (frozen source H; deterministic suite, D's stop suite, budget and CLOSE tests, mutants, arm64 compile and vet, 47-row matrix); out/frame-r6-tests (pre-round-2 unit, call-ceiling and commit logs, mutation logs, red logs on the pre-correction snapshot); out/frame-rerun-r6 (47 rows; label comparison with E10-R5). Not run: production T-DRAIN-UNIT, T-T2-POLL, T-ADM-FRAMING, T32, the slice 1 integration and race gates, T08 subcases, T-CL0, T-CLOSE-BOUND W3 and W6, the generated differential oracle, and any -fuzz run in this round. |
| A53 | title, 0.2, 0.3, 0.4, 0.6, A, 6.1, 6.3, 6.4, 12.2, 13.1, 13.2, 13.9, 13.12, 13.13, 15, 16, 17.1, 17.2, 17.3, 18, 18.1, 18.2, 19, 20 (changed sections, by comparison with the R6 contract; 12.1 has no change) | Revision R6 final-2 (maintainer request 88ac, final corrective pass on R6 final; no new contract version family). (1) commitExit takes a final flag; at CL0a the value is stored and frozen (6.1, 6.4). TestR6FinalUnknownIsFrozen added to the scratch harness: red on R6 for two subtests (the red run used a scratch shim, not in the bundle), green on the candidate, two mutants red. (2) Tier A and E10 status rows cite E10-R6 (47 rows), label level only. (3) Unobserved is a set; L is listed only when started and unproven; CL0a has no readiness wait; the PID-signal prohibition is scoped to the production supervisor lifecycle; the base code keeps the number-based path until slice 4. (4) The owner notice changes beyond the process identifier (0.3 change record). The process identifier is removed; the original is in restricted storage outside the bundle; the reviewer-conduct sentence and the advisor row are removed; item (24) is text-match counts only; D9 OPEN. (5) E10 label acceptance is MET for draft-start readiness only (R6-1). (6) Section 20 is a completion checklist that separates specification-readiness checks from production test requirements. (7) 88ac correction after B's final2b review, in a scratch copy, not published: see 13.13 row 'R6 final-2 correction'. No production change. | out/frame-r6-final2/RUN-INFO.txt (source H2 6bf96406d39fe730239c4646e1f811300befa15f89537b604f8e9ed831a5246d; 43 top-level entries (41 Test and 2 Fuzz functions; TestMain is not a test), 52 subtests, 95 PASS lines, 0 FAIL (the RUN-INFO wording '43 top-level tests' means these 43 entries); stop suite 9 PASS; matrix 47 of 47, 0 label differences) |

---

## 0. Scope, status and notices

### 0.1 Scope

Each producer runs in its own PID namespace, joined to the existing per-producer user and network holder. This contract
defines the process topology, admission of the namespace init, descriptor ownership, capability and RLIMIT policy,
teardown, the channel, the launch sequence and the capture lease interaction. It does not claim mount isolation,
authenticated evidence, or closure of the peer-write known gap.

Host metadata residual (D11): a producer in N shares the procfs view of the host. Scratch P3 (reviewer B) showed that a
same-uid victim's cmdline, status and fd listing are readable from N, and that environ, mem, cwd and ns/pid are refused.
Cross-uid visibility is predicted, not measured. This residual is stated, not removed.

### 0.2 Prohibitions in force

- No repository writes, commits, pushes, merges, tags, releases or deployments.
- In the production supervisor lifecycle that v6.1 changes: no signal by PID number. No kill(-pgid). No pkill or pgrep. No matching on command line or comm. The scratch test tools are not that lifecycle (0.3). The base code at 153e7236 still has number-based paths; slice 4 removes them (17.2). This scope does not permit a PID-number signal in any production code.
- No /proc scan to find processes. /proc is not used as a production decision oracle.
- Test-only experiments run in controlled scratch processes. They do not probe unrelated host processes.
- No unbounded fork loops. Every test fork loop has a fixed bound.
- No attribution trailers on commits (AGENTS.md).

### 0.3 Owner notice (restricted record; carried forward from contract v5 and v6; changed as the change record below states)

3. **Owner notice.** During an earlier probe cleanup, a signal went to a process recorded in the restricted record. The process identifier is held in restricted storage outside this bundle and this branch. That process was `supervisor.test -test.run=TestScratchE3`, a Go test binary, not a probe process. Its owner is unknown. It needs to be reported to its owner. The base code still has the number-based path; slice 4 removes it (17.2). The scratch test tools are not the production lifecycle: src/flat61/chain61.py keeps a PID-number fallback (Popen.kill, line 385) that runs only after a pidfd SIGKILL and a 5 s wait both fail. Whether that fallback ran in any recorded run is not recorded here.

Status of this notice: OPEN. Owner unknown. Not resolved by this design. No host-process probing was done to find the owner in
this round. The wording changes in the change record below have not been checked against the carried text by anyone outside this branch. Before any D9 action, the maintainer confirms in writing which text is to be sent.
Maintainer action: decision D9.

Change record (88ac, R6 final-2). The carried R6 notice text is held in restricted storage outside this bundle. The notice changes from it as follows. (1) The process identifier is removed; the identifier is not printed in the bundle. Commits 98c0d511 through 4ea69f82 on research/pidns-supervisor contain the earlier wording, including the pseudonymous label. The branch history is not rewritten; the current tree does not contain the label. (2) The heading changed. (3) Item 3 changed: it gains the restricted-storage sentence and the base-code sentence, and its carried claims about the signal path are replaced as item (4) states. (4) Two carried historical claims are replaced: that the number-based signal path was removed, and that the current harness signals only through pidfds. Neither claim was verified in this round. Verified in this round: origin/main at 153e7236 still has the number-based path (contrib/frr-correlation/supervisor/namespace_linux.go, line 292, killGroup); src/flat61/chain61.py keeps a PID-number fallback (line 385), which runs only after a pidfd SIGKILL and a 5 s wait both fail. (5) The carried status sentence about reviewer B's review is removed. It is an unverified reviewer-conduct claim, and it is not restored.

### 0.4 Skills and tools (what was actually used)

| Skill or tool | Use in this round |
|---|---|
| caveman:investigate-first | Scratch evidence for T-N8, T-CAP-INH, T32, T-ADM-FRAMING and T-PTRACE-GO. Causes and proof recorded in section A. |
| caveman:verify-and-stop | Run after this document is written. Results in section 18. |
| ponytail:ponytail-audit | From v6 (section 11). Not re-run. |
| code-review, security-review | Not applicable: no diff, no PR. |
| caveman and ponytail output modes | Output style only. Not evidence. |

### 0.5 Environment record

| Item | Value | Source |
|---|---|---|
| Kernel | Linux 7.2.11-200.fc44.x86_64 #1 SMP PREEMPT_DYNAMIC Thu Oct 15 15:58:58 UTC 2026 x86_64 | `uname -srvm` (out/host_metadata.txt) |
| Architecture | x86_64 only. All measurements are x86_64. | `uname -srvm` |
| util-linux | unshare from util-linux 2.41.6 | out/host_metadata.txt |
| Python (scratch harness) | 3.14.8 | out/host_metadata.txt |
| Go (gate toolchain) | go1.27.3, the module toolchain for `go 1.27.3` in go.mod. Plain `go` in the repository selects it. | E12, frame61 build |
| Go (local install) | go1.27.0 at /usr/local/go. GOTOOLCHAIN=local selects it. It fails the go.mod floor inside the module. | out/host_metadata.txt |
| Yama ptrace_scope | 0 on this host. CI does not set it. | /proc/sys/kernel/yama/ptrace_scope |
| kernel.pid_max | 4194304 | out/host_metadata.txt |
| user.max_user_namespaces | 126328 | out/host_metadata.txt |
| fs.lease-break-time | 45 s | out/host_metadata.txt |
| AppArmor userns restriction | Not present on this kernel (file absent). | out/host_metadata.txt |
| CGO | Release builds require CGO_ENABLED=0. Scratch builds use it and -buildvcs=false. | Repository rule (AGENTS.md) |
| Hosted CI kernel and util-linux | Not recorded in the repository. Unknown. CI must print them (T120). | ci.yml runs on ubuntu-26.04 |

Host metadata disclosure record: out/host_metadata.txt in the bundle lists the values above. It contains versions and
sysctls only. No host name, user name, address or path is recorded.

### 0.6 Evidence index

| ID | Experiment | Runs | Location |
|---|---|---|---|
| v6 E1 to E8 | Flat teardown, stop and kill matrix, ptrace matrix, ENOMEM, RLIMIT, unshare exit status, foreign init | as in v6 section 0.6 | contract-v6-bundle.tar.gz (carried, unchanged) |
| E9 | Channel exclusion, CapInh/CapAmb refusal, ptrace attach, Python chain. 9 cases x 5 runs. | 45 | out/chain/results.normalized.jsonl; out/evidence61_v61.txt lines 1 to 27 |
| E10 | Admission framing decision table (Go, go1.27.3). 23 cases. | 23 | out/frame/results.normalized.jsonl; out/evidence61_v61.txt lines 41 to 66 (table) and 68 to 81 (flags). Labels of rows 60 and 62 are superseded (E10-R4; see the SUPERSEDED note at the end of that file). |
| E10-R2 | Bounded rerun of two E10 cases with the D15 labels (this round, go1.27.3, FRAME61_CASES filter) | 1 each | out/frame-rerun-d15/ |
| E10-R3 | Bounded rerun of the same two E10 cases after the decidePost fix (go1.27.3, FRAME61_CASES filter). Label and fd-count evidence only; not evidence that the full Close ladder ran (T-STATUS-POST, T-CLOSE-BOUND). | 1 each | out/frame-rerun-r3/ |
| E10-R4 | Full E10 on the R4 build: 23 base cases and 10 post-status cases (33 rows, no FRAME61_CASES filter). Label, fd-count and pipe-EOF evidence only; not evidence of the full Close ladder (T-STATUS-POST, T-CLOSE-BOUND). Superseded for E10 labels by E10-R6 (section 12.1); still the record of the R4 build. | 33 | out/frame-rerun-r4/ |
| E10-R5 | Full E10 on the R5 build: fresh build of the frame61 source with sha 917f42b8 (binary sha 334717de, build-path dependent, built in the scratch build directory with go1.27.3 and CGO_ENABLED=0). 47 rows, no FRAME61_CASES filter. Label, fd-count, pipe-EOF and receive-counter evidence only. | 1000 iterations (47000 rows) | out/frame-rerun-r5/ |
| E10-R5-REP | Repeated E10 runs on the supplementary root build (sha e6685f56; source not recorded): three runs of 1000 iterations. With E10-R5: 4000 iterations and 188000 rows, 0 wrong labels, 0 failing iterations. R4 binary (sha 1f207190) as control: 2000 iterations, 42 first-attempt failing iterations (section 12.1). | 3000 iterations | out/frame-rerun-r5/ |
| R5 tests | Frame harness unit tests (receive_test.go, fuzz_test.go): go test -count=1 -v, 59 PASS lines; FuzzDecideOracle 10 s (418108 execs); FuzzParseWireAgreement 10 s (274743 execs); TestParseWireEscapedNames PASS. Scratch only. Superseded for current counts by the R6 tests row (R5 sources). | unit and fuzz | out/frame-r5-tests/ |
| E10-R6 | Full E10 matrix on the R6 build: frame61 R6 sources, binary sha prefix 6acb8e75737e0d37 (build-path dependent; go1.27.3, CGO_ENABLED=0). 47 rows, one run, no FRAME61_CASES filter. Compared label by label with the E10-R5 summary: 0 differences. Label, fd, pipe-EOF and receive-counter evidence only. | 1 run (47 rows) | out/frame-rerun-r6/ |
| R6 tests | Frame harness tests on the R6 sources: go test -count=1 -v, 35 top-level PASS, 70 PASS lines including subtests, 0 FAIL. Red on R5 sources: 4 FAIL (the four TestR6Repro tests). The red run used the R5 main.go, the R5 receive_test.go and an R5-signature repro_test.go (sha256 18c94c05...); its test bodies differ from the final repro_test.go only in call signatures. Mutations A and B caught. FuzzDecideOracle and FuzzParseWireAgreement at -fuzztime=10s (last progress lines of the final run: 263539 and 146326 execs; PASS). Scratch only. | unit, red, mutation and fuzz | out/frame-r6-tests/ |
| E15 | Drain receive probe: blocking and MSG_DONTWAIT recvmsg on an empty SOCK_SEQPACKET pair, and a receive after the peer closes, with a kernel SO_RCVTIMEO of 2 s. Shows that MSG_DONTWAIT returns EAGAIN at once. | 5 per case | out/drain-probe/results.txt; src/flat61/drain61_probe.py |
| RB61-P4, RB61-P5 | Reviewer B probes of this round: pidfd_getfd and /proc fd reads from P; a forged record in the breach control | 5 each | reviewer B review (this round). Not re-run. Not in the bundle. |
| E11 | Sender credential and ppid checks across namespaces (Python chain, same run as E9). | 5 per ok case | out/evidence61_v61.txt lines 29 to 39 |
| E12 | Per-thread CapBnd oracle with LockOSThread and fork from the same thread (Go, go1.27.3, inside a user namespace). | 5 | out/gocaps/run1.txt to run5.txt |
| E13 | Same oracle outside a user namespace (negative control): drop refused with EPERM. | 5 | out/gocaps/plain_shell_negative/ |
| E14 | Host metadata disclosure. | 1 | out/host_metadata.txt |
| RB-P1 to RB-P6 | Reviewer B probes: channel exposure, per-thread drop, host read, sender translation, supervisor death (Python and nsenter chain). | 1 each (P6: one per mode) | reviewer B review (review-v6.md, section 2). Not re-run. |
| RC-Y1 to RC-Y12 | Reviewer C results: SIGTERM and SIGKILL to L, RLIMIT A/B, framing, ptrace, admission order. | Y1: 10 runs (5 per branch); other cases as stated in the reviewer file | reviewer C review (issue-390-v6-acceptance-review.md, sections 4 and 6). Not re-run. |

Scratch sources in the bundle: src/flat61/chain61.py, src/flat61/summarize61.py, src/flat61/evidence61.py, src/tools/bundle61.py,
src/frame61/main.go, src/frame61/receive_test.go, src/frame61/fuzz_test.go, src/frame61/repro_test.go, src/frame61/r6_test.go, src/frame61/go.mod, src/gocaps/main.go. The bundle README gives the commands.

### 0.7 Environment limits of this round

Only one kernel (7.2.11) and one architecture (x86_64). Python producer and Python init for E9 and E11. The Go frame
harness (E10) exercises the receive path only. The gocaps oracle (E12) is not the production launcher. No production
code exists at base 153e7236, so no production gate has run.

---

## 1. Decision

### 1.1 Recommended architecture: flat topology (T-FLAT), unchanged

- H0 (holder) keeps the base user and network namespaces. Its PID namespace is the host's.
- L is `unshare --pid --fork --kill-child`, joined into H0's user and network namespaces by nsenter. L is a child of D.
- I is the first process in the new PID namespace N. I is a child of L. I is PID 1 of N. I is the Go binary in init role (D13).
- P (producer) is a child of I. G (producer descendant) is a child of P, or reparented to I if P exits first.
- D (supervisor) holds pidfds for H0 and L (its own children), and for I and P (sent by I over the channel).

### 1.2 Rejected alternative: nested topology (rejected, unchanged)

The nested topology is rejected for the identity reasons in v6 section 1.2 (X1, N4, N7). No stopped-C control was run.

### 1.3 Gate status for the recommendation

| Gate | v6 result | v6.1 result |
|---|---|---|
| Corrected T-F5 teardown with verified ownership | PASS in flat (v6 E2) | Unchanged |
| Real producer child under I, live and zombie | PASS as a Python stand-in (v6 E1, E2, E3). Mechanism only. | Unchanged. Production producer not run. |
| Repeat timing-sensitive experiments | PASS, 5 runs per case in v6 | Unchanged. E9, E10, E12 use 5 runs per case. |
| Environment recorded | PASS (v6 0.5). Extended in 0.5 here. | PASS |
| Same-binary launcher ENOMEM mechanism | PASS for the mechanism (v6 E4). The same-binary launcher is not adopted. | Unchanged |
| Bounded forks, no unrelated probes | PASS | Unchanged |
| Channel exclusion (T-N8) | NOT RUN in v6 | Scratch PASS (E9). Production gate Tier B, slice 3. |
| Channel control 2 (T-GETFD: pidfd_getfd and /proc/<I>/fd refused) | NOT RUN in v6 | Reviewer probe RB61-P4 only. Production gate Tier B, slice 3. |
| Go-side SCM_RIGHTS framing (T32, T-ADM-FRAMING) | NOT RUN in v6 | Scratch PASS, 23 of 23 (E10). Production gate Tier B, slices 1 and 3. |
| CapInh and CapAmb refusal (T-CAP-INH) | NOT RUN in v6 | Scratch PASS (E9). Production gate Tier B, slice 3. |
| Per-thread drop on the Go forking thread (T-PTRACE-GO, scratch form) | NOT RUN in v6 | Scratch PASS, 5 of 5 (E12, E13). Production gate Tier B, slice 3. |
| Admission sender credentials and ppid (T-ADM-PPID, positive form) | NOT RUN in v6 | Scratch PASS, 5 of 5 (E11). Negative forms: Tier B, slice 6. |
| Real producer under RLIMIT_NPROC (T-F6b) | NOT RUN | Blocked by D2 and D12. Slice 7. |
| Writer inside N against a leased inbox (T-LEASE) | NOT RUN | Not run. Slice 8. |
| Admission parent check, check 4 | Header only | Scratch positive form (E11). |
| Go init drops the bounding bit on its forking thread (R6) | NOT RUN | Scratch PASS (E12). Production Tier B. |

The decision stays conditional on the Tier B gates in section 12.2. The Tier A blockers are resolved in scratch.

---

## 2. Ownership: processes and descriptors

### 2.1 Process tree and namespaces (unchanged except the P note)

```
D  supervisor (host user ns, host PID ns, host net ns)
|
+-- H0  holder: user ns U0, net ns NET0, PID ns host         [D child]    pidfd(H0) held by D
|
+-- L   unshare --pid --fork --kill-child, joined to U0/NET0,  [D child]    pidfd(L) held by D
|       |
|       +-- I  PID 1 of N (new PID ns), user U0, net NET0      [L child]
|             |  pidfd(I): created by I (pidfd_open of itself), sent to D
|             |  holds channel child end until the status record is sent or I exits
|             |
|             +-- P  producer, I child, exec'd, no channel       pidfd(P): created by I, sent to D
|             |     +-- G  producer descendant (reparented to I if P exits first)
|             +-- (no other members in production)
```

P can also obtain a pidfd for PID 1 with pidfd_open(1) (E9). That pidfd does not reach D and admission does not use it.
Signals from P to I are covered by T-SIG-INIT (Tier B, slice 3). P can also reach I's fds through pidfd_getfd(pidfd(I), fd) and through /proc/<I>/fd. Both are refused while the capability invariants of section 4.1 hold (control 2 of section 3.1; gate T-GETFD, slice 3). Reviewer probe RB61-P4 measured the refusals; in the breach control the channel fd was returned.

Namespace N has no mount namespace. /proc inside N shows host PIDs. Nothing in production reads /proc inside N.

### 2.2 Descriptor ownership (restated)

| Descriptor | Held by | Created by | Released when |
|---|---|---|---|
| pidfd(H0) | D | D (pidfd_open of its own child) | After Done(H0) and reap by D (CL5) |
| pidfd(L) | D | D (pidfd_open of its own child) | After Done(L) and reap by D (CL5) |
| pidfd(I) | D (copy sent by I) | I (pidfd_open(getpid())) | After Done(I) (CL2). D does not wait for I's reap. |
| pidfd(P) | D (copy sent by I) | I (pidfd_open of its own child P) | After Done(P) is observed (Stop T1, or Close CL2) |
| channel parent end | D | D (socketpair, SOCK_SEQPACKET, SOCK_CLOEXEC) | After Close succeeds (CL7) |
| channel child end in I | I | D (socketpair), passed to L as an inherited descriptor. I's copy has FD_CLOEXEC set before the fork of P. | I closes it after the status record is sent, or when I exits. |
| channel child end in L | L (inherited) | D | L closes it at exit. L never reads or writes the channel. |
| channel child end in D | D, until Start of L returns | D | D closes its copy when Start of L returns, on success or failure |
| channel child end in P | nobody | Not possible after exec. FD_CLOEXEC is set in I before the fork of P, and P is exec'd. Fork without exec is forbidden (S21). | n/a. Measured: E9 lines 3 to 5. Also refused through pidfd_getfd and /proc/<I>/fd while section 4.1 holds (A36; T-GETFD, slice 3). |
| pidfd(1) in P | P | P (pidfd_open(1), own namespace) | Not used by D. Not part of admission. |

L holds the channel child end because util-linux `unshare` inherits descriptors and does not close them. L is outside N, so P
cannot name it by pid. A record from L is rejected by check 10 (section 3.3): its SCM_CREDENTIALS pid is pid(L), not pid(I).
Check 4 does not reject it, because check 4 reads pidfd(I) and ppid(I) equals pid(L). Check 4 is not a sender check (A37).

### 2.3 Who reaps what (unchanged)

| Process | Reaped by | Mechanism |
|---|---|---|
| H0 | D | waitid(P_PIDFD) after Done(H0), D's own child |
| L | D | waitid(P_PIDFD) after Done(L), D's own child |
| I | L (normal path, I dies first) or the host orphan reaper (when L dies first) | Not controlled by D. D3 and N9. |
| P | I | I's own child, waitid(P_PID) |
| G | I (after reparenting) or the namespace zap | Not observed by D |

---

## 3. Admission and channel (restated)

### 3.1 Trust model

- P is the adversary. It runs unprivileged in N with the capability rules of section 4.
- H0, L and I are helpers started by D. They are trusted for correct behavior, but admission still checks their identities.
- P receives no channel descriptor and no pidfd from D. P can create a pidfd for PID 1 itself (E9). P cannot send a channel
  record while both controls hold. Control 1: FD_CLOEXEC with exec. P holds no channel fd after exec (E9 line 4, P_has_channel
  0 of 5). Control 2: the capability invariants of section 4.1 (R1, R2, R3 and R6). P cannot obtain the channel from I by
  pidfd_getfd(pidfd(I), fd) or by reading /proc/<I>/fd. Both are refused by the ptrace access check that refuses attach
  (recalled rule, section 4.2; gate T-GETFD). Breaking control 2 lets P reach the channel and send records that carry pid(I)
  credentials (RB61-P5, breach control only). The pid(I) credential rules of section 3.2 and check 10 depend on control 2.
- Signals from P to I are not restricted by the channel rules. T-SIG-INIT (section 12.2) covers them.

### 3.2 Channel framing (exact)

- Socket: socketpair(AF_UNIX, SOCK_SEQPACKET, 0) with SOCK_CLOEXEC. One record per message.
- Credentials: SO_PASSCRED is set on D's end before L is spawned. Every record carries SCM_CREDENTIALS.
- Receive: recvmsg with MSG_CMSG_CLOEXEC and MSG_DONTWAIT. Every receive on the channel parent end is non-blocking. An admission receive is a poll with the admission deadline (last bullet of this section), then a non-blocking receive. EAGAIN after a readable poll polls again. An admission receive makes at most 17 recvmsg calls, EAGAIN included. At most 8 of them may return EINTR (the approved bound; the ninth gives CLOSE:budget). Poll EINTR is retried only inside the deadline and does not count. A drain receive has no poll and follows the rule of A40. Control buffer: CmsgSpace(size of ucred) + CmsgSpace(4 * sizeof int). On amd64 this is 32 + 32 = 64 bytes (E10 used 64).
  Data buffer 1024 bytes.
- Reject the message if any of these hold: MSG_TRUNC (0x20) is set; MSG_CTRUNC (0x8) is set; SCM_CREDENTIALS is missing;
  the payload fails the strict grammar below; the message type is not allowed in this state; the fd count is not the required count for the type;
  the record exceeds 1024 bytes.
- Strict grammar (R5, R6): the payload is valid UTF-8 and exactly one JSON object. Duplicate member names after unescape are rejected. Allowed member names are v, type, kind and value only. A null value is rejected. Numbers are integers only, and an integer must fit the Go int of the build target (R6 integer rule). The harness parses the value as int64 and checks that it fits the build's int (int64 on amd64; a 32-bit build would reject values outside int32, which is not built or measured here). -0, fractions, exponents and leading zeros are rejected. v is present as an integer; its value is checked as shape (class b for V not 1), not as grammar.
- EOF (R5, R6): a zero-byte receive is EOF only when SO_PASSCRED was verified by readback (A8), the receive delivers no ancillary data, and neither MSG_TRUNC nor MSG_CTRUNC is set. With verified credentials the kernel attaches SCM_CREDENTIALS to every record, so a zero-length record from a sender carries ancillary data and is a record. A closed peer delivers no ancillary data and is EOF. Without verified credentials every zero-length receive is a record, and a closed peer then yields records until the drain cap ends the loop (scratch test TestDrainZeroLengthIsRecordWithoutCreds). Any other zero-length result is a record. It counts toward the eight records of the drain (A40). It is class (a) (3.4 rows for zero-length records).
- Readiness poll (R6): the T2 readiness wait is the only poll in the drain path. POLLIN, POLLHUP and POLLERR count as readable. POLLNVAL, and any poll error other than EINTR, is an observation error at T2 (A40). The drain itself has no poll. The admission receive keeps its own poll (Receive above).
- The count rule is the primary guard for 2 to 4 fds. CTRUNC is the guard for more than 4 fds. The kernel closes undelivered
  fds on CTRUNC (E10: pipe EOF 2 of 2, 3 of 3, 5 of 5).
- Message types, in required order:

| Order | type | Sent by | Fd count | Data (JSON, v=1) | Credentials pid |
|---|---|---|---|---|---|
| 1 | "init" | I, before P is forked | exactly 1: pidfd(I) | {"v":1,"type":"init"} | equal to pid(I) (check 4) |
| 2 | "producer" | I, after P is forked | exactly 1: pidfd(P) | {"v":1,"type":"producer"} | equal to pid(I) |
| 3 | "status" | I, after it reaps P | exactly 0 | {"v":1,"type":"status","kind":"exit" or "signal","value":N} | equal to pid(I) |

- Before admission completes, any record out of order, duplicate, or not one of these types is an admission failure and runs Close (section 3.4).
- After admission completes, each record is class (a) or class (b) (D15). Class (a) runs the full Close ladder when D reads the record: an init or producer record, a record with an unexpected descriptor, a record with MSG_TRUNC or MSG_CTRUNC, a zero-length record (3.2 EOF rule), a record whose sender credentials are missing or not pid(I), and any other record that is not a status record, including a record that does not parse and whose type field does not decode to status (R4 decision 8).
- Class (b) makes ExitStatus Unknown and does not start Close. It applies only to a status candidate (defined below) that is malformed, has an unknown kind, has a V other than 1, or repeats a valid status, when its sender credentials are pid(I) (provenance intact), it carries no descriptor, and it is not truncated. Status candidate rule (R5): a status candidate has exactly one member named type, matched by exact name after unescape, whose value is the string status. The candidate test runs before the duplicate-name check. A payload that is truncated or not valid UTF-8 is not a candidate. A case variant such as TYPE is not a candidate. A record that does not parse and whose type field does not decode to status is class (a) (R4 decision 8). Unauthenticated records are never class (b). Provenance depends on section 3.1 control 2: P keeps CAP_SYS_ADMIN in U0 (RB61-P4, CapPrm 000001fffff7ffff), and a sender with that capability may name pid(I) (recalled, not measured). Where control 2 fails, pid(I) credentials prove nothing, and class (b) is not authenticated.
- D reads the channel at admission, at Stop (T2), at Close entry (CL0a), and at EOF. Reads at T2 and CL0a use the drain rule of A40 (at most 8 accepted records, at most 8 EINTR returns, at most 17 recvmsg calls per drain, all non-blocking; an observation error ends the drain with no status accepted). A class (b) record does not stop T2. No reader runs while Running in v6.1, so a class (a) record that arrives while Running is acted on at the next read. Adding a reader changes the architecture; it is open for the maintainer (18.2).
- A status record before the producer record is an ordering violation. It is an admission failure.
- Every received fd is closed by D on any rejection path before cleanup starts, except the required pidfd of an accepted init or producer record, which D keeps (A40).
- Admission has a bounded deadline: admissionDeadline = 5 s from the channel being created, using poll on the parent end, then a non-blocking receive (above). Expiry is a rejection.

Architecture-neutral receive path (R6 final, A52 (5)). The admission poll is SYS_PPOLL on Linux (syscall.SYS_POLL is not defined on linux/arm64). The receive uses recvmsg with MSG_DONTWAIT and MSG_CMSG_CLOEXEC on Linux amd64 and arm64. R6 scratch execution is amd64 only. On arm64, go test -c and go vet exit 0 with CGO_ENABLED=0; the arm64 tests and the integration runs are NOT RUN. There are no 386 obligations; the 32-bit integer path is item 30 of 18.2.

### 3.3 Admission rules

Step 1, on message "init":

1. Namespace identity of I against L's children namespace: st_dev and st_ino of PIDFD_GET_PID_NAMESPACE (ioctl 0xff05) of pidfd(I) equal those of PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE (ioctl 0xff06) of pidfd(L). Fail closed on any error from either ioctl. (C16). Gate T-A-ADM.
2. User namespace: PIDFD_GET_USER_NAMESPACE (0xff09) of pidfd(I) equals that of pidfd(H0), by the same comparison.
3. Network namespace: PIDFD_GET_NET_NAMESPACE (0xff04) of pidfd(I) equals that of pidfd(H0), by the same comparison.
4. Parent and identity check: PIDFD_GET_INFO (0xC058FF0B, struct pidfd_info, 88 bytes). Request mask PIDFD_INFO_PID (1) and PIDFD_INFO_CREDS (2). Require (returned mask and 3) == 3 before reading fields. Read pid(I) at offset 16 and ppid(I) at offset 24. ppid(I) must equal the pid of L as D holds it. L is D's unreaped child, so that pid cannot have been reused. Both values are in D's PID namespace (host). Fail closed on ENOTTY or EINVAL. Check 4 does not check the sender: a record from L passes it when it carries pidfd(I) (A37). Check 10 rejects that record.
5. Rejection of substitutes: pidfd(H0) and pidfd(L) fail check 1 (host PID namespace) and check 4 (parent is D). A producer pidfd passes checks 1 to 3, because the producer is in N. Only check 4 rejects it (gate T-ADM-PPID, negative form, slice 6).

Step 2, on message "producer":

6. pidfd(P) PID namespace (0xff05) equals N (the value from step 1 check 1), by the same comparison.
7. Parent check: PIDFD_GET_INFO on pidfd(P), mask check as in check 4. ppid(P) must equal pid(I).
8. User and network namespace checks as in checks 2 and 3, for pidfd(P) against N's user and net namespaces.
9. Order: the "producer" record is accepted only after the "init" record and after I has forked P.
10. Sender (C25): SCM_CREDENTIALS pid of each record must equal pid(I) from check 4. A record from a sibling process, or from L (pid(L)), is rejected here, not by check 7 alone. This check authenticates the sender only while section 3.1 control 2 holds (section 3.2, class (b)): a channel holder with CAP_SYS_ADMIN in U0 could name pid(I) (recalled, not measured). Zero-length records are covered by the same check (T-SENDER, 12.2).

Status: the status record is accepted only after "producer" and only if it parses (section 3.2 rules and section 3.4).

Measured (E11, E10):

- creds(I) == pid(I), ppid(I) == pid(L), creds(P) == pid(I), ppid(P) == pid(I), and mask and 3 == 3 for both pidfds: 5 of 5 in each ok case (E11 lines 31 to 33 and 37 to 38).
- Frame decisions for the same rules: CLOSE:creds_pidfd for a record whose pidfd is not from the sender (E10 line 54), CLOSE:creds for a producer record from a different sender (E10 line 64), CLOSE:ppid for a producer that is not I's child (E10 line 65).

Not measured: namespace identity checks 1 to 3 with the dev and ino comparison (C16). The foreign-init substitute was measured in v6 E8 (5 of 5, rejected by check 1). The producer pidfd as init (negative form of T-ADM-PPID) is not run.

### 3.4 Failure and status routing

| Event | Before admission completes | After admission completes | Action |
|---|---|---|---|
| Init admission check 1 to 4 fails | yes | no | Close (section 6.4) |
| Init record missing, malformed, or with wrong fd count or creds | yes | no | Close |
| Producer admission check 6 to 10 fails | yes | no | Close |
| Duplicate producer record | yes | yes | Close (control framing, D15 class a). E10 line 62 recorded UNKNOWN:late_record under the superseded expectation. Rerun in R2 (E10-R2): UNKNOWN observed, CLOSE expected, FAIL on label. Rerun in R3 (E10-R3): CLOSE observed, PASS on actual classification. |
| Status record before producer record | yes | no | Admission failure: Close (E10 line 59: CLOSE:early_status) |
| Status candidate (3.2) malformed, with unknown kind, or with V not 1, with exact creds (pid(I)), no descriptor and no truncation, after producer | no | yes | ExitStatus Unknown. No Close (D15 class b). E10 line 61 (unknown kind): UNKNOWN:status_shape. E10-R4 row producer_then_status_type_mismatch: UNKNOWN:malformed. The row name says type mismatch, but its kind field is a number (a wrong JSON type for a field, not a wrong type member; the same note as main.go line 1031). V not 1 after producer is not measured by E10-R5; decidePost and FuzzDecideOracle cover it (T-STATUS-POST (m)). |
| Record that does not parse and whose type field does not decode to status, after producer | no | yes | Close (D15 class a: not a status record). E10-R4 row producer_then_unparseable: CLOSE:malformed. |
| Status record with a descriptor, MSG_TRUNC or MSG_CTRUNC, or with wrong or missing creds, after producer | no | yes | Close (D15 class a: unexpected descriptor, truncation, or sender identity). E10 line 60 (descriptor) recorded UNKNOWN:status_shape under the superseded expectation. Rerun in R2 (E10-R2): UNKNOWN observed, CLOSE expected, FAIL on label. Rerun in R3 (E10-R3): CLOSE observed, PASS on actual classification. E10 lines 78 to 81 (CTRUNC and TRUNC flags): CLOSE. Wrong creds on a status record: not measured (T-STATUS-POST). |
| Valid status record, first, alone | no | yes | ExitStatus Known (only if no other record follows, section 6.1) |
| Second status record after a valid status, with exact creds (pid(I)), no descriptor and no truncation | no | yes | ExitStatus Unknown. No Close (D15 class b). E10 line 63: UNKNOWN:after_terminal. E10-R4 row known_then_status_type_mismatch: UNKNOWN:after_terminal (the row name is the same kind-as-number note as above). |
| Second status record after a valid status, with a descriptor, truncated, or with wrong or missing creds | no | yes | Close (D15 class a). E10-R4 rows known_then_status_with_fd, known_then_status_truncated, known_then_status_ctrunc and known_then_status_foreign_creds: CLOSE:status_fd, CLOSE:trunc, CLOSE:ctrunc and CLOSE:creds. Full ladder in T-STATUS-POST (d). |
| Init or producer record after admission, including after a valid status | no | yes | Close (D15 class a). E10-R4 row known_then_producer: CLOSE:late_record. |
| Record after a valid status that is not a status record (valid JSON of another type, or unparseable with a type field other than status) | no | yes | Close (D15 class a). E10-R4 row known_then_unparseable: CLOSE:malformed. Full ladder in T-STATUS-POST (g) and (k). |
| Valid status after a malformed status (type field status, exact creds, no descriptor, not truncated) | no | yes | First record UNKNOWN:malformed (class b); second record UNKNOWN:after_terminal (class b). No Close. E10-R4 row malformed_status_then_valid. |
| Zero-length record after producer (EOF rule, 3.2) | no | yes | Close (D15 class a). E10-R5 row producer_then_zero_length: CLOSE:empty. |
| Zero-length record after a valid status | no | yes | Close (D15 class a), full ladder. T-STATUS-POST (n). E10-R5 row known_then_zero_length: CLOSE:empty. |
| Zero-length record before init | yes | no | Close. E10-R5 row init_zero_length: CLOSE:empty. |
| SO_PASSCRED readback returns zero (credentials unverified) | yes | no | Close: CLOSE:passcred_unverified (A8; E10-R5 row passcred_readback_zero). Without verified credentials a zero-length receive is a record, not EOF (3.2 EOF rule). |
| Truncated record before admission completes (MSG_TRUNC or MSG_CTRUNC) | yes | no | Close (D15 class a). E10 rows init_oversize_1500 (CLOSE:trunc) and init_one_fd_v6_buf24 (CLOSE:ctrunc), E10-R5 rows. |
| Drain observation error (a recvmsg error other than EAGAIN, EINTR or EOF at a drain; a readiness poll error other than EINTR, or POLLNVAL, at the T2 wait) at Stop T2 or at Close entry (CL0a) | no | yes | ExitStatus Unknown. The error is sticky (R6): the drain state is poisoned, so every later drain on the handle returns POISONED with zero recvmsg calls, and no status is accepted after the error, including a valid status read later. At T2: Stop runs T3, then returns an error that wraps ErrObservation, joined with any Lost error; Stop never returns nil after an observation error (S28). At CL0a: Close runs CL0 to CL7 and never returns nil after an observation error. ErrObservation is a separate sentinel from ErrProtocolViolation (R6-3). Seam tests only (A50; R6 tests TestR6ObservationErrorWrapsAndPoisons and TestR6ReproObservationNotRestoredByLaterStatus). The T2 poll path is not in the harness (T-T2-POLL). |
| Valid status, then an observation error in the same drain or in the T2 continuation | no | yes | ExitStatus Unknown, not Known (R6). Stop or Close follow the observation error rows above. Seam test TestR6PostStatusErrorIsNotKnown. |
| Status candidate with V not 1 (type status, exact creds, no descriptor, not truncated), after producer | no | yes | ExitStatus Unknown. No Close (class b). Not measured by E10-R5; decidePost and FuzzDecideOracle cover it (T-STATUS-POST (m)). |
| Drain overflow (a ninth accepted record, or a ninth EINTR return; A40) at Stop T2 or at Close entry (CL0a) | no | yes | ExitStatus Unknown. No status read in the drain is accepted. The overflow is sticky (R6): later drains on the handle return POISONED with zero recvmsg calls. No Close (overflow is not class (a), A42). At Stop T2: Stop runs T3 (SIGKILL to pidfd(I), Done(I) within 5 s), then returns an error that wraps ErrProtocolViolation, joined with any Lost error from T1 or T3. Stop never returns nil after overflow, even when T3 succeeds (R4 decision 3). At Close entry: Close runs the safe bounded cleanup of 6.4 (CL0 to CL7). Close never returns nil after overflow. It returns ErrProtocolViolation, joined with ErrCleanupIncomplete when cleanup cannot be proven (R4 decision 4). |
| Receive-call ceiling (17 recvmsg calls, EAGAIN included) reached without a conclusive result (CALL_BOUND) | yes, per receive (receiveOne; an admission failure, so Close) | yes, per receive (each later receive, receiveOne). Per drain (T2 and CL0a): not reached while the record cap of 8 and the EINTR cap of 8 hold, because the 17th call is the last call a drain can make; the drain check is defensive | ErrObservation, a separate sentinel from ErrProtocolViolation (R6-3). Normative (R6 final). After admission: ExitStatus Unknown; at T2 Stop returns an error wrapping ErrObservation; at CL0a Close never returns nil. A ninth record and a ninth EINTR return stay ErrProtocolViolation. The receive ceiling restarts at each receive; the drain ceiling spans one drain, across records, EINTR returns and the terminal call; EAGAIN ends a drain without repoll (A52 (9)). The ceiling is reachable in receiveOne through repeated EAGAIN (TestR6CallCeilingIsObservation). |
| Channel EOF before init | yes | no | Close |
| Channel EOF after init, before producer | yes | no | Close |
| Channel EOF after producer | no | yes | ExitStatus Unknown if no status arrived; no Close |

Rules:

- Any admission failure (checks 1 to 10) runs the full Close ladder (section 6.4). The rejection path does not return success while H0 is alive.
- A drain overflow (A40) never accepts a status and never lets Stop or Close return nil (R4 decisions 3 and 4). A drain observation error has the same effect (R5, S28).
- A malformed or unknown-kind status record of class (b) is not an admission failure once admission has completed. It makes ExitStatus Unknown and does not start Close.
- Class (a) records after admission run the full Close ladder (section 6.4) when D next reads them (D15). Class (b) never starts Close. Under class (b) the producer keeps running and stays observed by pidfd. The caller decides, through Stop or Close.

### 3.5 Channel exclusion (N8): scratch PASS, production gate open

Design rules:

- FD_CLOEXEC is set on the channel child end in I before the fork of P.
- P is exec'd. Fork without exec is forbidden (S21).
- After exec, P's non-stdio fd set holds no channel and no pidfd(I) (gate T-N8, Tier B, slice 3).
- Control 2 (pidfd_getfd, /proc/<I>/fd, attach) is gate T-GETFD and T-PTRACE (slice 3), with the drift guard of section 4.1 R2.

Measured (E9, Python chain, 5 runs per case):

| Case | P holds channel | P holds pidfd(I) (by D's inode) | CapPrm19 in P | attach to I |
|---|---|---|---|---|
| ok_none_exec1 (no FD_CLOEXEC, exec) | 5 of 5 | 0 of 5 | 0 | EPERM 5 of 5 |
| ok_cloexec_exec1 (rule applied) | 0 of 5 | 0 of 5 | 0 | EPERM 5 of 5 |
| ok_cloexec_exec0 (rule applied, fork without exec) | 5 of 5 | 5 of 5 | 1 | OK 5 of 5 |

E9b (P fd set after exec, non-stdio): in ok_cloexec_exec1 each P holds only a memfd inherited from the Python runtime (cloexec
true, not the channel). The production producer (Go) has no such fd. The T-N8 assertion is "no channel and no pidfd(I) among
non-stdio fds", not "no non-stdio fd".

---

## 4. Capabilities and ptrace (restated)

### 4.1 Invariants at launch

| Item | I (init) | P (producer) | How it is read or set |
|---|---|---|---|
| CapBnd bit 19 (CAP_SYS_PTRACE) | 0 (dropped) | 0 (inherited) | prctl(PR_CAPBSET_DROP, 19) on the forking thread; read with PR_CAPBSET_READ on the same thread |
| CapPrm bit 19 | 1 (kept) | 0 (derived) | capget |
| CapEff bit 19 | 1 (kept) | 0 (derived) | capget |
| CapInh | 0 (asserted, R3) | 0 (asserted) | capget. Refuse launch if nonzero. |
| CapAmb | 0 (asserted, R3) | 0 (asserted) | prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET) per cap |

Derivation (recalled from capabilities(7), kernel source not on the host): after exec, permitted = inheritable OR bounding
OR ambient for the executed file. The formula matched E9 in every exec case: P_permitted19 = inh19 | bnd19 | amb19 (5 of 5 per variant, E9 formula_match column).

Rules:

- R1: I drops CAP_SYS_PTRACE from the bounding set only. I keeps it in permitted and effective. R1 is one of four rules that keep channel exclusion (control 2 of section 3.1): R1, R2, R3 and R6 together.
- R2 (load-bearing, must hold): I keeps bit 19 in its permitted and effective sets. Dropping it from permitted or effective in I (bndperm) is forbidden. Measured: it lets P attach to I (v6 E5, bndperm OK 5 of 5). R2 is required because the permitted-subset rule passes once I's permitted set lacks bit 19: P's permitted set lacks it too (R1, R3 and R6), so the subset condition holds for the same uid and attach succeeds. No production launch may drop it. The drift guard (T-PTRACE, slice 3) asserts I's CapPrm and CapEff bit 19 are 1 on every launch.
- R3 (mandatory, refusal): I refuses to start if CapInh or CapAmb is nonzero after its own setup, or if CapBnd bit 19 is set after the drop. Refusal happens before any init record. Measured: refused_before_init 5 of 5 for inh, amb and nobnd (E9 lines 6 to 8), P never runs, L exits with 2 (unshare returns the child's exit code, v6 E7). Breach controls with refusal off: attach OK 5 of 5 (E9 lines 9 to 11).
- R3 note: P's permitted set is inheritable OR bounding OR ambient for the executed file (derivation, section 4.1). Refusing nonzero inheritable and ambient bit 19, and refusing a bounding bit 19 after the drop, keeps P's permitted set free of bit 19 once R1 holds.
- R4: dumpable state is not a control. Measured in v6 E5: dumpable 0 did not stop attach when P held the capability.
- R5: D never gives P the channel or a pidfd (section 3.5). P can create its own pidfd for PID 1 (E9). That is accepted, and T-SIG-INIT covers the signal consequences.
- R6: capabilities are per thread. A child inherits the bounding set of the thread that forks it. I's Go runtime starts several threads. The drop and the fork of P happen on one locked thread (runtime.LockOSThread). The thread reads CapBnd before the fork and refuses the fork if bit 19 is set (C22). Threads that exist before the drop keep bit 19, and a fork from one of them gives P bit 19. Measured: E12 (go1.27.3, 5 runs): the locked, dropped thread and its fork show 000001fffff7ffff; the undropped threads show 000001ffffffffff; a fork from an undropped thread shows bit 19 set. E13 (control): plain shell drop is refused with EPERM, so the drop needs a user namespace (U0 provides CAP_SETPCAP in I).
- R6 note: R6 is load-bearing for control 2. P's bounding set lacks bit 19 only because the drop happens on the forking thread before P is forked (E12).
- R7: P is exec'd (A12, S21). Fork without exec leaks the channel and bit 19 (E9 line 5).
- R8: I's CapInh and CapAmb are asserted to be 0 after I's own setup, and the same check runs on the forking thread before the fork of P.

### 4.2 Measured ptrace results

Python chain, E9 (attach column). Production Go init not run.

| Variant | Meaning | P attach to I |
|---|---|---|
| none (v6 E5, bounding bit 19 not dropped) | P holds the capability (breach baseline) | OK 5 of 5 (v6 E5) |
| bnd (v6 E5: bounding bit 19 dropped; E9 `ok`, refusal on) | Required variant | EPERM 5 of 5 (v6 E5; E9 lines 3 and 4) |
| bndperm (bounding and permitted dropped in I) | Forbidden (R2) | OK 5 of 5 (v6 E5) |
| none, dumpable 0 | Dumpable does not help (R4) | OK 5 of 5 (v6 E5) |
| bnd, dumpable 0 | Bounding drop still blocks | EPERM 5 of 5 (v6 E5) |
| E9 fork without exec (line 5; S21 forbids this path) | Channel and bit 19 leak to P | OK 5 of 5 |
| E9 inh (inheritable bit 19, refusal off, line 9) | Breach control | OK 5 of 5 |
| E9 amb (ambient bit 19, refusal off, line 10) | Breach control | OK 5 of 5 |
| E9 nobnd (no bounding drop, refusal off, line 11) | Breach control | OK 5 of 5 |

Gate S18 (reviewer C, Y11): an EPERM from a ptrace gate counts only if the none control passes in the same run. Yama ptrace_scope 0 on
this host. CI does not set it. CI must print it, and a ptrace gate is INCONCLUSIVE when the control fails.

The commoncap rule (recalled, not checked in source): ptrace is allowed when the caller and target have the same UID, the target is
dumpable, and the target's permitted set is a subset of the caller's permitted set, or the caller has CAP_SYS_PTRACE in the target's
user namespace. The same-user-namespace condition is part of the rule (RB-F10). The measured results match the rule including that condition. The access checks for pidfd_getfd and /proc/<I>/fd use the same rule (recalled). Reviewer B measured both refusals with the bounding drop present (RB61-P4). T-GETFD and T-PTRACE pin the behavior in production; this text does not.

### 4.3 Capability items

| Item | Status | Gate |
|---|---|---|
| Forced inheritable bit 19 (T-CAP-INH) | Scratch PASS: refused before init, 5 of 5 (E9) | Tier B slice 3 (production) |
| Per-thread drop on the forking thread (T-PTRACE-GO) | Scratch PASS: 5 of 5 (E12 and E13) | Tier B slice 3 (production launch) |
| Refusal on nonzero CapAmb | Scratch PASS: refused 5 of 5 (E9 lines 7) | Tier B slice 3 |
| Refusal on bit 19 in CapBnd after the drop | Scratch PASS: refused 5 of 5 (E9 line 8) | Tier B slice 3 |
| Channel control 2: pidfd_getfd and /proc/<I>/fd refused for P (A36) | Reviewer probe RB61-P4: refused 5 of 5 with the drop; channel returned in the breach control 5 of 5. Not re-run. | Tier B slice 3 (T-GETFD) |
| Drift guard: I keeps CapPrm and CapEff bit 19 (R2) | Not measured as a gate. Required assertion in T-PTRACE. | Tier B slice 3 (T-PTRACE drift guard) |

---

## 5. RLIMIT_NPROC policy (restated for 5.3)

### 5.1 Measured behavior (carried from v6, E6)

v6 section 5.1 table, unchanged. Measured in v6 with Python test processes (own level, tree, chain, raised and lowered limits).

Reviewer C (RC-Y5, not re-run in v6.1): before the RLIMIT was lowered, a fork in a new user namespace failed with EAGAIN 10 of 10 when the
ancestor limit was low; after the change the fork succeeded 10 of 10. The initial-namespace control failed with EAGAIN 10 of 10. The limit 100000 gave OK 3 of 3.

### 5.2 Hierarchical accounting (carried)

- The check for a fork uses the uid's count in the task's user namespace and in each ancestor user namespace.
- The limit checked for an ancestor is the limit in force when that ancestor's child namespace was created (RC-Y5).
- A nested user namespace does not get a fresh budget. Its forks count against the outer total (E6).
- Host-wide uid count rises by the subtree size. Predicted from the ancestor rule, not measured against unrelated host processes.

### 5.3 Policy (restated)

- P1 (narrowed): I may set its own soft and hard limit to producerNprocLimit before forking P. This bounds forks by tasks in N at N's own level (E6 own-level behavior). It does not change the ancestor count in U0 (RC-Y5).
- P1a (new): D must not lower RLIMIT_NPROC before it creates H0 (S17). The limit D holds at H0 creation is the ancestor cap for U0.
- P2: hard = soft prevents the producer from raising the limit (measured, v6 E6).
- P3: base sets no limit (namespace_linux.go lines 76 to 83). This design adds one. That is a behavior change and is recorded as D2.
- P4: T-F6b (slice 7) runs the real producer under the limit with a bounded fork loop. It must reach EAGAIN and stop. No unbounded fork loops in any test.
- P5 (aggregate, C4): this bounds processes only. CPU, memory and file descriptors are not bounded. The uid-wide host process count still rises by the subtree size, so a limit above the host's headroom does not protect other processes of the same uid. Forks by D itself count against the same budget (RB-F4), so D's own forks can fail when producers consume it. There is no cap on concurrent producers yet (D12). This residual is stated, not removed.
- P6: assumption. D runs as a non-root host uid. The RLIMIT check may be skipped for uid 0 (recalled, not verified). If D runs as host root, P1 may bound nothing. Gate T-NONROOT (Tier C).
- Status: P1 and P1a are design rules. The aggregate policy (P5, D2, D12) is open, and slice 7 is blocked until D2 and D12 are recorded and T-LAUNCH-LIMIT, T-RL-AGG and T-F6b pass.

---

## 6. Process semantics (restated for 6.1 to 6.4)

### 6.1 Definitions

- Done(X): the pidfd of X is readable with POLLIN within the stated deadline. POLLIN means X has exited (it may be a zombie). Done is not a reap.
- Reaped(X): waitid(P_PIDFD) with WEXITED returns for X. D observes Reaped only for its own children (H0 and L). POLLHUP on a non-child (I, P, G) is not a Reaped observation (RC-Y7).
- Lost(X): D cannot establish X's state within the deadline. Lost covers: any pidfd or poll error other than EINTR (including ENOTTY, EINVAL, and ESRCH before exit), an invalid pidfd, or the deadline expiring with no POLLIN. Lost is not Done (C18). A drain receive error is an observation error, not Lost (A40).
- Waits: poll with a deadline, retrying EINTR only within that deadline. The base EINTR loop without a deadline (sys_linux.go lines 37 to 52) is replaced (N2).
- waitid is permitted only for actual children of the caller: D for H0 and L, I for P.
- ExitStatus(P): Known(kind, value) only when exactly one valid "status" record arrives after admission and no other record arrives on the channel
  (A11). Otherwise Unknown, including after a drain overflow or observation error (A40). Both errors are sticky (R6): a status read after either error, in the same drain or a later one, does not make ExitStatus Known, and a receive error after a valid status gives Unknown, not Known. ExitStatus commit (R6 final-2): T2 gives a provisional value (6.3). The one commit point is CL0a of the first Close (6.4), decided by commitExit with final set. A value before that point is provisional and may change. At the commit point the value is stored and frozen: every later call returns it unchanged. A final UNKNOWN is never KNOWN later, not after a later valid status, a protocol violation, or poisoning. A final KNOWN is not changed by a later record. Read the final value after the first Close returns. UNKNOWN is sticky: once stored, it is never KNOWN. A handle poisoned by a drain overflow or observation error is never KNOWN, at T2 or at CL0a. Provisional and final values (88ac, K2): at T2 a clean drain with no record returns UNKNOWN and stores nothing. A record-caused or poison-caused UNKNOWN is stored at T2 and never becomes KNOWN. A provisional KNOWN from T2 becomes UNKNOWN if a later record is read at CL0a. The first Close fixes the value at CL0a as final, and a final UNKNOWN is irreversible. This correction does not change commitExit (src/frame61/main.go: commitExit at line 787, commitDrain at line 803), whose non-final stores give this outcome.
- L's exit status is never used as P's status. Measured in v6 E7: unshare returns the child's exit code (3 for exit 3) but returns 0 when the child dies from SIGTERM or SIGKILL.
- Watch semantics: a Done wait is a poll on the pidfd with a bounded deadline and a cancel pipe (section 6.6).

### 6.2 Start (restated)

S1. Validate config. Helper paths are absolute (section 10.1). Each helper is opened and verified on one descriptor, and executed by that descriptor (A20). The init is D's own executable, opened by os.Executable() and verified by the same procedure, with fixed arguments.
S2. Create the channel (section 3.2). Set SO_PASSCRED on D's end. The admission deadline starts.
S3. Start H0: the base holder, unchanged. Its base Pdeathsig is retained. The production holder is not measured; the harness used a sleep stand-in (T-HOLDER, slice 4).
S4. Readiness: H0 is ready when pidfd(H0)'s user namespace (0xff09) and network namespace (0xff04) differ from D's own, by the comparison in section 3.3. Bounded by startDeadline = 5 s (base constant).
S5. Start L. The creator thread is locked (runtime.LockOSThread) for L's lifetime. Pdeathsig SIGKILL is set in the child before the exec of nsenter (D5 revised; A22). Launch: /usr/bin/nsenter --target <H0 pid> --user --net --preserve-credentials -- /usr/bin/unshare --pid --fork --kill-child -- <init absolute path> <fixed arguments>. No PATH lookup occurs (section 10.1). The H0 pid is safe to pass: H0 is D's unreaped child, so the kernel does not reuse its pid while D has not reaped it. The same holds for L.
    pidfd(L) = pidfd_open(L.pid) immediately after start. L is D's unreaped child, so this is not a pid-reuse race.
    Measured (RB-P6, one run per mode, Python chain): Pdeathsig set in the nsenter child survives the exec of nsenter, and when the creator dies, L and I are dead within 0.1 s. The Go launcher is not run (T-DEATH, slice 4).
S6. Admission (section 3.3, checks 1 to 10). Failure at any check: Close (6.4).
S7. Running. Stop and Close are available.
Context (D17, cancellation): Start(ctx) checks ctx before each of S1 to S5, in order. If ctx is done before pidfd(L) exists, Start runs Close (6.4) and returns an error that wraps ctx.Err() and Close's result. After pidfd(L) exists, ctx is not checked: admission runs to admissionDeadline (5 s) and Close uses its fixed deadlines. Test: T-CTX (slice 5).

### 6.3 Stop (restated; unchanged steps)

Stop ends the producer and its namespace. It does not end H0 or L. Steps:

T1. pidfd_send_signal(pidfd(P), SIGKILL). Wait Done(P) within killDeadline = 5 s.
T2. Drain the channel (A40; R6: the readiness wait is the only poll in the drain path, and its POLLNVAL or non-EINTR poll error is an observation error): wait for readability within statusDeadline = 1 s, then read with the non-blocking drain of A40: at most 8 accepted records, at most 8 EINTR returns, and at most 17 recvmsg calls for that drain (per drain, 3.4). Poll wakeups do not count. Reaching the receive-call ceiling of 17 without a conclusive result is an observation error (CALL_BOUND, 3.4), not a protocol violation. A valid status is Known only if it is the only record read: after a valid status, T2 keeps reading until EAGAIN, EOF, overflow or an observation error. A timeout, EOF with no status, or a class (b) record makes ExitStatus Unknown; a class (b) record does not stop T2. None of these is a Stop error. Overflow makes ExitStatus Unknown and is a Stop error: T2 ends, T3 still runs, and Stop returns an error wrapping ErrProtocolViolation, joined with any Lost error (R4 decision 3). An observation error (A40) makes ExitStatus Unknown and is a Stop error in the same way: T2 ends, T3 still runs, and Stop returns an error wrapping ErrObservation, joined with any Lost error (R5, S28). If T2 reads a class (a) record, Stop stops reading, runs the full Close ladder (6.4), and returns ErrProtocolViolation wrapping Close's result. Stop never returns nil in that case. The T2 value is provisional until the commit point at CL0a (6.1). T2 and CL0a use one value rule, commitExit (final false at T2, true at CL0a): a valid status is Known only if it is the only record read on the handle and the handle is not poisoned.
T3. pidfd_send_signal(pidfd(I), SIGKILL). Wait Done(I) within killDeadline = 5 s. T3 also runs after a T2 overflow (pidfd only, bounded). Killing I zaps N: G and any other members die (E2 and E3 in v6: about 1 to 2 ms).
Stop returns nil only if Done(P) and Done(I) and no drain overflow or observation error was read at T2 (A40, S28). Stop returns an error on Lost at T1 or T3, an error wrapping ErrProtocolViolation after a T2 overflow, and an error wrapping ErrObservation after a T2 observation error, joined with any Lost (R4 decision 3; R5). A T2 timeout is not Lost. A Stop that ends in Close under T2 returns ErrProtocolViolation (above).
Stop success means: P exited (observed), I exited (observed). G's death is enforced by the namespace zap and is not observed by D.
Stop and Close serialize on one mutex. A Stop that starts after Close has begun returns an error and sends no signal (RB-F12). Test: T-REENTRY (slice 5).
Behavior change from base (N10, F13): base Stop sends SIGKILL to the leader, sweeps the process group, and reaps the leader. v6.1 Stop kills P directly, then kills I. ExitStatus is Known only when the status record arrives before I is killed, which is the normal case. Decision D4.

### 6.4 Close ladder (restated, CL0 to CL7)

Close always attempts every step that is possible. A step failure does not skip later steps. Close returns nil only if every observed member exits and H0 and L are reaped. Close never returns nil while H0 or L is alive (correction 1). Close never returns nil after a drain overflow or observation error at T2 or CL0a, on this call or any later call (R4 decision 4, R5, CL7).

CL0a. Drain the channel once, on the first Close entry (A40, A42): the non-blocking drain of A40 (at most 8 accepted records and at most 17 recvmsg calls for that drain). CL0a has no readiness wait of its own; it does not repeat the T2 readiness wait. It applies the record and error rules of T2. Records read here set ExitStatus under 6.1 and otherwise change nothing: a class (a) record found here does not change the steps, because Close already runs. An overflow here changes no step: Close runs CL0 to CL7 and returns ErrProtocolViolation (R4 decision 4). The overflow is recorded on the handle (CL7). An observation error here changes no step either: Close runs CL0 to CL7 and returns an error wrapping ErrObservation, never nil (R5, S28); it is recorded on the handle (CL7). Received fds are closed at once. A retry does not repeat CL0a. If T2 already poisoned the handle (R6), CL0a returns POISONED with zero recvmsg calls, and Close still runs CL0 to CL7. The commit of ExitStatus (6.1) happens at this point, on this drain's result, by commitExit, the same value rule T2 uses, called with final true (R6 final-2): the value is stored and frozen. The value after this point is final.
CL0. If pidfd(H0) is not held and H0 was started: H0 is listed in Unobserved (A24, A41). Unobserved is a set: each member is listed once, however many steps find it unobserved. A never-started H0 is not listed (R5, Option Y). CL0 does not return here. Skip every step that needs pidfd(H0): CL1, and the H0 reap in CL5. Continue through CL4b and CL5 to CL7 on the pidfds that are held (R6 final; the R5 text omitted CL4b). Each of these steps checks its own pidfd, and none of them needs pidfd(H0). The required-exit set is H0, L, I and P. Each member is Done or Reaped, or is listed in Unobserved: H0 by CL1 and CL5, or by the listing above; I and L by CL2 to CL5, or by their listing (L when pidfd(L) is not held, I when pidfd(I) is not held); P by CL4b, or by its listing. G, a descendant of P, is not in the required-exit set by design: D does not observe it, and the namespace zap ends it when I dies (Stop T3). In the production supervisor lifecycle, send no PID-number signal and no group signal (S9, A24). The scratch harness is test code, not that lifecycle, and its cleanup is not evidence for production cleanup (12.2). Close returns ErrCleanupIncomplete, never nil. Decided in R4 (maintainer decision 5; 18.2 item 9). Test: T-CL0 (12.2, slice 5).
CL1. SIGKILL H0 via pidfd(H0). Wait Done(H0) within killDeadline = 5 s. (N1: unconditional when pidfd(H0) is held.)
CL2. If pidfd(I) is held:
     SIGKILL I via pidfd(I). Wait Done(I) within killDeadline = 5 s.
     (R6) No P wait in CL2. P is waited on after CL4 in every branch (CL4b). R5 placed that wait inside this branch, so a held pidfd(P) with pidfd(I) not held was never waited on.
     If pidfd(I) is not held (rejected init, or init never received): list I as Unobserved if L was started (R5, A41); skip CL3, and go to CL4. Never send SIGTERM to L (S16, A26).
CL3. If pidfd(I) is held: if pidfd(L) is held, wait Done(L) within killDeadline = 5 s. If pidfd(L) is not held and L was started, list L in Unobserved (A41) and do not wait (R6 final). L is listed only when started and its exit is unproven; a never-started L is not listed. L normally exits after it reaps I (v6 E1 control_killI: L exits 1.1-1.6 ms after KILL to I; 12.1 row: all members exit within 1.6 ms of KILL I).
CL4. If pidfd(L) is held: poll Done(L) with a zero timeout. If it is observed, send no signal. Otherwise SIGKILL L via pidfd(L) and wait Done(L) within killDeadline = 5 s. If pidfd(L) is not held, send no signal and wait for nothing; L is listed in Unobserved when it was started (R6 final). CL4 runs when pidfd(I) is not held or when CL3 did not observe Done(L). A retry sends no signal to a member already Done (A41, 7.4).
CL4b (W3, R6). In every branch, after CL4: if pidfd(P) is held, wait Done(P) within killDeadline = 5 s. If pidfd(P) is not held, list P as Unobserved (D14, A41). This applies whether or not pidfd(I) or pidfd(L) was held.
     Measured (v6 E1 stopL_killI, 5 of 5): a stopped L is not Done until SIGKILL. SIGKILL releases it in 0.2 ms. Reviewer C (RC-Y1, not re-run): SIGKILL to L ends L, I and P within 3 s (5 of 5). SIGTERM to L ends none of them within 3 s (5 of 5).
CL5. Reap D's own children H0 and L: waitid(P_PIDFD, WEXITED|WNOHANG) on pidfd(H0) when it is held, and on pidfd(L) when it is held, after their Done. The zombie is present by then, so the call does not block. A child that is not returned is Lost. If pidfd(L) is not held, L is not reaped and no waitid is issued for it; L is listed in Unobserved when it was started (R6 final), and Close does not return nil.
CL6. Cancel and join watchers with one watcherJoinDeadline = 1 s shared by all watchers (section 6.6; R6). A watcher that has not joined by that deadline is Lost.
CL7. Descriptor retention and release (R4 decision 6; RB-F8 and RB-C11; R6 release rule): two conditions are defined. CleanupComplete: every held member is observed and reaped (H0 and L reaped; I and P observed; Lost and Unobserved empty) and the watchers are joined. ProtocolClean: no drain overflow or observation error is recorded on the handle. Close returns nil only when CleanupComplete and ProtocolClean both hold. On any failure Close releases no descriptor a retry needs. It retains every valid descriptor and state item needed for a cleanup retry: every held pidfd, the channel parent end, the lists Lost and Unobserved, and the drain error record. Received descriptors that are untrusted or unexpected were closed when received (3.2). The overflow or observation record is set at T2 or CL0a and is never cleared on the handle. Every later Close returns the sticky error (ErrProtocolViolation after an overflow, ErrObservation after an observation error) and never nil. Close returns ErrCleanupIncomplete with the lists Lost and Unobserved when cleanup is not complete, joined with the protocol error where one is recorded. When CleanupComplete holds, Close releases the retained descriptors even if the handle records an overflow or observation error (R6 maintainer decision R6-2; this accepts reviewer C R-D1 and replaces the R5 retention reading of A27). After a release, the handle's pidfd slots are marked invalid, so a later Close returns the sticky error, sends no signal and uses no released descriptor. A wait that timed out stays in Lost for this Close call, even when a later step observes the member.

Close returns nil only when CleanupComplete and ProtocolClean hold (CL7, R6), and all of these hold: pidfd(H0) held, Done(H0) and H0 reaped (CL1, CL5; a missing pidfd(H0) is never nil, CL0); pidfd(I) held and Done(I) (CL2); pidfd(P) held and Done(P) (CL2); Done(L) and L reaped (CL3 to CL5); watchers joined (CL6); Unobserved empty; no drain overflow or observation error recorded on the handle, at T2 or CL0a (A40, CL7, R4 decision 4, S28). Passing T-ZAP-ORDER changes none of these conditions.

D14 (new): without pidfd(P) Close cannot return nil, because the producer is not observed. The error carries Unobserved = [P]. A launch that failed before P existed also returns ErrCleanupIncomplete with Unobserved = [P]. Callers can distinguish "all observed members reaped, producer unobserved" from "a member was Lost" by the lists. The namespace is still gone once I, H0 and L are reaped (kernel zap, recalled, not measured for this path; gate T-ZAP-ORDER, slice 5, Tier B, D4). Passing T-ZAP-ORDER does not relax this: Close never returns nil while Unobserved is not empty (A41). O-CL7 (decided, 18.2 item 10): a failure that leaves Unobserved = [P] releases nothing (CL7), so the descriptors of a launch that failed before P existed are held until a retry or process exit. R3 decision (18.2 item 10): retain every descriptor needed for retry on incomplete cleanup. Until a retry or process exit, they stay held.

Not claimed by Close: that N is released, or that I's zombie is reaped. I's reap depends on L (normal path) or the host orphan reaper (when L is killed first, CL4). Decision D3.

Worst-case Close time: CL0a 0 (non-blocking, at most 17 recvmsg calls, or POISONED with zero calls), CL0 0 (no wait; CL1 is skipped when H0 is not held), CL1 5, CL2 5 (I), CL3 5, CL4 5, the P wait of CL4b 5, CL5 0, CL6 1 = 26 s. Every step is bounded. The six waits are W1 Done(H0) (CL1, 5 s), W2 Done(I) (CL2, 5 s), W3 Done(P) (CL4b, after CL4 in every branch, 5 s), W4 Done(L) (CL3, 5 s), W5 Done(L) after SIGKILL (CL4, 5 s), and W6 watcher join (CL6, 1 s, one deadline for all watchers); total 26 s (R5). R6 moves W3 from inside the held-I branch to CL4b and keeps the total at 26 s.

Testable bound (R3, request 88ac item 3). Every wait and step above has a fixed bound. T-CLOSE-BOUND (12.2, slice 5) wedges one of the six waits W1 to W6 per run, in turn, and asserts per run: Close returns within 26 s; it returns ErrCleanupIncomplete with Lost and Unobserved as the failed steps require; it releases no descriptor a retry needs (CL7); and a second Close repeats only the failed steps and sends no signal to a member already Done. The timing assertion uses the production constants and does not widen them (17.4). The two D15 class (a) triggers (a status with a descriptor after the producer, and a repeated producer record) run the same ladder assertions in T-STATUS-POST rows (d) and (f).

### 6.5 Base comparison (updated rows)

| Behavior | Base | v6.1 flat |
|---|---|---|
| Producer parent | D | I. D sees P only by pidfd and by the status record. |
| Producer exit observed by | waitid by D | pidfd POLLIN by D; status record from I |
| Stop | SIGKILL leader, group sweep, waitid | SIGKILL P, wait status, SIGKILL I (zap) |
| Close kills holder | yes | yes, CL1 (pidfd only; CL0 if no pidfd) |
| Signal by process group | kill(-pgid) | not used. Group signals removed from base (namespace_linux.go line 292; child_linux.go lines 275, 278, 287). |
| Descendant sweep | group sweep in Stop | namespace zap; not observed |
| EINTR wait | unbounded loop | bounded poll |
| ExitStatus source | leader waitid | I's status record only |
| Helper path | PATH lookup (base) | absolute path, open-verify-exec by descriptor |
| Pdeathsig | producer (base child_linux.go) | L (A22). Holder: base retained. Producer: none (D5 revised). |

### 6.6 Watcher design (new, C17)

- A watcher waits for one pidfd with poll on {pidfd, cancelPipeRead}, in slices of at most 100 ms, re-checking the deadline on each slice.
- Return values: Done (the pidfd is readable), Cancelled (the cancel pipe reports hangup), Deadline (the deadline expired with no readable pidfd), Error (a poll or pidfd error other than EINTR; the member is Lost). If more than one of these holds in one poll return, the result is the first that applies in this order: Done, Cancelled, Deadline (R4 decision 10).
- Cancel: close the cancel pipe write end. Every watcher returns Cancelled on its next poll return, at most 100 ms after the close, unless its pidfd is already readable (then Done).
- Join: one deadline of 1 s (watcherJoinDeadline) covers all watchers together (CL6, R6). It is not 1 s per watcher. A watcher that has not returned by that deadline is Lost.
- The base watch() helper uses waitid on a pidfd, which fails for non-children (child_linux.go lines 148 to 155). It is not reused.
- Gate T-WATCH (slice 5, test T07 in 12.2): a stopped member is watched; cancel returns Cancelled and join completes within 1 s; 5 runs.

---

## 7. Lifecycle, failure and retry state machines

### 7.1 Launch states (unchanged from v6)

```
Idle --start--> H0Ready --start L--> LStarted --init record, admitted--> InitAdmitted
     --producer record, admitted--> Running
Any state --failure or deadline--> Closing
Closing --all steps Done and reaped, every observed member--> Closed
Closing --any step Lost, or any member Unobserved--> Incomplete
Incomplete --caller calls Close again--> Closing (failed steps only; same bounds)
Closed: terminal. All descriptors released.
```

### 7.2 Stop states (unchanged from v6)

```
Running --Stop--> StopKillP --Done(P)--> StatusWait --status or 1 s--> StopKillI --Done(I)--> Stopped
Lost at T1 or T3 --> StopFailed --caller must Close--> Closing
```

### 7.3 Failure matrix (restated)

| Failure point | Before P exists | After P exists | Action |
|---|---|---|---|
| H0 not ready | yes | no | Closing (CL0 or CL1, then the full ladder) |
| L fails to start | yes | no | Closing |
| Init record missing or malformed | yes | no | Closing |
| Init admission (checks 1 to 4) fails | yes | no | Closing (CL2 to CL4: I, H0 and L) |
| Refused by I (R3) | yes | no | Closing. Channel EOF before init. L exits 2 (E9). |
| Admission failure of any kind before P exists | yes | no | Closing: ErrCleanupIncomplete with Unobserved = [P] (D14, A41; Option Y, R5: I is also listed when L was started and pidfd(I) is not held). Open point O-CL7 (18.2 item 10). |
| Producer record missing or malformed | yes (I may have forked P) | unknown | Closing. P is Unobserved (D14). |
| Producer admission (checks 6 to 10) fails | no | yes | Closing |
| Status record before producer | yes | no | Closing (E10 line 59) |
| Zero-length record after producer (EOF rule, 3.2) | no | yes | Closing (class a). E10-R5 row producer_then_zero_length: CLOSE:empty. |
| Zero-length record after a valid status | no | yes | Closing (class a; full ladder, T-STATUS-POST (n)). |
| Truncated record before admission completes (CLOSE:trunc or CLOSE:ctrunc) | yes | no | Closing. |
| Admission receive budget exhausted (a ninth EINTR return, or 17 recvmsg calls) | yes | no | Closing (CLOSE:budget). Seam tests only (A50). |
| Observation error at T2 (drain recvmsg error, readiness poll error other than EINTR, POLLNVAL) | no | yes | ExitStatus Unknown. T3 runs. Stop returns an error wrapping ErrObservation, joined with any Lost. Seam tests only (A50). The T2 poll path is not in the R6 harness (T-T2-POLL). |
| Observation error at CL0a | no | yes | Closing. Close runs CL0 to CL7 and returns an error wrapping ErrObservation, never nil. Seam tests only (A50). |
| Observation error or overflow recorded earlier on the handle, then a later drain (sticky, R6) | no | yes | The later drain returns POISONED with zero recvmsg calls and accepts no status. Every later Stop or Close returns the sticky error and never nil. Seam tests only (R6 tests TestR6OverflowPoisonsLaterStatus and TestR6ReproObservationNotRestoredByLaterStatus). |
| V not 1 after producer (status candidate, class b) | no | yes | ExitStatus Unknown. No Closing. Not measured by E10-R5; decidePost and FuzzDecideOracle cover it. |
| Class (b) record read at the T2 continuation | no | yes | ExitStatus Unknown. T2 continues to EAGAIN, EOF, overflow or observation error. No Closing. |
| Status record malformed or with unknown kind, with exact creds and no descriptor, after producer | no | yes | ExitStatus Unknown. No Close (D15 class b). |
| Status record with a descriptor, MSG_TRUNC or MSG_CTRUNC, or with wrong or missing creds, after producer | no | yes | Closing (D15 class a). |
| Lost during Stop | no | yes | StopFailed; caller must Close |
| Lost during Close | any | any | Incomplete; failed-step descriptors retained (CL7) |

Each failure row is tested before P starts. Rows that can occur after P starts are also tested after P starts. Rows that cannot (R3 refusal, init admission, init record missing or malformed) are tested before P only. T06b (slice 6, mandatory before merge) asserts the outcome in 12.2.

### 7.4 Retry rule (unchanged)

- Close is idempotent. A second call repeats only the failed steps, with the same deadlines. A step that succeeded is not repeated, and CL0a is not repeated (A42). CL4 polls Done(L) before it signals (A41), so a repeated CL4 sends no signal to a member already Done.
- No internal retry loop. The caller decides how many times to call Close.
- Retained descriptors are the only state needed for retry. Nothing else is persisted.

---

## 8. Capture lease and post-read verification (unchanged)

### 8.1 Base behavior

- The base capture takes a read lease with F_SETLEASE(F_RDLCK) (contrib/frr-correlation/capture/capture_linux.go line 235). F_UNLCK releases it (line 241).
- finish() (line 374) rechecks: fstat identity, name-to-inode binding, F_GETLEASE == F_RDLCK, and the inbox listing. Then it seals and hashes the snapshot.
- Lease break time on this host is 45 s (fs.lease-break-time, E14).

### 8.2 Effect of PID namespacing

Leases are per inode, not per PID namespace. A writer in N is still a writer. v6.1 does not change lease semantics and makes no lease claim (D8).

### 8.3 Required test (Tier B, slice 8, not run)

A writer inside N opens the leased inbox for write during capture. Expected: finish() refuses Modified, or the write open is held until the lease is released or broken within the break time. The test records which occurs.

### 8.4 Lease tests named by reviewer C

T110 to T116 are reviewer C's proposed IDs. The review gives names, not file paths. The base tree at 153e7236 has no lease test file: `git ls-tree` matches "lease" only in .github/workflows/release.yml, .goreleaser.yaml and docs/release-notes-v2.md. They are proposals, not implemented tests.

---

## 9. Peer-write known gap and claims not made (unchanged)

- Base capture README row 2: "A producer cannot reach another producer's inbox: Not enforceable now. Needs per-producer mount and PID namespace confinement."
- v6.1 provides PID-namespace confinement only. It does not provide mount isolation. N shares the mount namespace with the host and with the other producers. A same-UID peer can still rewrite another inbox.
- Test TestKnownGapPeerProducerCanRewriteAnotherInbox (contrib/frr-correlation/capture/integration_linux_test.go:109) stays unchanged and must keep passing as a known gap (T117). It is not flipped by this design.
- Not claimed: mount isolation, authenticated evidence, closed peer-write gap, tamper-proof inbox, leased capture resisting in-namespace writers (D8).

---

## 10. Helpers, launcher and ENOMEM

### 10.1 Helper paths (restated; D7 and A20)

- unshare and nsenter are invoked by absolute path: /usr/bin/unshare and /usr/bin/nsenter.
- Procedure per helper: open the file, fstat the descriptor, verify it is a regular file, owned by root, not group- or world-writable. Then execute by that descriptor (execveat with AT_EMPTY_PATH on Linux). The verified object is the executed object. A missing or failing verification refuses launch with an error that names the helper.
- If execveat cannot be used on the platform, launch fails closed. No check-then-execute by path.
- Helpers run with a fixed environment. PATH is not consulted.
- The init is D's own executable, opened and verified by the same procedure.
- Gate T-HELPER (slice 4): the executed inode equals the verified inode, and a replaced path after verification does not change what runs.

### 10.2 Launcher (unchanged)

- L remains util-linux unshare (single fork). D does not call unshare(CLONE_NEWPID) itself.
- The same-binary launcher (N15 option b) is not adopted.

### 10.3 ENOMEM rule (unchanged, E4)

- Measured (v6 E4, 5 of 5): unshare(CLONE_NEWPID), child 1 exits, then a fork into the namespace returns ENOMEM. The same sequence with child 1 still alive: OK. No unshare: OK.
- Rule R-E1: no process forks into a PID namespace after its init has exited. The flat design never forks into N after I exits (S11).
- Rule R-E2: a launcher that unshares and then forks more than once is refused unless it is tested against R-E1.

### 10.4 nsenter shape (updated)

- The L launch line has nsenter with --user, --net and --preserve-credentials, and no --pid or --fork. Measured (E11): ppid(I) == pid(L) in 5 of 5 ok cases. The nsenter process D spawned is the parent of I, so this shape inserts no wrapper.
- If a wrapper ever appears, check 4 (ppid(I) == pid(L)) fails closed.
- Measured on util-linux 2.41.6 only.

---

## 11. Ponytail audit (carried from v6, not re-run)

The v6 audit (section 11 of contract-v6.md) stands. Its cut list is not changed by v6.1.

---

## 12. Tests and evidence

### 12.1 Measured results

Case names in E9 are variant_fix_exec_refuse. Variants: ok (bounding drop), inh (inheritable bit 19), amb (ambient bit 19), nobnd (no bounding drop). Fix: none (no FD_CLOEXEC) or cloexec (FD_CLOEXEC on I's copy before the fork of P). Exec: 1 (P exec'd) or 0 (fork only). Refuse: 1 (R3 on) or 0 (R3 off, breach control).

v6 rows (carried verbatim from v6 12.1, v6 lines 584 to 596; the `v6` prefix marks origin). v6.1 corrections change no measurement: (C24) the E2 and E3 claims exclude P2, which was already a zombie before the trigger (0 to 0.1 ms); (C1) H0 is killed at 500 ms, so its exit is about 0.1 ms after its own KILL, not 500.1 ms after KILL (section 13.1, N1).

| ID | Case | Runs | Result |
|---|---|---|---|
| v6 E1 control_killI | KILL I, KILL H0 | 5 | All members exit within 1.6 ms of KILL I. H0 exit 0.1-0.2 ms. I and P reaped 0.8-1.5 ms. |
| v6 E1 killL | KILL L, KILL H0 | 5 | All members exit within 1.6 ms. L exit 0.1 ms. |
| v6 E1 stopL_killI | STOP L, KILL I, KILL H0 | 5 | L not Done after 4 s in 5 of 5. I zombie, not reaped while L is stopped. SIGKILL L: L exit 0.2 ms; I reaped 0.3 ms after it. |
| v6 E1 stopI_killI | STOP I, KILL I, KILL H0 | 5 | All members exit within 1.4 ms. No stuck member. |
| v6 E1 stopP_killI | STOP P, KILL I, KILL H0 | 5 | All members exit within 1.3 ms. |
| v6 E1 stopL_killH0_then_I | STOP L, KILL H0, KILL I at 2 s | 5 | P, G and I exit 2000.8-2001.5 ms (after the delayed I kill). H0 exit 0.1-0.2 ms. L not Done until SIGKILL in 5 of 5. SIGKILL L: L exit 0.2 ms, I reaped 0.3-0.4 ms after it. |
| v6 E2 T-F5 | STOP L, KILL I, CONT L and KILL H0 at 0.5 s | 5 | Every member observed: P, G, P2 exit within 1.8 ms of KILL I. H0 and L exit at 500.1-500.2 ms (after CONT). I reaped by L at 500 ms. No fallback SIGKILL needed (not_exited empty in 5 of 5). |
| v6 E3 T-F5_zombieP | as E2, with producer P exiting into a zombie under I | 5 | P exit 0-0.1 ms (zombie). G exit 0.8-1.2 ms. H0 and L at 500 ms. I reaped at 500 ms. No fallback needed. |
| v6 E4 ENOMEM | control / exit_then_fork / sleep_then_fork | 5 each | OK / ENOMEM / OK. |
| v6 E5 ptrace | five variants | 5 each | Section 4.2. |
| v6 E6 RLIMIT | chain and tree | 5 repeats and singles | Section 5.1. |
| v6 E7 unshare exit | exit 3, TERM, KILL, exit 0 | 3 x 4 | Exit 3 gives 3. TERM and KILL give 0. exit 0 gives 0. |
| v6 E8 admission substitute | foreign PID 1 sharing H0 net ns | 5 | Matches its own children namespace; does not match L's. Rejected. |

v6.1 rows (new):

| ID | Case | Runs | Result | Location |
|---|---|---|---|---|
| E9 channel exclusion | ok_none_exec1_refuse1 (no FD_CLOEXEC) | 5 | Channel in P 5 of 5. pidfd(I) in P 0 of 5. pidfd_open(1) in P OK 5 of 5. | out/evidence61_v61.txt line 3 |
| E9 channel exclusion | ok_cloexec_exec1_refuse1 (rule applied) | 5 | Channel in P 0 of 5. pidfd(I) in P 0 of 5. CapPrm19 0. Attach EPERM 5 of 5. | line 4 |
| E9 fork without exec | ok_cloexec_exec0_refuse1 | 5 | Channel in P 5 of 5. pidfd(I) in P 5 of 5. CapPrm19 1 in 5 of 5. Attach OK 5 of 5. | line 5 |
| E9 refusal | inh, amb, nobnd, refuse1 | 5 each | refused_before_init 5 of 5 each. P never runs. L exit 2. | lines 6 to 8 |
| E9 breach controls | inh, amb, nobnd, refuse0 | 5 each | CapPrm19 1 in 5 of 5. Attach OK 5 of 5. Formula match 5 of 5. | lines 9 to 11 |
| E9 formula | permitted bit 19 = inh19 or bnd19 or amb19 | 5 per exec variant | 5 of 5 in each exec variant | column formula_match |
| E9 P fd set | non-stdio fds after exec | per case | cloexec cases: only a Python memfd (cloexec true). fork-only: channel and pidfd(I). | lines 13 to 27 |
| E10 framing | 23 cases (decision table, go1.27.3) | 23 | 23 cases recorded: 23 of 23 on kernel facts. Under D15 (final), 21 of 23 match at the action level (the label suffix is a harness label, not D15 evidence). The two superseded cases (status_with_fd_after_producer, duplicate_producer; lines 60 and 62, and line 75 by descriptor count) were rerun in this round with the D15 labels and FAIL on the label (E10-R2). | lines 41 to 66, 68 to 81 |
| E10 flags | MSG_TRUNC 0x20, MSG_CTRUNC 0x8, MSG_CMSG_CLOEXEC 0x40000000 | records | walk and parse counts agree on every record | line 68 onward |
| E10-R2 | status_with_fd_after_producer and duplicate_producer with the D15 labels (this round, go1.27.3, FRAME61_CASES filter) | 1 each | Both FAIL on the label: CLOSE expected, UNKNOWN observed. fd 7 before and 7 after. Pipe EOF 1 of 1 (first case). | out/frame-rerun-d15 |
| E10-R5 | Full E10 on the R5 build: fresh build from source sha 917f42b8 (binary sha 334717de, built in the scratch build directory with go1.27.3 and CGO_ENABLED=0; the hash depends on the build path), no FRAME61_CASES filter, 1000 iterations of 47 rows. Measures receiveOne (admission framing) only; the drain, overflow, observation error and V not 1 paths are not exercised. | 47000 rows | 0 wrong labels; 0 failing iterations; 0 wrong fields; poll EINTR 3 (absorbed inside the deadline); recv EINTR 0; recv EAGAIN 0; recvmsg calls 114000. | out/frame-rerun-r5 |
| E10-R6 | Full E10 on the R6 build: frame61 R6 sources, binary sha prefix 6acb8e75737e0d37 (build-path dependent; go1.27.3, CGO_ENABLED=0). 47 rows, one run, no FRAME61_CASES filter. | 47 rows | 0 differences from the E10-R5 labels in 47 rows (SUMMARY pass=47 total=47). Label, fd, pipe-EOF and receive-counter evidence only; the R6 drain fixes are not in this matrix. | out/frame-rerun-r6 |
| E10-R5-REP | Repeated E10 on the supplementary root build (sha e6685f56; source not recorded): three runs of 1000 iterations, the first two made by driver runs that were then aborted after their E10 phases completed. Totals with E10-R5: 4000 iterations. | 141000 rows (root build); 188000 rows (all) | 0 wrong labels; 0 failing iterations. Poll EINTR 17 in total across the four runs (root 4, 8 and 2; fresh 3), absorbed; recv EINTR 0 in every run. Rule of three: 0.3% per iteration at n = 1000 and 0.075% at n = 4000. | out/frame-rerun-r5 |
| R5 control | R4 binary (sha 1f207190) under the same driver: 500 iterations in each of four driver runs (2000 iterations). | 2000 iterations | 42 first-attempt failing iterations (10, 10, 9, 13), 2.1%. Iteration 0414 failed more than once. Cause inferred (EINTR in the blocking receive), not measured: the R4 binary reports no counters. The two aborted runs list 10 failing iterations as never passing because no retry ran after the abort, not because the failures persisted. File counts 527 and 539 exceed 500 iterations; not reconciled in this round. | out/frame-rerun-r5 |
| E11 sender and ppid | 6 checks, ok cases | 5 each | 5 of 5 each. Refused cases have no records (refused before init). | lines 29 to 39 |
| E12 per-thread drop | go1.27.3, LockOSThread, drop, fork from same thread | 5 | Dropped thread and child 000001fffff7ffff. Undropped threads 000001ffffffffff. | out/gocaps/run1 to run5 |
| E13 plain shell | same oracle outside a user namespace | 5 | Drop refused with EPERM. Every thread shows 000001ffffffffff (no drop). | out/gocaps/plain_shell_negative/ |
| RB-P6 supervisor death | Python chain, Pdeathsig on L through nsenter | 1 per mode | L and I dead within 0.1 s of creator death. Control without Pdeathsig: no tie. | reviewer B |
| RC-Y1 SIGTERM and SIGKILL to L | Python chain | 5 each | SIGKILL: all ended within 3 s. SIGTERM: none ended within 3 s. | reviewer C |
| RB61-P4 and RB61-P5 | Reviewer B probes of this round: pidfd_getfd and /proc fd reads from P; a forged record in the breach control | 5 each | Reviewer B (this round). Not re-run. Not in the bundle. |

Timing caveat: one host, one kernel, 5 runs per case. The deadlines are design constants, not measured bounds.

### 12.2 Gates (restated, with tiers)

Tier definitions:

- Tier A: scratch evidence required before implementation starts. A Tier A gate may use scratch programs. It does not require production code.
- Tier B: production tests required before the merge of the slice that introduces the code. Not required before the code exists. Every Tier B test is NOT RUN unless its row says otherwise. A scratch run of a Tier B test is not a production run.
- Tier C: deferred. Recorded as residual risk. Not required for slices 0 to 7. Required before any claim that depends on it.

Tier A (start blockers and their scratch status):

| Gate | Test | Status | Evidence |
|---|---|---|---|
| T-N8 channel exclusion, control 1 | P's non-stdio fds after exec hold no channel and no pidfd(I). Negative control: fork without exec leaks. Control 2 is T-GETFD (Tier B, slice 3). | PASS (scratch, 5 of 5). Not re-run in R2. | E9 lines 3 to 5 |
| T-CAP-INH refusal | Forced inheritable bit 19, ambient bit 19, and no bounding drop each refused before init | PASS (scratch, 5 of 5 each). Not re-run in R2. | E9 lines 6 to 8. Breach controls lines 9 to 11. |
| T32 count rule (Go framing) | Required fd count enforced; two fds rejected at 64 bytes; CTRUNC at 56 and 64 with more fds; kernel closes undelivered fds | PASS (scratch Go, go1.27.3, 23 of 23 cases). Its count-rule rows do not include the two superseded labels. | E10 lines 43 to 52 |
| T-ADM-FRAMING | Extra fd, CTRUNC, TRUNC, wrong type, duplicate, status with fd, missing creds: each case decided as section 3.4 states (CLOSE or UNKNOWN) | LABEL-LEVEL PASS on the R6 build (E10-R6, 47 rows, one run; the 33-row E10-R4 run is history). Earlier, on the R2 build, 21 of 23 matched D15 and the two superseded labels failed (E10-R2) and then passed on classification (E10-R3). Kernel facts PASS (23 of 23 cases: fd counts, EOF, record counts). status_with_fd_after_producer and duplicate_producer expect CLOSE under D15 and recorded UNKNOWN (E10 lines 60 and 62). The R2 rerun FAILED both on the label (E10-R2). The R3 rerun PASSES both on actual classification (E10-R3). The full E10 was rerun on the R4 build (E10-R4) and passed on labels. E10 label acceptance is MET for draft-start readiness only (R6-1). E10-R5 (fresh build, 47 rows, 1000 iterations) also passed on labels with 0 failing iterations; it covers admission framing only (12.1). E10-R6 (R6 build, 47 rows) matched the E10-R5 labels in every row (admission framing only). Production T-ADM-FRAMING remains a merge gate: slice 1. | E10 lines 43 to 66, 68 to 81; out/frame-rerun-d15 |
| T-PTRACE-GO per-thread oracle | Drop on the locked forking thread; fork from it; control threads keep bit 19; control outside user namespace | PASS (scratch Go, go1.27.3, 5 of 5). Not re-run in R2. | E12, E13 |
| R5 seam and fuzz tests (scratch) | receive_test.go (20 Test functions: receive without blocking, receive deadline, EINTR budget of 8, poll EINTR inside the deadline, call cap of 17, EAGAIN after a readable poll, zero-length records in the drain, status then zero-length, drain EINTR budget, drain call ceiling, T2 Known only for one clean status) and fuzz_test.go (2 Test and 2 Fuzz functions: FuzzDecideOracle, FuzzParseWireAgreement, TestAcceptPathsWithInjectedIdentity, TestParseWireEscapedNames). Not production code. | Superseded for current counts by the R6 row below. The R5 files PASS: 59 unit PASS lines; FuzzDecideOracle 418108 execs and FuzzParseWireAgreement 274743 execs, 10 s each; TestParseWireEscapedNames PASS. Excluded fuzz inputs: count NOT RECORDED (18.2 item 20). The generated differential oracle (150 seeds) is NOT RUN; it encodes the R4 grammar and must be ported (18.2 item 19). | out/frame-r5-tests/ |
| R6 corrective-pass tests (scratch): receive_test.go (20 Test functions, adapted to the R6 drain API), repro_test.go (TestMain and four TestR6Repro tests), r6_test.go (seven TestR6 tests: DrainKeepsMetadataAndClosesFds, OverflowPoisonsLaterStatus, ObservationErrorWrapsAndPoisons, EINTROverflowIsProtocolViolation, PostStatusErrorIsNotKnown, StatusGateSameForDecideAndT2, IntegerGrammarMatchesRefParse), and fuzz_test.go (R6 changes: the generator sets r.nfds, the count the drain now keeps; refParse rejects -0 for v and value, as 3.2 requires). Unit: 35 top-level PASS, 70 PASS lines including subtests, 0 FAIL. Red on the R5 sources: 4 FAIL (TestR6ReproDrainStatusWithFdIsNotKnown, TestR6ReproDrainTruncatedStatusIsNotKnown, TestR6ReproObservationNotRestoredByLaterStatus, TestR6ReproReadContinuesAfterObservation). Mutation A (the fd-count case removed from the shared status gate) and mutation B (the -0 rejection removed) are caught. Fuzz: FuzzDecideOracle and FuzzParseWireAgreement at -fuzztime=10s; last progress lines of the final run 263539 and 146326 execs; PASS. The red run used the R5 main.go, the R5 receive_test.go and an R5-signature repro_test.go (sha256 18c94c05...); its test bodies differ from the final repro_test.go only in call signatures. Excluded fuzz input count NOT RECORDED. The generated differential oracle (150 seeds) is NOT RUN (18.2 item 19). TestR6ReproReadContinuesAfterObservation shows that no record is classified after an observation error; it does not show Known restoration, which the runCase harness cannot reach (each step is a new sender process). | Scratch PASS (harness only; not production evidence; not counted in the Tier A count). | out/frame-r6-tests/ |
| T-PTRACE (Python chain) | Attach EPERM with drop, OK in breach controls | PASS (scratch, 5 of 5). Not re-run in R2. | E9 attach column |

Tier A count: 6 gates. T-N8, T-CAP-INH, T32, T-PTRACE-GO and T-PTRACE: PASS on scratch evidence (not re-run in R2). T-ADM-FRAMING: label-level PASS on the R6 build (E10-R6, above); E10 label acceptance is MET for draft-start readiness only (R6-1). Implementation may start only when the conditions of 17.1 hold. The R5 and R6 seam, fuzz and red/green rows are scratch evidence and are not counted here, and neither is TestR6FinalUnknownIsFrozen. The 47-row matrix does not call commitExit.

Tier B (production, before merge of the named slice):

| Gate | Test | Slice | Notes |
|---|---|---|---|
| T-N8 production | Go producer lists its non-stdio fds after exec; channel and pidfd(I) absent; fork-only negative test present (S21) | 3 | Replaces the scratch harness. Control 1. |
| T-CAP-INH production | Launch refused by I on inh, amb, nobnd; P never runs | 3 | |
| T-PTRACE production | P attach to I EPERM 5 of 5; none control OK in the same run (S18); the same run also runs T-GETFD | 3 | Same-run condition open (18.2 item 5). |
| T-PTRACE drift guard | Name TestLaunchCapabilityDriftGuard. I's CapPrm and CapEff bit 19 = 1; I's CapBnd bit 19 = 0 after the drop; P's CapBnd and CapPrm bit 19 = 0; CapInh and CapAmb of I and P are 0. Asserted in the same run as the attach check. | 3 | R2, MB8, A38 |
| T-GETFD | Name TestProducerCannotReachChannelByGetfdOrProcFd. Setup: launch as in slice 3. The test passes P the channel fd number and I's host pid (test only). P calls pidfd_getfd(pidfd_open(1), channel fd number) and readlink on /proc/<I host pid>/fd/<channel fd number>. Assert: getfd fails with EPERM and readlink fails with EACCES, 5 runs. Control in the same run, with the bounding drop absent (breach control, not production): both succeed and the returned fd has the channel inode. | 3 | MB1, SB3, A36. Basis RB61-P4 (not re-run). |
| T-HOST-REACH-D | Name TestProducerCannotReachSupervisor. P in N attempts ptrace attach, pidfd_getfd and readlink on /proc/<D host pid>/fd against D (host user namespace). Assert: all refused (EPERM or EACCES). Control: the same three probes from the test process against its own same-uid child, in the same user namespace, must succeed. 5 runs. | 3 | MB7. The protection is the same-user-namespace condition (4.2), not R1. Not measured. |
| T-PTRACE-GO production | Attach EPERM 5 of 5 with the drop on the forking thread; assertion refuses a fork from an undropped thread | 3 | D10 |
| T-SIG-INIT | P sends SIGTERM, SIGHUP, SIGINT and SIGKILL to PID 1 (I). I survives or the result is Unknown. Never Known (S22). Five runs per signal. | 3 | Depends on Go init handler set. Python init would not test it. |
| T32 (Go name TestChannelRejectsWrongDescriptorCount) | Production receive path, 0 to 5 fds, both buffer sizes, count rule | 1 | Production version of the Tier A framing test |
| T-DRAIN-UNIT | Name TestChannelDrainCapAndOverflow. Socketpair with the integration tag; every receive uses MSG_DONTWAIT. Cases: (a) eight records then EAGAIN: clean; (b) nine records, counted and not classified: overflow at the ninth record, no status accepted, ErrProtocolViolation at the drain boundary; (c) empty queue: EAGAIN at once, within the test deadline, with no added wait; (d) EOF: clean; (e) eight EINTR returns then EAGAIN: clean; (f) nine EINTR returns: overflow; (g) received fds closed at once. (h) to (k) (R5): (h) zero-length record with creds: a record, class (a), CLOSE:empty, not EOF; (i) zero-length record without creds: a record, rejected for missing creds; (j) truncated record: counted toward the eight, class (a); (k) recvmsg error seam: ErrObservation, no status accepted. (m) to (q) (R6): (m) a status with a descriptor, and a truncated status, read in a drain: not Known, with the descriptor count and flags kept through classification and the descriptor closed (TestR6DrainKeepsMetadataAndClosesFds; TestR6ReproDrainStatusWithFdIsNotKnown; TestR6ReproDrainTruncatedStatusIsNotKnown); (n) after an overflow, a later valid status is not accepted and a later drain returns POISONED with zero recvmsg calls (TestR6OverflowPoisonsLaterStatus); (o) a recvmsg error wraps ErrObservation, poisons the drain state, and a later valid status is not Known (TestR6ObservationErrorWrapsAndPoisons; TestR6ReproObservationNotRestoredByLaterStatus); (p) a ninth EINTR return in one drain is ErrProtocolViolation (TestR6EINTROverflowIsProtocolViolation); (q) a valid status, then an observation error: ExitStatus Unknown (TestR6PostStatusErrorIsNotKnown). Case (l) (POLLNVAL) moved to T-T2-POLL, because the readiness poll is not part of the drain. EINTR cases replace the receive call with a test seam (no real signal). Mandatory before slice 1 merge. One deterministic run per case, 5 runs for case (c). Not run. | 1 | A40, SB7, R3-1, R3-2; R5 D-C, D-E, D-G; R6 bug 1 and bug 2 |
| T-T2-POLL | Name TestStopT2ReadinessPoll. Seam at the T2 readiness wait: (a) POLLNVAL: ErrObservation, T3 runs, Stop returns an error wrapping ErrObservation, no status accepted; (b) a poll error other than EINTR: the same; (c) POLLIN, POLLHUP or POLLERR: readable, the drain runs; (d) EINTR within the 1 s readiness deadline: retried and not an observation error; (e) readiness timeout (no readable record within the 1 s deadline): ExitStatus Unknown, not a Stop error, so Stop returns nil when T1 and T3 succeed (6.3 T2). Not in the R6 harness. Mandatory before slice 5 merge. 5 runs. Not run. | 5 | R6 (correction pass); moved from T-DRAIN-UNIT (l) |
| T-CL7-RELEASE | Name TestCloseReleasesOnlyAfterCleanup. Production merge test, slice 5. Close releases the retained descriptors when CleanupComplete holds, even with a recorded drain overflow or observation error (CL7, R6-2). When CleanupComplete does not hold, no descriptor a retry needs is released. A later Close returns the retained sticky error, sends no signal, and uses no released descriptor. After a release every pidfd slot is marked invalid. Not run. | 5 | R6 final-2 (CL7 release rule, R6-2; 88ac K1) |
| T-CL6-JOIN | Name TestCloseJoinsWatchersWithOneDeadline. Production merge test, slice 5. One watcherJoinDeadline of 1 s is shared by all watchers (CL6). A watcher not joined by the deadline is Lost. Not run. | 5 | R6 final-2 (CL6) |
| TestCloseCommitIsFrozenAtCL0a | Name proposed in 88ac. Production merge test, slice 5. The value the first Close fixes at CL0a is the final ExitStatus (6.1, 6.4). A later Close, a later valid status and a later protocol violation return that value unchanged. Close side only; separate from T-FINAL-COMMIT, which covers admitted sequences. Not run. | 5 | 88ac K2 |
| TestCloseWatcherJoinSharesOneDeadline | Not a separate test. The 88ac case (two watchers that do not exit, joined by one CL6 call within one watcherJoinDeadline of 1 s) is T-CL6-JOIN above. | 5 | 88ac; merged into T-CL6-JOIN |
| T-FINAL-COMMIT | Name TestFinalCommitIsFrozen. Production merge test, slice 6; the admitted-sequence form of TestR6FinalUnknownIsFrozen (scratch); its Close-only freeze is TestCloseCommitIsFrozenAtCL0a, a separate test. A provisional T2 value with no record stays open for CL0a. A final UNKNOWN at CL0a is never KNOWN after a later valid status, a protocol violation, or poisoning. A final KNOWN is not changed by a later record. Not run. | 5 | R6 final-2 (6.1, CL0a) |
| T-ADM-FRAMING production | Full list of Tier A cases, in production code, with the D15 expectations (descriptor on a status record and duplicate producer: CLOSE), plus a case with 4 fds at 64 bytes, and the ten post-status rows of E10-R4 (names in out/frame-rerun-r4/summary.txt). The production set is the 47-row set of E10-R5 (passcred_readback_zero replaces init_no_passcred; section 12.1). Row init_escaped_type_name has a plain payload and is misnamed; disclosed, not renamed (18.2 item 21). Identity by an injected interface in slice 1 (no PIDFD_GET_INFO). init_pidfd_not_sender and producer_not_child move to slice 6. | 1 | MB14, R3-8, R3-10. Mandatory before slice 1 merge. One deterministic run per row. Not run. |
| T-A-ADM | Checks 1 to 3 positive for I; negative for H0, L, and a foreign init (E8 form); dev and ino comparison; fail closed on ENOTTY and EINVAL | 2 (rootless part); 6 (userns part) | C16 |
| T-ADM-PPID | Check 4 negative forms: producer pidfd sent as init rejected; sibling pidfd as producer rejected by creds (T-SENDER). Includes init_pidfd_not_sender and producer_not_child (moved from slice 1). | 6 | ADV-2 |
| T-SENDER | Name TestChannelSenderMustBeI. Records from non-I senders rejected by check 10: own pid, sibling pid, and L (pid(L) credentials; L holds the channel child end and sends a record that carries a pidfd(I)). I's records accepted. Covers senders that do not spoof pid(I); a spoofing holder is covered by T-GETFD (slice 3). 5 runs. | 6 | Positive form measured (E11). SB4. Sender-credential check is C25 (R4 decision 7). R5: a zero-length record from each non-I sender is rejected by check 10 (3.2 EOF rule). Mandatory before slice 6 merge. Not run. |
| T-ADM-ORDER | Name TestAdmissionOrder. Producer record before init, or init after producer: rejected. Status before producer: Close (CLOSE:early_status). Status with a descriptor before producer: Close. | 6 | |
| T06b | Name TestAdmissionFailureRunsFullClose. Setup: one run per row of 7.3 that can occur after P starts, before and after P exists (for example producer record rejected, producer record missing); one run per row that cannot (R3 refusal, init admission failure, init record missing or malformed), before P only. Trigger: the failure. Assert per run: Close returns ErrCleanupIncomplete, never nil, with Unobserved [P] in every row (pidfd(P) is never held in these rows; D14, A41, Option Y), and with I also listed in a row where L was started and pidfd(I) is not held (R5); Lost empty when no seam is armed; H0 reaped before Close returns; a second Close returns the same error and sends no signal; every valid descriptor held at the failure is retained, with the held pidfds and the channel parent end, and the retained set equals that set (CL7, R4 decision 6); any unexpected received descriptor in the run was closed at once (3.2); no descriptor is released before cleanup completes (CL7, R6). Mandatory before merge of slice 6. Run count: one run per row, and 5 runs for the rows with timing. Not run. | 6 | X4, MB6, review C D5 |
| T-STATUS-POST | Name TestStatusRulesAfterAdmission. Setup: an admitted handle from the production admission path; a test sender that holds a channel child end and is neither I nor P (its own pid as SCM_CREDENTIALS). Rows: (a) I's valid status alone: Known provisionally at T2 (6.1); the final value is fixed only at the first Close (CL0a), so this row asserts the provisional value. (b) I's status, then a second I status: Unknown, no Close; the aggregate ExitStatus is Unknown (6.3 T2). (c) malformed or unknown-kind I status, no descriptor, exact creds: Unknown, no Close. (d) I's status with a descriptor, with MSG_TRUNC or MSG_CTRUNC, or with the test sender's creds: Close. (e) the test sender's status, then I's status: Close (class a). (f) init or producer record after admission: Close. (g) after a valid status, a record that is not a status: Close, full ladder. (h) after a valid status, a status with a descriptor: Close, full ladder. (i) after a valid status, a truncated status: Close, full ladder. (j) after a valid status, a status with the test sender's creds: Close, full ladder. (k) after a valid status, an unparseable record whose type field does not decode to status: Close, full ladder. (l) a malformed status with exact creds, then a valid status: ExitStatus Unknown, no Close (both records class b). (m) after producer, a status candidate with V not 1, exact creds, no descriptor, not truncated: ExitStatus Unknown, no Close (class b). (n) after a valid status, a zero-length record: Close, full ladder (class a; 3.2 EOF rule). Assert the ExitStatus and the Close result per row (6.4). K3 (88ac): in rows (d) to (k) and (n) the final ExitStatus is Unknown, and the test asserts it after the first Close returns; provisional labels are kept apart from final ExitStatus assertions. Rows (d), (e), (f), (g), (h), (i), (j), (k) and (n) also assert the full ladder: H0 and L reaped; Done(I) and Done(P) observed; Lost and Unobserved as 6.4 states; CL7 retention; and the 26 s bound (6.4 testable bound). The E10 harness checks labels and fd counts only; it is not evidence of the full ladder. 5 runs for rows with timing. Mandatory before slice 6 merge. Not run. | 6 | MB5, reviewer C reason 7, R4 decision 8. Pre-admission status rows are in T-ADM-ORDER. |
| T-DRAIN-STATUS | Name TestDrainStatusNeedsNoOtherRecord. Admitted handle (slice 6 admission). (a) I sends a valid status and then eight more valid status records (nine records in total, all class b): ExitStatus Unknown (overflow), and Stop returns an error wrapping ErrProtocolViolation (asserted, not only the status). (b) Moved to T-DRAIN-FLOOD (b), the Close-entry overflow case. (c) A valid status alone, then EAGAIN: Known provisionally at T2; the final value is fixed at the first Close (6.1). Mandatory before slice 6 merge. 5 runs. Not run. The Close-entry overflow case is in T-DRAIN-FLOOD (b). | 6 | A40, MB2, R3-3, R3-4, R3-9 |
| T-STOP-KNOWN | Name TestStopKnownNeedsStatusAlone. Stop with the status record first and alone: ExitStatus Known (provisional, T2); Done(P) and Done(I). The first Close after that Stop reads nothing at CL0a (EAGAIN), so the committed value stays Known (6.1). Mandatory before slice 6 merge. Not run. | 6 | Moved from T-STOP. |
| T-NO-BYPASS | Merge assertion: no exported path reaches Running without checks 1 to 10. Slice 5: the test-only constructor for lifecycle handles lives in _test.go files only; a merge check finds no call to it outside _test.go files. Slice 6: a test calls every exported constructor and asserts that each substitute of 3.3 is refused. | 5 and 6 | Reviewer C item 13 |
| T-DONE | Never-exiting member for each of P, I, H0, L: Lost at deadline; no hang. 5 runs. | 5 | |
| T-WATCH | Watcher cancel and join within 1 s with a stopped member. Result Cancelled (6.6). Named test T07 below. 5 runs. | 5 | D16 |
| T07 | Name TestWatcherCancelJoinsWithinDeadline. Setup: one watcher on the pidfd of a child stopped by pidfd_send_signal(SIGSTOP), not exited, and a cancel pipe. Action: close the cancel pipe write end (6.6). Assert: with a 5 s watcher deadline, the watcher returns Cancelled within one poll slice (100 ms) of the close, and never Deadline; join completes within watcherJoinDeadline = 1 s (CL6); no watcher is reported Lost. Cleanup: SIGKILL the stopped child through its pidfd, then reap it. Repeat 5 runs. | 5 | Mandatory before slice 5 merge. 5 runs. Not run. |
| T08 | Name TestCloseRetryRepeatsOnlyFailedSteps, three subtests (a), (b) and (c). A test-only seam replaces the result of exactly one wait with timeout; the real wait and any real signal still happen; a test-only counter records every signal Close sends. (a) negative_pidfd_I_missing: pidfd(I) and pidfd(P) not held; the seam is on the CL4 wait. First Close: ErrCleanupIncomplete with Lost = [L] and Unobserved = [I, P] (Option Y, R5); releases no descriptor. The seam is disarmed. Second Close: ErrCleanupIncomplete with Unobserved = [I, P] and Lost empty; zero signals (CL4 polls Done(L) first). (b) positive_all_held (control): all four pidfds held; the seam is on the CL3 wait. First Close: ErrCleanupIncomplete with Lost = [L]; CL4 then runs by its rule. The seam is disarmed. Second Close: nil; zero signals; every descriptor released. (c) R6, W3 variant: pidfd(H0), pidfd(L) and pidfd(P) held, pidfd(I) not held; the seam is on the W3 wait after CL4. First Close: ErrCleanupIncomplete with Lost = [P] and Unobserved = [I] (L started, pidfd(I) not held); no descriptor released. The seam is disarmed. Second Close: ErrCleanupIncomplete with Unobserved = [I] and Lost empty; zero signals to a member already Done. Repeat 5 runs each. | 5 | Y9, reviewer C reason 1 (item 8). Mandatory before slice 5 merge. Run count: 5 runs per subtest (15 runs, with subtest (c)). Not run. |
| T-CLOSE-BOUND | Name TestCloseIsBoundedWhenEveryWaitWedges. A test seam wedges one wait per run: W1 Done(H0), W2 Done(I), W4 Done(L) at CL3, W5 Done(L) after SIGKILL at CL4, W3 Done(P) after CL4 in every branch (R6), and W6 the joint watcher join (the six waits of 6.4); the real wait still happens. An empty-queue CL0a case adds no wait (R3-1). Assert per run: Close returns within 26 s (6.4); it returns ErrCleanupIncomplete with Lost and Unobserved as the failed steps require; it releases no descriptor a retry needs (CL7); a second Close repeats only the failed steps and sends no signal to a member already Done. Production constants, not widened (17.4). | 5 | R3 (request 88ac, item 3), R3-1, D9. Mandatory before slice 5 merge. Run count: 5 runs per wedged wait (six waits, 30 runs) and 5 runs for the empty-queue case. Not run. |
| T-CL0 | Name TestCloseWithoutHolderPidfdSignalsNoNumber. Setup: a launch in the slice 5 test form. Four subcases: (i) pidfd(H0) discarded before Close; pidfd(I), pidfd(L) and pidfd(P) held. (ii) As (i), and pidfd(P) also not held. (iii) pidfd(L) discarded before Close; pidfd(H0), pidfd(I) and pidfd(P) held. (iv) pidfd(I) discarded before Close; pidfd(H0), pidfd(L) and pidfd(P) held. Trigger: Close. Assert per subcase: Close returns ErrCleanupIncomplete, never nil; the listed members are H0 in (i) and (ii), P in (ii), L in (iii) and I in (iv), and no other member is listed; a test-only counter records zero PID-number and zero group signals; every held member reaches Done or Reaped through its own pidfd, within killDeadline (CL1 to CL5); P is waited on after CL4 (W3, R6) when its pidfd is held; no descriptor is released (CL7, Unobserved not empty); a second Close repeats only the failed steps and sends no signal to a member already Done. Mandatory before slice 5 merge. 5 runs per subcase. Not run. | 5 | R3-6, D4 (review C), R4 decision 5; R6 final (2) |
| T-ZAP-ORDER | Name TestZapOrderMembersDoneAfterInit. Slice 5, mandatory pre-merge gate (D4), Tier B. Setup: a launch with I, P and G in N, built by the test-only constructor of slice 5 (_test.go only), not by slice 6 admission (R4 decision 10). The test then closes D's copy of pidfd(P), so Close sees pidfd(P) not held (the D14 branch). P opens pidfd(G) on its own child G and pidfd(P) on itself (pidfd_open of its own pid), and sends both to the test through a test-only socketpair, separate from the production channel, with SCM_RIGHTS. Trigger: pidfd_send_signal(pidfd(I), SIGKILL). Assert: Done(I) observed within killDeadline; then on every run a zero-timeout poll reports POLLIN on the test's pidfd(G) and pidfd(P). 5 runs, every run counted. Passing changes no Close rule (D14). | 5 | D4. Reviewer C reason 2, item 10, D8. Mandatory before slice 5 merge (D4). 5 runs, every run counted. Not run. |
| T-CLOSE-LIVE | Real Close: live P, zombie P, no pidfd(P) (Unobserved P), H0 and L reaped by D. No pidfd(I): SIGKILL L path (CL4), no SIGTERM. | 5 | Y1, D14 |
| T-STOP | Slice 5, no-status legs. Name TestStopMembersDone. Stop with live and zombie P: Done(P) and Done(I) within deadlines; ExitStatus Unknown when no status arrives. The Known leg is T-STOP-KNOWN (slice 6). | 5 | |
| T-REENTRY | Name TestStopAfterCloseStartsSendsNoSignal. A test seam pauses Close at entry (CL0a). Stop is called while Close runs: Stop returns an error and the test-only signal counter does not change. The seam is released and Close completes. 5 runs. | 5 | RB-F12, MB3 |
| T-DRAIN-FLOOD | Name TestStopDrainOverflowIsUnknown. A test-only I floods valid repeated status records, all class b (constructed handle, slice 5, _test.go only). (a) Stop while Running: T2 accepts at most 8 records and makes at most 17 recvmsg calls; the ninth record is overflow; T3 runs and Done(I) is observed; Stop returns an error wrapping ErrProtocolViolation even though T3 succeeded; ExitStatus Unknown; memory stays bounded. (b) Close entry: the flood is read at CL0a. Run 1: a wedged wait makes cleanup incomplete; Close returns an error wrapping ErrProtocolViolation joined with ErrCleanupIncomplete, never nil, and the overflow record is retained. Run 2 (retry, no wedge): cleanup completes; Close still returns an error wrapping ErrProtocolViolation, never nil. Run 2 asserts that the descriptors are released when cleanup completes (CleanupComplete, R6), and that the returned error stays the sticky ErrProtocolViolation. Run 3 (R6): a further Close returns the same sticky error, sends no signal and uses no released descriptor. Close returns within the Close bound (26 s) in each run. Mandatory before slice 5 merge. 5 runs per case. Not run. | 5 | MB2, A40, R3-3, R3-4 |
| T-CTX | Name TestStartContextRunsCloseBeforeLeader. (a) ctx cancelled before S3: Start returns an error that wraps context.Canceled and Close's result, with Unobserved [P] (D14); H0 is not started, so it is not listed (Option Y, A41). (b) ctx cancelled after H0 is ready and before pidfd(L) exists (seam pause at the S4 wait): Close runs; H0 is reaped before return. Assert: the error matches ctx.Err(); Close returns ErrCleanupIncomplete or nil per 6.4. 5 runs. | 5 | D17, MB4 |
| T-HOLDER | Production holder H0 teardown matches the E2 result | 4 | Base holder, D6 |
| T-DEATH | Supervisor death through the real Go launcher: L, I and P gone within deadline. 5 runs. Control without the tie: survivors recorded. Creator-thread exit case: the locked creator goroutine returns while its thread is locked, which ends the thread; Pdeathsig then kills L, and I dies with L (unshare --kill-child). L and I are dead within the deadline. The case shows why the creator thread must stay alive for L's lifetime (6.2 S5). | 4 | F3, D5, MB9 |
| T-ORPHAN | Name TestOrphanInitIsReapedAfterLeaderKill. Setup: launch to Running with pidfd(I) held. Trigger: SIGKILL to L through pidfd(L), so that I is reparented. Assert: pidfd_send_signal(pidfd(I), 0) polled until it returns ESRCH, within killDeadline, which shows I was reaped by the host reaper. No PID number and no command-line match is used. If no reaper exists on the CI image, the test fails and D3 is decided again. 5 runs. | 4 | D3, MB10 |
| T-HELPER | Executed inode equals verified inode; replaced path after verification does not change what runs | 4 | D7 |
| T-HOLDER-KILL-GROUP-ABSENT | grep and test that release() has no killGroup and no PID-number signal (S9) | 4 | F7, F11 |
| T-RL-AGG | Two producers and D under one uid budget; D's fork fails when producers consume it; bounded loops | 7 | Blocked by D2, D12 |
| T-LAUNCH-LIMIT | Launch under low inherited RLIMIT fails with EAGAIN before the producer runs; D must not lower RLIMIT before H0 (S17) | 7 | RC-Y5 |
| T-F6b | Real producer under RLIMIT_NPROC, bounded fork loop reaches EAGAIN and stops | 7 | Blocked by D2, D12 |
| T-LEASE | Writer inside N against a leased inbox during capture: refusal or held open, recorded | 8 | D8. Not a blocker for slices 0 to 7. |
| T-HOST-REACH | Host metadata read matrix on the CI image: same-uid rows; cross-uid rows are Tier C | 8 | D11 |
| T120 | CI prints kernel, util-linux, Yama scope and uid before any ptrace or namespace test runs | 2 | Reviewer C item 15 |
| T117 | TestKnownGapPeerProducerCanRewriteAnotherInbox still passes as a known gap | every slice | S8 |

Tier C (deferred, residual risk):

| Gate | Test | Why deferred |
|---|---|---|
| T-NONROOT | Non-root D and producer (N16, ADV-6, P6) | Requires a new uid mapping. Not a test-only change. |
| T-KERNEL-FLOOR | Ioctls 0xff04, 0xff05, 0xff06, 0xff09 and PIDFD_GET_INFO on a kernel below 7.2 (base comment says 6.11) | Needs an older kernel. Fail-closed behavior on ENOTTY and EINVAL is tested in slice 2 (Tier B). |
| T-HOST-REACH cross-uid rows | Metadata of other-uid host processes (predicted visible) | Needs a second uid |
| E4 exit_no_wait mode | Defined in the probe, not run | Not needed by the design |
| v5 matrix rows not listed here | Kept as NOT RUN | Reviewer C acceptance matrix maps them |

### 12.3 Verify-and-stop

Section 18.

---

## 13. Disposition tables

Values: RESOLVED (text changed and evidence or gate named), RESOLVED-SCRATCH (scratch evidence in v6.1, production gate open), OPEN (decision or gate open), CARRIED (unchanged, named owner), WITHDRAWN.

### 13.1 Reviewer B N1 to N17

| ID | Finding (short) | v6.1 disposition | Section and evidence or gate |
|---|---|---|---|
| N1 | Flat has no H0 kill; wrong wording of H0 exit | RESOLVED (C1): H0 exits about 0.1 ms after KILL H0 at 500 ms, not 500.1 ms after KILL. | 6.4 CL0 and CL1. 12.1 header note. v6 E1 control. |
| N2 | Done undefined; waitid blocks | RESOLVED. Gate open. | 6.1 poll with deadline. T-DONE slice 5. |
| N3 | Close with live producer unmeasured (MEASURED-PARTIAL) | MEASURED-PARTIAL (C2). Close function not run. | v6 E2 and E3 cover kernel teardown only. T-CLOSE-LIVE slice 5. |
| N4 | Stopped C not covered | RESOLVED by topology | 1.2 |
| N5 | R1 omits inheritable and ambient | RESOLVED-SCRATCH | 4.1 R3 and formula. E9 refusal rows. T-CAP-INH production slice 3. |
| N6 | RLIMIT_NPROC lets producer exhaust uid budget | OPEN (D2, D12) | 5.3 P1, P1a, P5. Slice 7 blocked. |
| N7 | Admission lacks PID-ns identity; floor unstated | RESOLVED-SCRATCH for foreign init (v6 E8) and positive checks (E11). Producer-as-init negative form open. | 3.3 checks 1 to 10. T-A-ADM and T-ADM-PPID slices 2 and 6. Floor: T-KERNEL-FLOOR (Tier C). |
| N8 | Channel inheritance and framing incomplete | RESOLVED-SCRATCH (E9, E10). Production open. | 3.2, 3.5. T-N8 slice 3. T-ADM-FRAMING slice 1. |
| N9 | I reparented to host reaper if L dies first | CARRIED (D3) | 2.3, 6.4 |
| N10 | Stop no longer sweeps producer descendants | RESOLVED (D4) | 6.3, 6.5. Status rule A11. |
| N11 | Owner notice in 0.3 open | CARRIED (D9). The notice changed from the carried text (0.3 change record). Maintainer action. | 0.3 |
| N12 | Watcher join and cancellation unbounded | RESOLVED. Gate open. | 6.6, CL6. T-WATCH slice 5. |
| N13 | Step ambiguity in Close | RESOLVED | 6.4: every step attempted, deadlines named |
| N14 | Release rule for pidfd(I) inconsistent | RESOLVED | 2.2 and CL7 (single rule) |
| N15 | Helpers resolved through PATH | RESOLVED. Gate open. | 10.1 (open-verify-exec by descriptor). T-HELPER slice 4. |
| N16 | Start and Close take no context | RESOLVED (D17) | 6.2 |
| N17 | Environment, arch, lease coverage missing | PARTIAL: environment RESOLVED (0.5, E14); lease test OPEN (T-LEASE slice 8, D8) | 0.5, 8.3 |

### 13.2 Reviewer B ADV-1 to ADV-6 (ADV IDs as recorded in the review)

| ID | Item | v6.1 disposition | Section and evidence or gate |
|---|---|---|---|
| ADV-1 | Contradiction on ExitStatus (3.2, 3.4, 6.1). Close nil with no pidfd(P). Review: NOT FIXED in v6. | Fixed in v6.1 text by A11, CL2 and D14. Gates T-STATUS and T-CLOSE-LIVE open. Awaiting review. | A11, 3.4, 6.1, CL2, D14. |
| ADV-2 | PIDFD_GET_INFO header check only; kernel floor untested; sibling pidfd passes check 7 (F1) | RESOLVED-SCRATCH (E11 positive); negative form open | 3.3 check 4 and step 10. T-ADM-PPID slice 6. |
| ADV-3 | Python-to-Go transfer of bounding drop (per thread); RLIMIT budget counts I's threads | RESOLVED-SCRATCH (E12, E13). RLIMIT part OPEN. | 4.1 R6, assertion C22. T-PTRACE-GO slice 3. Budget: slice 7. |
| ADV-4 | H0 pid as nsenter target (pid safe while D holds it unreaped) | RESOLVED | 6.2 S5 (absolute paths, descriptor exec). Pid safety argument carried. |
| ADV-5 | Fail-closed argument (review ADV-5): sound given checks 1 and 4. | ACCEPT as design. Depends on T-ADM-PPID. Measured shape ppid(I) == pid(L), 5 of 5 (E11). | 3.3 checks 1 and 4, 10.4. T-ADM-PPID slice 6. |
| ADV-6 | RLIMIT scope for uid 0 | CARRIED (assumption). Host-root D untested. | 5.3 P6. T-NONROOT (Tier C). |

### 13.3 Reviewer B F1 to F12 (new findings)

| ID | Sev | Finding (short) | v6.1 disposition | Section and evidence or gate |
|---|---|---|---|---|
| F1 | HIGH | Channel exposure to the producer | RESOLVED-SCRATCH (E9). Production open. | 3.5, 2.2. T-N8 slice 3. S3, S15. |
| F2 | MEDIUM | ExitStatus precedence | RESOLVED | A11, 3.4, 6.1. E10 lines 43, 44, 63. T-STATUS slice 5. |
| F3 | MEDIUM-HIGH | Supervisor death: no tie | RESOLVED in design (A22, D5). Measured through nsenter (RB-P6, one run per mode). | 6.2 S5. T-DEATH slice 4 (5 runs). |
| F4 | MEDIUM-HIGH | RLIMIT aggregate exhaustion | OPEN (D2, D12) | 5.3 P5. T-RL-AGG slice 7. |
| F5 | LOW-MEDIUM | Host metadata disclosure | CARRIED as residual (D11) | 0.1, 16 (D11). T-HOST-REACH slice 8. Cross-uid Tier C. |
| F6 | MEDIUM | Close nil without observing producer | RESOLVED (D14) | 6.4 CL2, 7.3. T-ZAP-ORDER is a mandatory pre-merge gate (slice 5, D4). |
| F7 | MEDIUM | Close without pidfd(H0) | RESOLVED (CL0; no PID-number signal; no killGroup) | 6.4 CL0. T-HOLDER and T-HOLDER-KILL-GROUP-ABSENT slice 4. |
| F8 | LOW-MEDIUM | Descriptor retention contradiction | RESOLVED (single rule) | 6.4 CL7 |
| F9 | LOW | Fail-open on old kernels | RESOLVED (fail closed on ENOTTY and EINVAL) | 3.3. T-KERNEL-FLOOR (Tier C). |
| F10 | LOW | ptrace rule text lacks same-user-namespace condition | RESOLVED | 4.2 |
| F11 | LOW (base code) | Base group signals remain | RESOLVED in plan (removal in slice 4) | 6.5 table. T-HOLDER-KILL-GROUP-ABSENT slice 4. |
| F12 | LOW | Stop and Close reentrancy | RESOLVED (one mutex; Stop after Close errors) | 6.3 |

### 13.4 Reviewer B C1 to C25 (mandatory corrections)

| ID | Correction | v6.1 status | Where |
|---|---|---|---|
| C1 | N1 evidence wording | APPLIED | 12.1 header note; A30 |
| C2 | N3 MEASURED-PARTIAL | APPLIED | 13.1 N3 |
| C3 | N16: Start context | APPLIED | 6.2 Context (D17) |
| C4 | N6 aggregate statement in 5.3 | APPLIED | 5.3 P5 |
| C5 | N17 lease part not measured | APPLIED | 13.1 N17 |
| C6 | 1.3: producer is a Python stand-in | APPLIED | 1.3 |
| C7 | One status rule | APPLIED | A11, 3.4, 6.1 |
| C8 | SO_PASSCRED; creds pid check; buffer for creds and rights | APPLIED | 3.2, 3.3 check 10 |
| C9 | CL2 nil rule; incomplete when pidfd(P) not held | APPLIED | 6.4 CL2, D14 |
| C10 | CL1 when pidfd(H0) not obtained | APPLIED | 6.4 CL0 |
| C11 | One retention rule | APPLIED | 6.4 CL7 |
| C12 | Supervisor-death tie | APPLIED (design); gate open | 6.2 S5, D5 |
| C13 | 5.3 P5: D's forks; D-side cap | APPLIED; cap open (D12) | 5.3 P5 |
| C14 | 4.2 same-user-namespace condition | APPLIED | 4.2 |
| C15 | Host metadata residual and D11 | APPLIED | 0.1, 16 |
| C16 | Namespace comparison (dev and ino); fail closed on ENOTTY and EINVAL | APPLIED; not measured | 3.3 checks 1 to 4 |
| C17 | Cancellable watcher; 1 s join | APPLIED; gate open | 6.6 |
| C18 | Lost on any pidfd error other than EINTR | APPLIED | 6.1 |
| C19 | Open-verify-exec | APPLIED; gate open | 10.1 |
| C20 | Gates added (T-WATCH, T-ZAP-ORDER, T-SENDER, T-STATUS, T-RL-AGG, T-DEATH, T-HOST-REACH); T117 NOT RUN in review | APPLIED. T117 remains in 12.2 Tier B. | 12.2 |
| C21 | 0.7 byte-for-byte re-derivation of f6 and f7 summaries | RECORDED from reviewer B. Not re-run in v6.1. | v6 0.7 |
| C22 | R6 runtime assertion before fork | APPLIED | 4.1 R6 |
| C23 | 14 adds the unverified items | APPLIED | 14 |
| C24 | E2 wording excludes P2 | APPLIED | 12.1 header note |
| C25 | Sender-credential verification (SCM_CREDENTIALS pid equals pid(I)); the R3 approval used C16 for it | APPLIED (R4 decision 7). T-SENDER is not run. | 3.3 check 10; 3.2; 16; 12.2 T-SENDER |

### 13.5 Reviewer C X1 to X5

| ID | Finding (short) | v6.1 status | Section and evidence or gate |
|---|---|---|---|
| X1 | H0 accepted as init | RESOLVED (checks 1 and 4; E8 in v6) | 3.3. T-A-ADM slice 6. |
| X2 | SIGCONT ordering | RESOLVED: SIGKILL L directly (CL4); no SIGCONT | 6.4 CL4. v6 E1 and E2. RC-Y1. |
| X3 | T-F5 kill trigger | RESOLVED (v6 E2) | 12.1 |
| X4 | Admission failure does not call Close | Design fixed (3.4, 7.3). Not closed: T06b NOT RUN. T06b is mandatory before merge of slice 6. | 3.4. T06b slice 6, mandatory. |
| X5 | P's pidfd transfer undefined | Partly accepted by review. Count rule is the guard (E10, Y2). Channel leak closed by A1 (E9). Production open. | 3.2. T-ADM-FRAMING slice 1. |

### 13.6 Reviewer C Y1 to Y12

| ID | Finding (short) | v6.1 status | Section and evidence or gate |
|---|---|---|---|
| Y1 | No pidfd(I): CL3 always times out; SIGTERM to L ends nothing | RESOLVED: skip CL3; SIGKILL L (CL4); SIGTERM never used (S16) | 6.4 CL2 to CL4. RC-Y1. T-CLOSE-LIVE slice 5. |
| Y2 | Two fds accepted by CTRUNC-only guard | RESOLVED (count rule) | 3.2. E10 lines 47 to 52. T32 slice 1. |
| Y3 | Channel left open in P lets P forge records | RESOLVED-SCRATCH (exec rule; E9 line 5 vs line 4). S15. | 3.5. T-N8 slice 3. |
| Y4 | Inheritable bit 19 defeats the bounding drop | RESOLVED-SCRATCH (refusal, E9 lines 6 to 8). Breach controls lines 9 to 11. | 4.1 R3. T-CAP-INH slice 3. |
| Y5 | RLIMIT ancestor cap fixed at namespace creation | RESOLVED in text (P1a). Policy OPEN (D2, D12). | 5.3. T-LAUNCH-LIMIT slice 7. |
| Y6 | Mask 0x7; require bit 1 before reading | RESOLVED: (mask and 3) == 3 | 3.3 check 4. E11 lines 31 to 33. |
| Y7 | Reaped used for non-children | RESOLVED (Reaped only for D's children) | 6.1 |
| Y8 | Fourth or duplicate record has no route | Decision D15 (maintainer, final). Control records after admission (init or producer, including a repeated producer), unexpected descriptors, truncation and sender failures run full Close when D next reads them. A repeated or malformed status with exact creds and no descriptor makes ExitStatus Unknown, no Close. Reviewer asked for Close on all unknown or duplicate records; the status-content split is the maintainer's. | 3.2, 3.4, 16 D15. E10 lines 59, 60, 62, 63, 75 (60, 62 and 75 under superseded expectations). |
| Y9 | Watcher cancellation, retry of Lost fds, retention undefined | Specified (6.6, 7.4, CL7). Reviewer tests T07 and T08 are defined in 12.2 (slice 5). Not run. | 6.6, 7.4, CL6, CL7, 12.2 T07 and T08. T-DONE gate open. |
| Y10 | T22 name says P refused for holder PID namespace; only check 4 refuses it | RESOLVED: the negative form is retargeted to check 4 | 12.2 T-ADM-PPID |
| Y11 | ptrace gate passes vacuously under Yama scope 1 | RESOLVED (S18: none control must pass first) | 4.2. CI prints scope. |
| Y12 | R6 written for a Go init; T102 says non-Go | Differs from reviewer fix (state I is non-Go). Decision D13 (maintainer): I is Go in init role; T102 withdrawn. Required before slice 3 merge: T-PTRACE-GO production, T-CAP-INH production, and the thread invariants (16 D13). A non-Go init needs separate evidence and maintainer approval. | 1.1, D13, 12.2 |

### 13.7 Reviewer C S14 to S20 (STOP conditions)

S14 to S20 come from reviewer C (RC-Y IDs). Section 15 holds the text. S15, S18 and S19 carry v6.1 additions, marked below.

| ID | Stop condition (section 15) | Disposition | Evidence or gate |
|---|---|---|---|
| S14 | Nonzero CapInh or CapAmb in I | Kept. Scratch PASS. | E9 lines 6 and 7: refused 5 of 5 each (inh, amb). Lines 9 and 10: OK 5 of 5 with refusal off. |
| S15 | P's fd set after exec contains the channel or pidfd(I) | Kept. v6.1 adds pidfd(I). | E9 line 4: channel 0 of 5, pidfd(I) 0 of 5 with FD_CLOEXEC and exec. Line 5 (fork without exec) leaks both. |
| S16 | Close returns nil with pidfd(I) never obtained, or SIGTERM to L as only kill step | Kept. | Reviewer measurement (RC-Y1), not re-run here: SIGTERM to L ends none within 3 s, 5 of 5; SIGKILL ends L, I and P, 5 of 5. Gate T-CLOSE-LIVE (slice 5). |
| S17 | D lowers RLIMIT_NPROC before creating H0, or a launch continues with forks failing silently | Kept. | Reviewer measurement (RC-Y5), not re-run here. Aggregate policy open (D2, D12). Slice 7 blocked. |
| S18 | ptrace gate reports EPERM without a passing none control | Kept. v6.1 adds the same-run condition. | Open. E9 and v6 E5 are separate runs. No single run yet holds the none control and the gate. |
| S19 | Go init drops bounding bit 19 on a thread that does not fork P (review text). v6.1 operative form: P is forked from a thread that still has bit 19 (C22). | Kept. Scratch PASS on go1.27.3. | out/gocaps run1 to run5: T2 drop, thread and child 000001fffff7ffff; T1 and T3 000001ffffffffff. Plain-shell negative control: drop EPERM 5 of 5. Gate T-PTRACE-GO. |
| S20 | Framing accepts a message whose fd count differs from the required count, including two fds for init | Kept. Scratch PASS: 23 of 23 framing cases. | out/frame: two fds for init closed by count (lines 48, 49); two fds at 24 bytes closed by CTRUNC (line 47). Gate T32 and T-ADM-FRAMING. |

### 13.8 Reviewer B decisions D1 to D12

| Reviewer B decision | v6.1 record | Section |
|---|---|---|
| D1 topology | Accept flat topology (reviewer D1: fewer identity paths; nested needs a trusted C identity). Nested rejected (1.2). | 1.1, 16 |
| D2 RLIMIT value | OPEN for the value. R3: a finite limit is required; the value is determined and tested before slice 7 merges. | 16 |
| D3 orphan reaper | Accept dependency; add orphan-path test on CI image (Tier B, slice 4 with T-DEATH). | 16 |
| D4 Stop semantics | Accept with status rule (A11) and zap evidence (E2 and E3). Maintainer decision (final): T-ZAP-ORDER is a mandatory pre-merge gate for slice 5 (12.2 Tier B), not Tier C. A missing producer pidfd yields incomplete cleanup (D14, Unobserved = [P]), never success, before and after T-ZAP-ORDER passes. Reviewer D4 asked for T-ZAP-ORDER before acceptance; the difference is for the independent review. | 16, 12.2 |
| D5 Pdeathsig | REVISED: no Pdeathsig on P; Pdeathsig SIGKILL on L; creator thread locked. | 16 |
| D6 production holder | Accept base holder, Pdeathsig retained; remove killGroup branch. | 16 |
| D7 helper paths | Accept absolute paths with open-verify-exec by descriptor. | 16 |
| D8 lease outcome | Residual until T-LEASE (slice 8). No lease claim. | 16 |
| D9 owner notice | Maintainer action. OPEN. | 16 |
| D10 Go drop method | Accept LockOSThread on forking thread with the assertion (C22). Scratch PASS on go1.27.3. Reviewer D10: do not use syscall.AllThreadsSyscall until its CGO_ENABLED=0 behavior is tested. The reviewer's per-thread measurement was on go1.27.0; E12 is on go1.27.3. | 16 |
| D11 host metadata residual | Accept with the residual stated. Mount isolation out of scope. | 16 |
| D12 concurrent producer cap | OPEN for the value. R3: a finite supervisor-side limit is required; determined and tested before slice 7 merges. | 16 |

---

### 13.9 Reviewer B SB1 to SB7 (start blockers) and MB1 to MB15 (merge blockers), revision R2

| ID | Requested correction (short) | R2 disposition | Section and evidence or gate |
|---|---|---|---|
| SB1 | Channel exclusion: state both controls; name pidfd_getfd and /proc/<I>/fd | APPLIED | 2.1, 2.2, 3.1, 3.5, S4, A36 |
| SB2 | R1 text: R2 is required (permitted-subset rule); drift assertion | APPLIED | 4.1 R1, R2, R3 and R6 notes; A38; T-PTRACE drift guard (12.2) |
| SB3 | Gate T-GETFD in slice 3; extend T-PTRACE; controlled comparison | APPLIED. Gate defined; NOT RUN | 12.2 Tier B T-GETFD and T-PTRACE; A36 |
| SB4 | Check 10 rejects L; check 4 does not; add L to sender tests | APPLIED | 2.2; 3.3 checks 4 and 10; A37; T-SENDER (slice 6) |
| SB5 | Tier A wording: only 21 of 23 E10 cases match D15 | APPLIED. The rerun shows FAIL on the two labels | 12.2 Tier A (T-ADM-FRAMING); 17.1; 18.1 item 1; E10-R2 |
| SB6 | Remove the Tier C reference for T-ZAP-ORDER (6.4) | APPLIED | 6.4 D14; 12.2 Tier B; 13.8 D4; 16 D4 |
| SB7 | Bounded drain at T2 and Close entry; cap 8 proposed; status and error behavior | APPLIED. Cap value proposed; the maintainer sets it | 3.2; 6.3 T2; 6.4 CL0a; A40; A42; T-DRAIN-UNIT, T-DRAIN-FLOOD, T-DRAIN-STATUS |
| MB1 | T-GETFD and its production form in T-PTRACE, slice 3 | DEFINED. NOT RUN | 12.2 T-GETFD (slice 3) |
| MB2 | T-DRAIN with a misbehaving I while Running | DEFINED. NOT RUN | 12.2 T-DRAIN-UNIT (1), T-DRAIN-FLOOD (5), T-DRAIN-STATUS (6) |
| MB3 | T-REENTRY | DEFINED. NOT RUN | 12.2 T-REENTRY (slice 5); 6.3 |
| MB4 | T-CTX | DEFINED. NOT RUN | 12.2 T-CTX (slice 5); 6.2 Context |
| MB5 | T-STATUS wrong-creds case, required in slice 5 | DEFINED, moved to slice 6 because its setup uses the production admission path (slice 6). The reviewer asked for slice 5; the maintainer may reverse this. NOT RUN | 12.2 T-STATUS-POST (rows d and e) |
| MB6 | T06b, T-ZAP-ORDER, T07, T08 | DEFINED with names, setup, triggers and assertions. NOT RUN | 12.2 T06b (6); T-ZAP-ORDER (5); T07 (5); T08 (5) |
| MB7 | Host-reach rows for P against D | DEFINED (slice 3). Cross-uid rows stay Tier C | 12.2 T-HOST-REACH-D; 4.2 |
| MB8 | Drift guard for I's CapPrm bit 19 | DEFINED (slice 3). NOT RUN | 12.2 T-PTRACE drift guard; 4.1 R2 |
| MB9 | T-DEATH creator-thread exit | DEFINED (slice 4). NOT RUN | 12.2 T-DEATH; 6.2 S5 |
| MB10 | Orphan-path test (D3) as a Tier B row | DEFINED (slice 4). NOT RUN | 12.2 T-ORPHAN |
| MB11 | S18 same-run condition for T-PTRACE | OPEN. Production T-PTRACE must run the control and the gate in one run | 12.2 T-PTRACE; 4.2; 18.2 item 5 |
| MB12 | D2 and D12 (RLIMIT policy) | OPEN. Slice 7 only | 16 D2 and D12; 17.1 |
| MB13 | Owner notice in 0.3 | OPEN. Maintainer action (D9). The notice changed beyond the process identifier, which is removed (0.3 change record) | 0.3; 16 D9; 18.2 item 6 |
| MB14 | Slice 1 T-ADM-FRAMING asserts CLOSE for rows 60 and 62 | MERGE GATE. R3: the harness returns CLOSE for both (E10-R3, PASS on actual classification). The full 23-case E10 is not rerun on the R3 build and must be before slice 1 | 12.2 T-ADM-FRAMING (slice 1); out/frame-rerun-r3 |
| MB15 | Optional: drop CAP_SYS_ADMIN from P's bounding set | DEFERRED as D18 (R3, pending compatibility evidence). Not required for drafting | 16 D18 |

### 13.10 Reviewer C reasons 1 to 7, items 8 to 16, and correction items, revision R2

| ID | Finding or item (short) | R2 disposition | Section and evidence or gate |
|---|---|---|---|
| C reason 1 | T08 success leg cannot pass; first Close omits Unobserved [P] | APPLIED: negative and positive control; CL4 polls first | 12.2 T08; 6.4 CL3, CL4; A41. NOT RUN |
| C reason 2 | Line 504 contradicts D4; "Until it passes" implies relaxation | APPLIED | 6.4 D14; 12.2 T-ZAP-ORDER; 13.8 D4; 16 D4; 18.2 item 3 |
| C reason 3 | CL2 skip branch does not list P as Unobserved | APPLIED | 6.4 CL2; A25; A41; 7.3 row |
| C reason 4 | Class (b) qualifier missing in the 3.4 repeated-status row, T-STATUS, A7 and A11 | APPLIED | 3.4 table; A7; A11; 12.2 T-STATUS-POST |
| C reason 5 | "Final form" and "two readings" wording in D15 | APPLIED. Maintainer statement recorded in 16 D15 | 16 D15; 18.2 item 5 |
| C reason 6 | Slice sequencing: PIDFD_GET_INFO in slice 1; L launch in slice 4 | APPLIED in R2 (A44). R3 restates the sequence: slice 1 injected identity, no PIDFD_GET_INFO; slice 2 PIDFD_GET_INFO wrapper and namespace checks; slice 3 L launch via nsenter on H0 without Pdeathsig; slice 4 Pdeathsig and launcher hardening | 17.2 slices 1 to 4; A44 |
| C reason 7 | T06b, T-STATUS, T-ZAP-ORDER and T07 without names; no watcher return values | APPLIED: names, setup, triggers, assertions | 12.2 T06b, T07, T08, T-STATUS-POST, T-ZAP-ORDER; 6.6 return values; A43 |
| C item 8 | T08 negative (pidfd(I) missing, Unobserved [P]) and positive control | APPLIED | 12.2 T08 (a) and (b) |
| C item 9 | CL2 records Unobserved [P]; never nil in that state | APPLIED | 6.4 CL2 and nil rule; D14; A41 |
| C item 10 | T-ZAP-ORDER mandatory in slice 5; no relaxation of the pidfd ownership rule | APPLIED | 12.2 T-ZAP-ORDER; 16 D4; 6.4 D14 |
| C item 11 | Exact class qualifier in 3.4, T-STATUS, A7 and A11 | APPLIED | as C reason 4 |
| C item 12 | Resolve "Final form" and "two readings" | APPLIED | as C reason 5 |
| C item 13 | Slice dependency ordering | APPLIED | 17.2; A44 |
| C item 14 | Names, setup, triggers and assertions; cancellation definitions | APPLIED | 12.2 T06b, T07, T08, T-STATUS-POST, T-ZAP-ORDER; 6.2 Context; 6.6 |
| C item 15 | T120 in slice 2 | APPLIED | 17.2 slice 2; 17.3 |
| C item 16 | E10 expectations for the two cases; rerun only those two; FAIL with reason | R2: expectations changed; both FAILED on the label (out/frame-rerun-d15). R3: decide() fixed; both PASS on actual classification (out/frame-rerun-r3) | 18.1 item 1; out/frame-rerun-d15; out/frame-rerun-r3; A45; A48 |
| C correction (decide) | decide() labels diverge from D15 (lines 222, 230, 238 of the R2 harness) | APPLIED in R3 for the two labels and for unparseable records (decidePost). The full E10 is not rerun on the R3 build; required before slice 1 (MB14) | 18.2 item 8; A48; out/frame-rerun-r3 |
| C correction (S2) | Checks 1 to 3 (st_dev and st_ino, C16) not measured; E10 does not cover checks 1 to 4 for init, or 6 and 8 for the producer | OPEN. E10 must not be cited as S2 coverage | 3.3; 18.2 item 11; 12.2 T-A-ADM |
| R3 item 1 | decide(): CLOSE for a status record with a descriptor after the producer, and for a repeated producer record | APPLIED in R3. Both cases PASS on actual classification (E10-R3) | 3.4; A48; out/frame-rerun-r3 |
| R3 item 2 | Harness assertions; bounded rerun of the two cases with PASS or FAIL on actual classification | APPLIED. Both PASS: status case pipe EOF 1 of 1 and fd 7 to 7; duplicate case fd 7 to 7 | out/frame-rerun-r3/summary.txt; A48 |
| R3 item 3 | Full bounded cleanup testable when production starts | APPLIED: 6.4 testable-bound paragraph; T-CLOSE-BOUND (12.2, slice 5); slice 5 list in 17.2 | 6.4; 12.2; 17.2 |
| R3 item 4 | Duplicate T120 entry in 17.3 | APPLIED: one entry kept (slice 2) | 17.3; 17.2 slice 2 |
| R3 item 5 | 13.10 reason 6 must match the slice sequence | APPLIED (C reason 6 above) | 13.10; 17.2 |
| R3 item 6 | O-CL0 against the agreed bounded drain | REVIEWED. Semantics unchanged; recommendation recorded; maintainer decides | 6.4 CL0; 18.2 item 9 |
| R3 item 7 | 17.1 must not claim independent approval | APPLIED. Advisor calls and correction passes are not B or C signoff | 17.1 |
| R3 item 8 | Check 1 stays PARTIAL where evidence is unverified | KEPT | 18.1 item 1; 18.2 |
| R3 item 9 | Process-identity leak audit; tgid redaction kept; reviewer scratch copies | AUDITED. No further leak in the normalized rows. Reviewer B and C scratch copies hold 60 raw tgid values each; not edited; replacement needed | A48; bundle README |
| R3 item 10 | Bundle rebuild and consistency checks | DONE; results in the R3 report | A48 |

### 13.11 Reviewer B and C changed-lines findings on R3, and the R4 disposition

Each row is one finding. B rows come from review-r3.md (R3-1 to R3-10, and the 17.1 text fix). C rows come from issue-390-v61-r3-changed-lines-review.md (D1 to D11 and its two minor items). The status column is the state of the R4 text and the R4 harness. Values marked proposed are for the maintainer to set.

| ID | Finding (short) | R4 disposition | Where in R4 | Status |
|---|---|---|---|---|
| B R3-1 | Drain receives not stated non-blocking | Every channel receive uses MSG_DONTWAIT. Empty-queue cases in T-DRAIN-UNIT and T-CLOSE-BOUND | 3.2, A40, 6.3 T2, 6.4 CL0a, 12.2 | APPLIED (decision 1; E15) |
| B R3-2 | Drain unit: recvmsg calls, not records | Eight accepted records; ninth overflow; EINTR capped separately at 8 (proposed); at most 17 recvmsg calls; EAGAIN ends a clean drain | A40, 3.4 overflow row, 6.3 T2, 6.4 CL0a, S26, 12.2 drain gates, 18.2 item 12 | APPLIED (decision 2). EINTR cap of 8 proposed; maintainer sets it |
| B R3-3 | Stop T2 overflow both silent and an error | T2 removes overflow from the no-error list. T3 runs. Stop returns ErrProtocolViolation joined with any Lost. T-DRAIN-FLOOD (a) | 6.3 T2, T3, 6.3 Stop rules, 3.4 overflow row, S27 | APPLIED (decision 3) |
| B R3-4 | Close after overflow at CL0a may return nil | No nil after overflow in both nil rules (6.4) and A25. ErrProtocolViolation joined with ErrCleanupIncomplete. T-DRAIN-FLOOD (b) | 6.4 CL0a, nil rules, A25, 3.4 overflow row, 18.2 item 13 | APPLIED (decision 4) |
| B R3-5 | O-CL0 maintainer decision not applied | CL0 does not return at once. CL1 and H0 part of CL5 skipped. CL2 to CL4 run on held pidfds. ErrCleanupIncomplete. No PID-number or group signal | 6.4 CL0 and CL5, A24, 16 R4 block, 18.2 item 9 | APPLIED (decision 5) |
| B R3-6 | No test for missing pidfd(H0) | T-CL0 added to 12.2 and to the slice 5 list. Merge gate. 5 runs per subcase | 12.2 T-CL0, 17.2 slice 5 | APPLIED (decision 10) |
| B R3-7 | C16 used for namespace identity and sender credentials | C16 stays namespace identity. Sender-credential check is C25. C table row C25 added. T-SENDER and 16 updated | 3.3 check 10, 13 C table, 16, 12.2 T-SENDER, 18.2 item 14 | APPLIED (decision 7) |
| B R3-8 | Post-admission classification rows missing (rows (a) to (f)) | E10-R4 post-status rows: harness rows 24 to 33 pass. T-STATUS-POST (g) to (l). T-ADM-FRAMING production includes the rows. Unparseable records need a type field that decodes to status for class (b) | 3.2 classes, 3.4 rows, 12.2 T-ADM-FRAMING and T-STATUS-POST, 16 D15, A7 | APPLIED (decision 8) |
| B R3-8 row (f) | Unparseable record after a valid status with exact creds expected UNKNOWN:after_terminal | Superseded. A record that does not identify a status is class (a): CLOSE:malformed (E10-R4 row known_then_unparseable) | 3.2, 3.4 | SUPERSEDED by decision 8 |
| B R3-9 | Slice 5 scope text does not match its tests | Slice 5 is Stop including the T2 drain and overflow handling, Close CL0 to CL7; status-result tests stay in slice 6 | 17.2 slices 5 and 6 | APPLIED (decision 10) |
| B R3-10 | Full E10 not on the bundle | Full 33-row run on the R4 build in out/frame-rerun-r4 (no filter), normalized, summary written. Old E10 labels marked superseded in out/evidence61_v61.txt. Production rerun is the slice 1 merge gate | 0.6, 18.1, 18.2 item 8, bundle | APPLIED for the R4 build (decision 12). Production rerun open (slice 1) |
| B text 17.1 | Gate (c) asks the maintainer to confirm item 7; a sentence appears twice | Gate (c) is the recorded maintainer acceptance. The sentence appears once | 17.1 | APPLIED (decision 13) |
| C D1 | Drain unit counts recvmsg calls (check 8) | Same change as B R3-2 | A40, 6.3 T2, 6.4 CL0a, 12.2 drain gates, 18.2 item 12 | APPLIED (decision 2). EINTR cap proposed |
| C D2 | Stop overflow contradicts 3.4 (check 9) | Same change as B R3-3 | 6.3 T2, 3.4 | APPLIED (decision 3) |
| C D3 | Close nil after overflow in three nil rules (check 9) | Same change as B R3-4 | 6.4 nil rules, A25 | APPLIED (decision 4) |
| C D4 | O-CL0 text returns early against 6.4 and the decision (check 10); no test row | Same change as B R3-5 and R3-6 | 6.4 CL0, A24, 12.2 T-CL0 | APPLIED (decisions 5, 9 and 10) |
| C D5 | O-CL7 has three definitions (check 10) | Retained set is every valid descriptor and state item needed for retry. CL7 and T06b agree. T08 and T-CLOSE-BOUND agree (no release a retry needs) | 6.4 CL7, A27, 12.2 T06b, 16, 18.2 item 10 | APPLIED (decision 6). Alternative not taken |
| C D6 | C16 collision (check 11) | Same change as B R3-7 | 13 C table (C25), 16, 12.2 T-SENDER | APPLIED (decision 7) |
| C D7 | Unparseable records and records after a valid status (check 4) | Same change as B R3-8. Harness and E10-R4 rows | 3.2, 3.4, 12.2 T-STATUS-POST, A7 | APPLIED (decision 8) |
| C D8 | T-ZAP-ORDER admission dependency (check 6) | T-ZAP-ORDER built by a test-only constructor, not slice 6 admission | 12.2 T-ZAP-ORDER | APPLIED (decision 10) |
| C D9 | Merge-gate wording and run counts (check 7) | Gates and run counts stated for T07, T08, T-DRAIN-UNIT, T-DRAIN-FLOOD, T-DRAIN-STATUS, T-CLOSE-BOUND, T-CL0 and T-ZAP-ORDER; T06b gate kept | 12.2 | APPLIED (decision 10). Run counts proposed; maintainer sets them |
| C D10 | Stale E10 evidence (check 2) | Old labels marked superseded in the bundle; E10-R4 full run recorded | 0.6, 18.1, bundle | APPLIED (decision 12) |
| C D11 | Slices 3 and 4 merge order (check 6) | Prerequisite and merge rule: neither slice merges in a state where L or I survives supervisor death; T-DEATH on combined code before the first production merge | 17.2 prerequisites | APPLIED (decision 11) |
| C minor, record_after_known | Aggregate Unknown not asserted | T-STATUS-POST (b) asserts the aggregate ExitStatus Unknown after the second status | 12.2 T-STATUS-POST | APPLIED |
| C minor, T-STATUS-POST (e) | Ladder assertions missing for row (e) | Row (e) asserts the full ladder | 12.2 T-STATUS-POST | APPLIED |

The R5 disposition of the reviewer B and C findings on R4 is in section 13.12.

### 13.12 Reviewer B and C changed-lines findings on R4, and the R5 disposition

Reviewer B findings are from the R4 review (D-A to D-H and cosmetic A8; D-F is dropped as an R4 defect and kept as an API note). Reviewer C findings are R-D1 to R-D9 from the R4 changed-lines review. Each row gives the R5 disposition. The changed-lines review of R5 by reviewers B and C is the next step (17.1 gate (a)).

| ID | Finding | R5 disposition | Where | Status |
|---|---|---|---|---|
| B D-A | CL7 and A27 release only "after proven complete cleanup, which is full success"; full success is nil, so an overflow blocks release even when cleanup is complete | Complete cleanup is every nil condition of 6.4; the wording is fixed in A27, CL7, T06b and T-DRAIN-FLOOD (run 2). The retention reading after overflow is the R5 choice; it conflicts with R-D1 | A27, 6.4 CL7, 12.2 T06b, T-DRAIN-FLOOD | APPLIED in R5; the R5 retention reading is superseded in R6 (13.13, A51) |
| B D-B | EINTR attempt budget recorded as "proposed" | 8 EINTR returns per drain approved in R5; a ninth is overflow at a drain and CLOSE:budget at admission | A40, 3.2, section 16 decision 2 and R5 item 1, 18.2 item 12 | APPLIED |
| B D-C | A zero-length record with credentials is read as EOF; a status then a zero-length record gives Known | EOF is a zero-byte receive with credentials, no ancillary data and neither MSG_TRUNC nor MSG_CTRUNC. Any other zero-length result is a record (class a). Tests: E10-R5 rows, T-DRAIN-UNIT (h) and (i), T-STATUS-POST (n), T-SENDER | 3.2 EOF rule, 3.4, 12.1, 12.2 | APPLIED; E10-R5 rows PASS on labels; production tests NOT RUN |
| B D-D | EAGAIN after a readable poll is not defined | Admission is a poll with the deadline, then a non-blocking receive; EAGAIN after a readable poll polls again; at most 17 recvmsg calls | 3.2 Receive, A40 | APPLIED; seam test TestEAGAINAfterReadablePollRepolls PASS (scratch) |
| B D-E | Does a truncated or zero-length record count toward the eight? | Both count toward the eight (A40) | A40, 3.2 EOF rule, 3.4 | APPLIED; proposed for B and C review (section 16, R5 item 2) |
| B D-F | Stop does not reap H0 or L after an overflow | Dropped as an R4 defect: 6.3 already requires the caller to call Close after any Stop. Kept as an API note | 6.3 (unchanged) | NOTE ONLY |
| B D-G | Errno other than EINTR, EAGAIN and EOF (18.2 item 15) | Observation error (ErrObservation; separation decided by R6-3; ErrObservation name and wording PENDING B and C confirmation, 18.2 item 16): no status accepted; Stop and Close never return nil after it (S28) | A40, 3.4, 6.3, 6.4, 15 S28, 18.2 items 15 and 16 | APPLIED; separation decided by R6-3; ErrObservation name and wording PENDING B and C confirmation (18.2 item 16) |
| B D-H | Class (b) omits a wrong V; "decodes to status" is undefined | Class (b) covers V not 1 (status_shape). Status candidate rule defined: exactly one member named type with value status, exact name after unescape, before the duplicate check; truncated or invalid UTF-8 payloads are not candidates | 3.2 class (b), 3.4, 12.2 T-STATUS-POST (m) | APPLIED; V not 1 not measured by E10-R5 |
| B cosmetic A8 | A8 row omits C25 | A8 cites C25 and check 10 | A8 | APPLIED |
| C R-D1 | CL7 release after an overflow is impossible because full success is nil | The R5 choice keeps the nil-condition reading: after an overflow or observation error, descriptors are retained until process exit (superseded for CleanupComplete by R6-2). R-D1 asks for release after cleanup instead | A27, 6.4 CL7 | ACCEPTED in R6 (R6 maintainer decision R6-2; 13.13). Release on CleanupComplete; the B and C changed-lines review of R6 is pending |
| C R-D2 | T2 does not say that reading continues past a class (b) record | A class (b) record does not stop T2; T2 reads until EAGAIN, EOF, overflow or observation error | 3.2, 6.3 T2 | APPLIED |
| C R-D3 | Unobserved is inconsistent for an unheld pidfd(I); T08(a) conflicts with CL0 | Option Y: P is listed when pidfd(P) is not held; H0, I and L are listed when started and pidfd not held; I counts as started once L is started; a never-started H0 is not listed. T08(a) expects [I, P] | A41, 6.4 CL0 and CL2, 12.2 T08, T06b, T-CTX | APPLIED; Option Y for B and C review (section 16, R5 item 4) |
| C R-D4 | Slices 3 and 4: the merge unit is not stated | Slices 3 and 4 land as one change set | 17.2 prerequisites, section 16, R5 item 7 | APPLIED |
| C R-D5 | "Six waits, 30 runs" does not match the list of waits | The six waits are listed (W1 to W6) in 6.4 and T-CLOSE-BOUND | 6.4, 12.2 T-CLOSE-BOUND | APPLIED |
| C R-D6 | "Does not parse" and "type field decodes to status" are undefined | Strict grammar and the status candidate rule (3.2); annotated rows (3.4) | 3.2, 3.4 | APPLIED |
| C R-D7 | EINTR cap of 8 still "proposed" | Approved at 8 in R5 | A40, section 16, 18.2 item 12 | APPLIED |
| C R-D8 | Rows producer_then_status_type_mismatch and known_then_status_type_mismatch test a field-type mismatch, not a type mismatch | Annotated in 3.4 with the note in main.go (line 1031). Row names are not changed | 3.4 | ANNOTATED; rename not made |
| C R-D9 | Gate 17.1(c) cites R4 decision 13, which is not among the maintainer decisions given for R4 | Gate (c) is not counted as met until the maintainer confirms decision 13 | 17.1, section 16 decision 13 and R5 item 6, 18.2 item 23 | FLAGGED (R6): the R6 maintainer statement is read as the confirmation of decision 13 for draft-start readiness. The maintainer confirms or changes this reading (17.1 gate (c)) |

### 13.13 R6 dispositions (corrective pass R6)

Each row gives the R6 finding, the change, where it applies, and the status. The rows come from the R6 changes and the R6 maintainer statement (request 88ac).

| ID | Finding | R6 disposition | Where | Status |
|---|---|---|---|---|
| R6 bug 1 | The drain erased the descriptor count and the MSG_TRUNC and MSG_CTRUNC flags before classification, so T2 could accept a status with a descriptor, or a truncated status, as Known | The drain keeps all three through classification. T2 and decidePost share one status gate, in this order: trunc, ctrunc, empty, malformed, late_record, creds, status_fd | 3.4, 6.3 T2, A51 (1), 12.2 T-DRAIN-UNIT (m) | APPLIED in the harness. Red on R5 (TestR6ReproDrainStatusWithFdIsNotKnown, TestR6ReproDrainTruncatedStatusIsNotKnown). Green on R6. Production T-DRAIN-UNIT NOT RUN |
| R6 bug 2 | An observation error followed by a valid status restored Known | The drain state is poisoned at the first observation error or overflow. A later drain returns POISONED with zero recvmsg calls. The decision is UNKNOWN | 3.4 rows, 6.1, 6.3, 6.4 CL0a, 7.3, A51 (2), 12.2 T-DRAIN-UNIT (n), (o), (q) | APPLIED in the harness. Red on R5 (TestR6ReproObservationNotRestoredByLaterStatus). Seam tests only (18.2 item 27) |
| R6 review: integer rule | The integer rule was stated loosely. The decodeInt comment said int64 range, but the harness checks the Go int of the build target, and it rejects -0 | An integer must fit the Go int of the build target (int64 on amd64). -0 is rejected | 3.2, A51 (3), 12.2 T-DRAIN-UNIT, T-STATUS-POST | APPLIED. Mutation B caught (TestR6IntegerGrammarMatchesRefParse). 32-bit build not run (18.2 item 30) |
| R6 review: EOF rule | The R5 wording mixed credential presence with ancillary data | EOF is a zero-byte receive with verified SO_PASSCRED (A8), no ancillary data and neither TRUNC flag. Without verified credentials every zero-length receive is a record | 3.2 EOF rule, 3.4 (passcred row), A51 (4) | APPLIED. Scratch test TestDrainZeroLengthIsRecordWithoutCreds PASS |
| R6 review: readiness poll | The readiness poll in the drain path was not placed in the contract | The T2 readiness wait is the only poll in the drain path. POLLNVAL and a poll error other than EINTR are observation errors there | 3.2 readiness poll, 6.3 T2, A51 (5), 12.2 T-T2-POLL | APPLIED in the contract. Not in the harness; NOT RUN (18.2 item 28) |
| R6 review: W3 | R5 waited on P only inside the held-I branch, so a held pidfd(P) with pidfd(I) not held was never waited on | CL4b: after CL4, in every branch, wait Done(P) within 5 s when pidfd(P) is held; otherwise list P as Unobserved. The worst case stays at 26 s | 6.4 CL2, CL4b, worst-case line, 12.2 T08 (c), A51 (6) | APPLIED in the contract. T08 subcase (c) NOT RUN |
| R6 review: release | R5 retained descriptors after an overflow or observation error, which reviewer C R-D1 disputes | Descriptors are released on CleanupComplete even when ProtocolClean is false. Close still returns that error, not nil (CL7 nil rule) | 6.4 CL7, A27, 13.12 R-D1, 16 R6-2, 12.2 T-CLOSE-BOUND | ACCEPTED (R6-2, maintainer decision). B and C returned REVISE on R6; re-review pending |
| R6 review: watcher join | One 1 s join per watcher would make the join cost grow with the watcher count | One watcherJoinDeadline of 1 s covers all watchers together. Worst case stays at 26 s | 6.4 CL6, 6.6, worst-case line, A51 (8) | APPLIED in the contract. T-CLOSE-BOUND W6 NOT RUN |
| R6 review: sentinels | ErrObservation and ErrProtocolViolation were not separated | Separate sentinels | 3.4, 16 R6-3, 18.2 item 16 | ACCEPTED (R6-3) |
| R6 review: CALL_BOUND | R5 item 8 said overflow; the R6 harness mapped CALL_BOUND to ErrObservation | Final R6: the receive-call ceiling (17 recvmsg calls, EAGAIN included) reached without a conclusive result is ErrObservation after admission (3.4, normative). A ninth record and a ninth EINTR stay ErrProtocolViolation. Per drain it is not reached while the caps hold (defensive); per receive it is reachable through repeated EAGAIN | 3.4 CALL_BOUND row, 6.3 T2, 16 R6-5, 18.2 items 17 and 29, A52 (3) | SETTLED (R6 final). Harness: TestR6CallCeilingIsObservation PASS on the R6 sources. B and C review of the mapping pending (18.2 item 29) |
| R6 review: T-DRAIN-UNIT | Case (l) (POLLNVAL) tested the readiness poll, which is not part of the drain | Case (l) moved to T-T2-POLL. Cases (m) to (q) added | 12.2 T-DRAIN-UNIT, T-T2-POLL | APPLIED in the contract. Not run |
| R6 review: incident record | The R5 item 24 text mixed counts with detail about process identifiers | Counts only in 18.2 item 24, with the other-session counts. No process identifiers in the bundle | 18.2 item 24, 0.6 | APPLIED. Historical claim "Owner notice text unchanged (0.3)": superseded by the R6 final-2 correction (0.3 change record); the notice changed beyond the identifier. |
| R6 review: red evidence | The first red log came from an earlier repro_test.go, not the final file | Red re-run on R5 sources with an R5-signature variant of the final repro_test.go. Its test bodies differ from the final file in call signatures only | 12.2 R6 row, 18.1 R6-V2, bundle README | DISCLOSED |
| R6 final (1) | ExitStatus had no single commit point; an observation error at CL0a after a valid T2 status could leave the value Known | One commit rule, commitExit, for T2 and CL0a. CL0a is the commit point of the first Close. UNKNOWN is sticky. A poisoned handle is never KNOWN | 6.1, 6.3, 6.4 CL0a, 12.2 T-STOP-KNOWN and T-DRAIN-UNIT (n) to (q), A52 (1) | APPLIED in the harness (TestR6FinalExitCommit, four subtests; mutations caught). Production NOT RUN |
| R6 final (2) | CL0 stopped before CL4b and CL5; pidfd(L) missing had no branch; the required-exit set was not stated | CL0 continues through CL4b and CL5 to CL7; pidfd(L)-missing branch across CL3, CL4 and CL5; required-exit set H0, L, I, P; G excluded by design; T08 and T-CL0 defined | 6.4 CL0, CL3, CL4, CL4b, CL5, 12.2 T08 and T-CL0, A52 (2) | APPLIED in the contract. T08 subcases and T-CL0 NOT RUN |
| R6 final (3) | CALL_BOUND was described as an open mapping | Normative: ErrObservation at the receive-call ceiling without a conclusive result; ninth record and ninth EINTR stay ErrProtocolViolation; per drain not reached while the caps hold (defensive), per receive reachable through repeated EAGAIN | 3.4, 6.3, 13.13, 16 R6-5, 18.2 items 17 and 29, A52 (3) | APPLIED. Harness: TestR6CallCeilingIsObservation PASS. Production NOT RUN |
| R6 final (4) | Gate (c) and R6-1 read as NOT MET in the pre-correction text; the 33-row E10-R4 reference stood for slice 1 | R6-1 MET for draft-start readiness only; 47-row E10-R6 matrix replaces the 33-row reference; differential parser oracle named as a slice 1 gate | 16 R6-1, 17.1 (c), 17.2 slice 1, 18.2 item 8, A52 (4) | APPLIED. Production gates NOT RUN |
| R6 final (5) | Portability: amd64 evidence not separated from arm64 and 386; no arm64 obligations stated | Architecture-neutral poll (SYS_PPOLL on Linux) and recvmsg for Linux amd64 and arm64; R6 scratch execution is amd64 only; arm64 go test -c and go vet exit 0 with CGO_ENABLED=0 on the frozen source; no 386 obligations | 3.2, 17.2 slice 1, 18.2 item 30, 19, A52 (5) | APPLIED. arm64 tests NOT RUN. amd64 is the only executed evidence |
| R6 final (6) | T-T2-POLL unnamed; T08 heading and run count mismatched; watcher join wording; slice lists | T-T2-POLL named TestStopT2ReadinessPoll with a readiness-timeout case; T08 has three subtests and 15 runs; one joint 1 s watcher join; slice 5 and 6 lists aligned with 12.2; A27 superseded wording; misleading comments corrected | 12.2, 17.2, A27, 6.6, A52 (6) | APPLIED in the contract. T-T2-POLL, T08 subcase (c) and T-CLOSE-BOUND W6 NOT RUN |
| R6 final-2 (1) | Final ExitStatus value could change after CL0a: a clean CL0a drain with no record stored nothing, so a later valid status made it KNOWN | commitExit takes final; at CL0a the value is stored and frozen; T2 stays provisional and stores nothing for a clean no-record drain | 6.1, 6.4 CL0a, A53 (1), 12.2 T-FINAL-COMMIT | APPLIED in the scratch harness (TestR6FinalUnknownIsFrozen): red on R6 for 2 subtests, green on the candidate; mutants (final store removed, freeze removed) red. The red run was the R6 source with commitExit renamed to commitExitR6 and a scratch shim (red/red_shim.go, not in the bundle) that ignores the final flag; it is not a run of unchanged R6 source. Production NOT RUN |
| R6 final-2 (2) | Tier A and E10 status rows cited the 33-row E10-R4 run | Status rows cite E10-R6 (47 rows), label level only; E10-R4 rows kept as history | 6, 12.2 Tier A count and T-ADM-FRAMING row, A53 (2) | APPLIED. Label evidence only; production T-ADM-FRAMING NOT RUN |
| R6 final-2 (3) | Cleanup and STOP text: duplicate Unobserved entries; a CL0a readiness wait; L listed when never started; ErrObservation called proposed; PID-signal prohibition unscoped; the base code described as free of the number-based path | Unobserved is a set; CL0a has no readiness wait; L listed only when started and unproven; ErrObservation wording fixed; prohibition scoped to the production supervisor lifecycle; base path removed in slice 4 | 0.3, 6.3 T3, 6.4 CL0 to CL5, 13.12, 17.2 slice 4, A53 (3) | APPLIED as text. Slice 4 removal NOT RUN |
| R6 final-2 (4) | Incident disclosure: process identifier in the owner notice, README and three shipped diffs; reviewer-conduct sentence; advisor row; signal inference from token counts in item (24) | Process identifier in the owner notice (0.3), README and three contract diffs of the R6 baseline removed (count-only scan: none in this bundle); original in restricted storage outside the bundle; the notice also changed beyond the identifier (0.3 change record); reviewer-conduct sentence and advisor row removed; item (24) text-match counts only; checks that named the notice now name the restricted record | 0.3, 13.1 N11, 13.9 MB13, 16 D9, 18.1, 18.2 item (24), README, A53 (4) | APPLIED. D9 OPEN |
| R6 final-2 (5) | Documentation: E10 label acceptance wording; advisor sentences; stale R4 and R5 references; R6 grammar reference in the differential oracle rows | E10 acceptance MET for draft-start readiness only (R6-1); advisor sentences removed; oracle rows name the R6 grammar (3.2); stale references updated | 6, 12.2 T-ADM-FRAMING row and Tier A count, 17.1 (c), 18.2 item (19), A53 (5) | APPLIED. Arm64 execution and full production cleanup tests remain merge gates |
| R6 final-2 (6) | Section 20 mixed the advisor record with the checklist; production merge tests missing for release, watcher join, final commit and T-T2-POLL | Section 20 is a checklist split into specification-readiness checks and production test requirements; T-CL7-RELEASE, T-CL6-JOIN and T-FINAL-COMMIT added to 12.2, 17.2 and 17.3; T-T2-POLL listed in 17.3 | 12.2, 17.2, 17.3, 20, A53 (6) | APPLIED as text. Production tests NOT RUN |
| R6 final (7) | Incident wording: a round-report pointer and an unverified R4 and R5 claim in 18.2 item 24 | 0.3 and 18.2 item 24 consistent; text-scan counts separated from other-session counts and unverified claims; no reviewer attribution without evidence; D9 OPEN | 18.2 item 24, 0.3, A52 (7) | APPLIED. Historical claim "Owner notice text unchanged (0.3)": superseded by the R6 final-2 correction (0.3 change record); the notice changed beyond the identifier. |
| R6 final (8) | Section 20 read as a completed review | Remaining independent-review scope listed; section 20 is not marked complete | 20, A52 (8) | APPLIED |
| R6 final (9) | Per-receive and per-drain call budgets were not stated separately in 3.4 and 6.3 T2 | Per receive (receiveOne): the 17-call ceiling restarts at each receive, EAGAIN counts within it. Per drain (drain): records, EINTR returns and the terminal call share one ceiling of 17; EAGAIN ends a drain without repoll | 3.4, 6.3 T2 and CL0a, A52 (9) | APPLIED in the contract and the harness (TestR6BudgetPerReceiveRestarts, TestR6BudgetDrainEndsOnFirstEAGAIN, TestDrainCallCeiling). Production NOT RUN |
| R6 final (10) | runCase did not treat CLOSE as terminal: later steps were launched and later records decided DISCARD | CLOSE is terminal in the harness run: no later step is launched, no later receive is made, no later record is decided; the observation-error stop is unchanged. No ladder change in 6.4 | Harness only; A52 (10) | APPLIED in the harness (TestR6CloseIsTerminalInRunCase; D's stop suite on frozen H). Production NOT RUN |
| R6 final-2 correction (88ac, after B's final2b review; scratch copy, not published) | Review findings on final2b: (1) S1 said '43 top-level tests'; the count is 41 Test functions and 2 Fuzz functions (43 top-level entries), 52 subtests, 95 PASS lines, 0 FAIL. (2) S4, 13.9 MB13, the 13.13 rows 'R6 review: incident record' and 'R6 final (7)', and 18.1 item 3 said the notice matched the carried text except the identifier; it changed beyond the identifier (0.3 change record). The reviewer-B sentence is not restored. (3) Redacted diffs were not labeled. (4) The A53 inventory listed 12.1 and omitted 0.2, 0.4, 0.6, 13.2, 13.9, 15, 16, 18, 19 and the title. (5) The S9 production scope was not stated. (6) The integration base was not recorded. (7) The 17.1 (a) and (b) artifact wording was missing. (8) No code change was requested or made. | Documentation only. Labels K1 to K3 are this row's correction items, not the decisions D1 to D12 (13.8, section 16). Section 20 checks are CS1 to CS9 and CP1 to CP7; earlier text in this row and in 13.9 used S1 to S9 and P1 to P7 for them. K1: T-CL7-RELEASE matches CL7 (R6-2). K2: 6.1 provisional and final values; commitExit unchanged. K3: T-STATUS-POST rows (d) to (k) and (n) assert final ExitStatus Unknown; row (a) and T-DRAIN-STATUS (c) are labeled provisional. Gates: slice 5 and slice 6 mandatory lists; Tier B statement (12.2); proposed names TestCloseCommitIsFrozenAtCL0a and TestCloseWatcherJoinSharesOneDeadline (not run). ErrObservation wording (18.2 items 15 and 16). Red run disclosed (R6 final-2 (1)). README counts and labels. | A53 (7), 0.2, 0.3 and its change record, 6.1, 12.2, 13.9, 13.13, 15 S9, 17.1, 17.2, 17.3, 18.1, 18.2 items 15, 16 and 24, 20 S1 and S4, README | APPLIED in the scratch correction copy. B re-review pending. Not published. No code change. |

---

## 14. Unverified claims

- Admission ioctls 0xff04, 0xff05, 0xff06, 0xff09 and PIDFD_GET_INFO work on kernels older than 7.2. Base comment says 6.11 or later. Not tested (T-KERNEL-FLOOR, Tier C).
- Namespace identity by st_dev and st_ino of the ioctl fds (C16). Not measured.
- The production holder H0 behaves like the sleep stand-in. Not measured (T-HOLDER, slice 4).
- The Go receive path (section 3.2) as production code. Scratch only (E10).
- The production Go init handles signals from P as the design needs (T-SIG-INIT, slice 3). Not measured.
- P can send signals to I through pidfd(1) (A3). The effect depends on I's handler set and on pid_namespaces(7) (recalled: only signals with a handler in init are delivered from the same namespace; SIGKILL and SIGSTOP are the exception only from ancestor namespaces). Not run.
- Real producer under RLIMIT_NPROC: limit value, EAGAIN point, absence of a fork bomb (T-F6b, slice 7). Not tested.
- I's Go threads and P's threads count toward U0's RLIMIT. I needs headroom. Not measured for the Go init.
- The ancestor limit captured at U0 creation (RC-Y5). Reviewer evidence, not re-run in v6.1.
- Host-wide uid process count behavior under the limit: predicted. Not measured against host processes.
- Lease behavior with a writer inside N (section 8.3). Not tested.
- Orphan reaping of I when L dies first depends on the host reaper. The reaper on the test host was not identified (D3).
- Namespace zap ordering for G and P when pidfd(P) is not held (D14). Recalled, not measured for this path (T-ZAP-ORDER, mandatory pre-merge gate for slice 5, D4).
- Reviewer B probes RB61-P4 and RB61-P5 (pidfd_getfd and /proc fd reads refused under control 2; a forged record accepted in the breach control): reviewer evidence, not re-run in R2.
- The access rule that governs pidfd_getfd and /proc fd reads (section 4.2): recalled, not read from kernel source.
- commoncap ptrace rule (section 4.2) and permitted-after-exec formula (section 4.1): recalled from documentation. The measured results match. The kernel source is not on the host.
- Timing: single host, single kernel, 5 runs per case. Not a kernel guarantee.
- The non-root producer and non-root D (N16, P6): untested (T-NONROOT, Tier C).
- F5 host metadata: cross-uid visibility predicted, not measured (T-HOST-REACH, Tier C rows).
- Hosted CI kernel, util-linux and Yama scope: unknown. T120 must print them.
- Watcher behavior under real stopped members: not measured (T-WATCH, slice 5).
- The Go init's CapBnd at the time of the fork of P matches the scratch oracle: the scratch oracle used a Go program, not the production init.
- EINTR budget values have no kernel-driven trigger in E10-R5: recv EINTR was 0 in 4000 iterations. The seam tests drive the budgets. Production behavior under real signals is not measured.
- The drain path (records, overflow, observation error, V not 1) is not measured on the kernel by E10-R5. Seam and fuzz tests only (18.2 item 18).

Removed from this list because v6.1 measured them: P cannot hold the channel after exec (E9); a pidfd for PID 1 is available to P (E9); the sender credential pid equals pid(I) (E11); ppid(I) equals pid(L) for the launch shape (E11); the bounding and inheritable formula for permitted bit 19 (E9).

---

## 15. STOP conditions

Stop implementation and return to review if any of these occur.

- S1: any Close path returns nil while H0 or L is alive or unreaped by D.
- S2: admission accepts H0, L, a producer descriptor as init (T-ADM-PPID), or a foreign PID 1.
- S3: T-N8 shows the producer holds the channel (v6 text) or a pidfd(I) after exec (v6.1 addition).
- S4: T-PTRACE, T-PTRACE-GO or T-GETFD shows the producer can attach to I, read I's fds, or obtain the channel fd through pidfd_getfd or /proc/<I>/fd in the production launch.
- S5: CapInh or CapAmb is nonzero at launch, or T-CAP-INH does not refuse.
- S6: the producer can raise the RLIMIT hard limit, or T-F6b does not reach EAGAIN.
- S7: T-LEASE shows a writer inside N modifies a leased inbox without refusal or a held open.
- S8: T117 flips (the peer-write gap would appear closed without mount isolation). Stop: the claim would be false.
- S9: production supervisor lifecycle, as v6.1 changes it (contrib/frr-correlation/supervisor; the scratch test tools are not that lifecycle, 0.3) uses kill(-pgid), a PID-number signal, pkill, pgrep, a command-line or comm match, or a /proc scan to find a process. The base code at 153e7236 has such paths (for example namespace_linux.go line 292), which are not new code; slice 4 removes them (17.2). A STOP follows from any such call that remains after slice 4, or that any slice adds. This clarification does not permit a PID-number signal in any production code.
- S10: any Go build path requires CGO. Release builds must keep CGO_ENABLED=0.
- S11: a fork into N is attempted after I exits (R-E1).
- S12: a review finds a misnumbered F or N or X finding, or a disposition that does not match the evidence.
- S13: any document or bundle file contains an em dash, an en dash, or a host identifier.
- S14: any launch proceeds with nonzero CapInh or CapAmb in I (RC-Y4).
- S15: P's fd set after exec contains the channel or pidfd(I) (RC-Y3).
- S16: Close returns nil with pidfd(I) never obtained, or sends SIGTERM to L as its only kill step (RC-Y1).
- S17: D lowers RLIMIT_NPROC before creating H0, or a launch continues with forks failing silently (RC-Y5).
- S18: a ptrace gate reports EPERM without a passing none control in the same run (RC-Y11).
- S19: a Go init drops bounding bit 19 on a thread that does not fork P (review C text, R6, T-PTRACE-GO). v6.1 operative form: P is forked from a thread that still has bounding bit 19 (C22).
- S20: framing accepts a message whose fd count differs from the required count, including two fds for init (RC-Y2).
- S21: production code forks P without exec, or any path forks P before FD_CLOEXEC is set on the channel child end in I.
- S22: a signal from P to I is classified Known, or a handled signal from P to I changes an outcome without an Unknown result.
- S23: ExitStatus is Known without a valid status record that arrived after admission and was the only record after admission.
- S24: any exported path reaches Running without checks 1 to 10 (T-NO-BYPASS).
- S25: Close returns nil while Unobserved is not empty, or a retry sends a signal to a member already Done (A41).
- S26: a drain accepts more than 8 records, has more than 8 EINTR returns, or makes more than 17 recvmsg calls in one T2 or CL0a call; a receive in a drain blocks; or a drain overflow is reported as Known (A40). More than 8 EINTR returns in one drain is overflow.
- S27: Stop or Close returns nil after a drain overflow (A40, R4 decisions 3 and 4).
- S28: Stop or Close returns nil after a drain observation error (A40; ErrObservation).
- S29: a zero-length record that is not EOF is treated as EOF, or is not counted toward the eight records of a drain (A40, 3.2 EOF rule).
- S31: a final ExitStatus that is UNKNOWN at CL0a is read as KNOWN by a later status, a later protocol violation or poisoning (6.1, 6.4). Tests: TestR6FinalUnknownIsFrozen (scratch); production T-FINAL-COMMIT and TestCloseCommitIsFrozenAtCL0a.

---

## 16. Maintainer decisions

Recorded as v6.1 defaults. The maintainer confirms or changes each at the review in section 20. Items marked OPEN block the slices named.

- D1: accept the flat topology and drop nested (recommended). Default recorded.
- D2: RLIMIT value producerNprocLimit and whether to set one. R3 (maintainer): a finite limit is required. Its value is determined and tested before slice 7 merges. The value is OPEN. Needs T-LAUNCH-LIMIT and T-F6b.
- D3: depend on the host orphan reaper when L is killed first (N9), or set a child subreaper. Default: depend on the reaper, record it, and add an orphan-path test on the CI image (slice 4).
- D4: Stop semantics (section 6.3). Default recorded: kill I and zap the namespace; ExitStatus Known only when the status arrives first, alone. Maintainer decision (final): T-ZAP-ORDER is a mandatory pre-merge gate for slice 5 (12.2 Tier B), not deferred to Tier C. Proceed on D14 now. A missing producer pidfd produces incomplete cleanup (D14), never success, before and after T-ZAP-ORDER passes. The maintainer's "until it passes" wording is read as gate timing (18.2 item 3). Reviewer D4 asked for T-ZAP-ORDER before acceptance; that difference is for the independent review.
- D5: REVISED. No Pdeathsig on the producer. Pdeathsig SIGKILL on L, set before the exec of nsenter, with the creator thread locked for L's lifetime. Holder keeps base Pdeathsig. Measured through nsenter (RB-P6). Gate T-DEATH.
- D6: production holder H0 is the base holder. Base release() killGroup and PID-number branch are removed (slice 4).
- D7: helper paths /usr/bin/unshare and /usr/bin/nsenter with owner and mode checks, opened, verified and executed by descriptor (C19).
- D8: lease. No lease claim until T-LEASE (slice 8) runs. Residual recorded.
- D9: owner notice for the PID in 0.3 (section 0.3). Maintainer reports it to the owner. OPEN. Not resolved by design. No PID-number cleanup until it is reported.
- D10: Go capability drop method: LockOSThread on the forking thread, with the assertion before the fork (C22). Scratch oracle PASS on go1.27.3 (E12). Production gate T-PTRACE-GO.
- D11: host metadata residual (RB-F5, RB-P3). Accept with the residual stated. Mount isolation is out of scope.
- D12: concurrent producer cap. R3 (maintainer): a finite supervisor-side limit is required. Its value is determined and tested before slice 7 merges. The value is OPEN.
- D13: I is the Go binary in init role, entered through a fixed internal argument that the public CLI does not expose (keeps --help standard). T102 WITHDRAWN (RC-Y12). Needed for D10. Before the slice 3 merge, these gates are required: T-PTRACE-GO production (12.2) and T-CAP-INH production (R3 refusal before init for inh, amb and nobnd). Invariant: P is forked only from the locked thread, after its capability drop; a fork from any other thread is refused by assertion (C22). The per-thread oracle (E12) shows control threads keep bit 19 after the drop; that result is the reason for the rule, not a production check. A non-Go init needs separate evidence and maintainer approval.
- D14: Close returns nil only when pidfd(I) and pidfd(P) are held and observed, plus H0 and L reaped. Without pidfd(P) the error carries Unobserved = [P]. Cost: launches that fail before P exists also return ErrCleanupIncomplete with Unobserved = [P]. Callers distinguish it from Lost by the lists. New in v6.1.
- D15: after admission, every record is class (a) or class (b). Class (a) runs the full bounded Close ladder (6.4) when D next reads the record: an init or producer record, a record with an unexpected descriptor, a record with MSG_TRUNC or MSG_CTRUNC, and any record whose sender credentials are missing or not pid(I). Class (b) makes ExitStatus Unknown and does not start Close: a status record that is malformed or has an unknown kind, or that repeats a valid status, but only when its SCM_CREDENTIALS pid is pid(I) (provenance intact), it carries no descriptor, and it is not truncated. Unauthenticated records are never class (b). No reader runs while Running in v6.1, so class (a) is acted on at the next read (open, 18.2). Under class (b) the producer keeps running and stays observed by pidfd; the caller decides through Stop or Close. Risk accepted: a misbehaving I with valid credentials keeps running until the caller acts. I is a trusted helper. New in v6.1. Revision R2 records the maintainer's statement: a descriptor on a status record is class (a), and a repeated producer record after admission is class (a). R3 (maintainer): detection latency is accepted for the initial draft and documented (18.2 item 6). The initial drain cap is eight accepted records (18.2 item 12; R4 decision 2). R4 (decision 8): a record is a status candidate for class (b) only when its type field decodes to status. An unparseable record that does not identify a status is class (a). A status candidate is class (b) (UNKNOWN:malformed) only under the same gates (creds pid(I), no descriptor, not truncated).
- D16: watcher design (6.6): poll slices of 100 ms and a cancel pipe; join deadline 1 s. New in v6.1 (answers C17).
- D17: Start takes a context until pidfd(L) exists; Close uses fixed deadlines and ignores the context. New in v6.1 (answers C3).
- D18: optional defense in depth (reviewer B MB15): drop CAP_SYS_ADMIN from P's bounding set. It blocks SCM_CREDENTIALS pid spoofing by channel holders and does not replace control 2 (pidfd_getfd). Producer compatibility is the maintainer's decision. R3 (maintainer): deferred pending compatibility evidence. Not a start gate and not required for any slice.
- R3 maintainer decisions (request 88ac, revision R3). Recorded as the maintainer's approvals. None reopens an architecture decision.
  - D4: T-ZAP-ORDER must pass before slice 5 merges. It never relaxes mandatory pidfd ownership or exit checks.
  - D13: init I remains implemented in Go.
  - D15: status records containing descriptors, and repeated producer records, are class (a) and require a full bounded Close.
  - Detection latency while Running is accepted for the initial draft and documented (18.2 item 6). Stop and Close perform bounded validation.
  - Initial drain cap: eight (18.2 item 12). Exceeding the cap must not accept an unverified status and must not silently ignore a protocol violation (3.4, 18.2 item 13).
  - D18: optional removal of CAP_SYS_ADMIN from P's bounding set is deferred pending compatibility evidence.
  - D2 and D12: a finite supervisor-side producer concurrency limit is required. Its value is determined and tested before slice 7 merges.
  - O-CL7: retain every descriptor needed for retry on incomplete cleanup (18.2 item 10).
  - C25 (R4 decision 7; the R3 approval used C16 for this item): sender-credential verification, covered by a mandatory production test (T-SENDER, 12.2). C16 is namespace identity (3.3 checks 1 to 3).
  - The owner notice in 0.3 is kept, changed as its change record states, and unresolved. D9 remains OPEN.
- R4 maintainer decisions (request 88ac, round R4). Recorded as approvals of the R4 defaults. None reopens an architecture decision.
  - Decision 1: every drain receive is non-blocking (MSG_DONTWAIT). A drain never blocks on channel traffic. Evidence E15.
  - Decision 2: a drain accepts at most eight complete records; a ninth is overflow. EINTR and EAGAIN are not records. A separate finite EINTR attempt budget (8, approved in R5; section 16, R5 item 1). EAGAIN ends a clean drain.
  - Decision 3: overflow at Stop: the remaining pidfd-only T3 runs, then ErrProtocolViolation, joined with an independently encountered Lost. Never ignored.
  - Decision 4: overflow at Close: safe bounded cleanup continues. Never nil after overflow. ErrProtocolViolation, joined with ErrCleanupIncomplete when cleanup cannot be proven.
  - Decision 5: missing pidfd(H0): no immediate return. Skip operations that need H0's pidfd, continue CL2 to CL4 with verified held pidfds (historical; the R6 final CL0 continues through CL4b and CL5, 6.4), return ErrCleanupIncomplete. No numeric PID or process-group signal.
  - Decision 6: retain every valid descriptor and state item needed for a cleanup retry when cleanup is incomplete. Close unexpected received descriptors at once. Release retry-critical handles only after proven complete cleanup.
  - Decision 7: C16 stays namespace identity. Sender-credential verification is C25.
  - Decision 8: a repeated authenticated status without descriptors or truncation is class (b), ExitStatus Unknown. An unparseable record is class (b) only if it identifies a status, comes from I, has no descriptors and is not truncated. All other malformed, unauthorized, non-status or gate-failing records are class (a). Tests: T-STATUS-POST (g) to (l), T-ADM-FRAMING rows.
  - Decision 9: decisions 5 and 6 apply to O-CL0 and O-CL7 in the contract, the state machine (6.4), the nil-return conditions and the tests.
  - Decision 10: T-CL0 added. T-ZAP-ORDER uses a test-only constructor. Merge gates and run counts on T07, T08, T-DRAIN-UNIT, T-DRAIN-FLOOD, T-DRAIN-STATUS and T-CLOSE-BOUND (12.2). T06b asserts descriptor retention. Post-status cases added to T-ADM-FRAMING and T-STATUS-POST. Watcher cancellation defined for T07 (6.6).
  - Decision 11: slices 3 and 4 may be developed separately. Neither may merge into a state that lets L or I survive supervisor death. T-DEATH passes on the combined launcher and Pdeathsig code before the first production merge of either (17.2).
  - Decision 12: the old E10 output is marked superseded in out/evidence61_v61.txt. The R3 full-suite runs (reviewer B ran the 23 base cases on the R3 build, 23 of 23 labels) are reviewer evidence, not author-bundle evidence. The complete 33-row suite ran on the R4 harness (out/frame-rerun-r4). No full Close execution is claimed from framing labels.
  - Decision 13: the maintainer accepted the corrected E10 labels for draft-start readiness. Independent B and C signoff remains pending until the R4 changed lines are reviewed (17.1).
  - Decision 14: check 1 stays PARTIAL. The owner notice in 0.3 is kept, with the process identifier removed and the other changes in its change record (0.3). Reviewer scratch copies with raw tgid values are not redistributed.

  R5 items (revision R5; referenced as "R5 item n" in this contract):
  - R5 item 1: the EINTR cap of 8 per drain is approved (R-D7, D-B). A ninth EINTR return in one drain is overflow (ErrProtocolViolation). At admission, a ninth EINTR return in one receive gives CLOSE:budget. The request asked for the approved bounded retry policy.
  - R5 item 2: zero-length and truncated records count toward the eight (D-E). Proposed for B and C review.
  - R5 item 3: the drain observation error is named ErrObservation. The name is used in the harness and the draft design; maintainer confirmation stays open (18.2 item 16).
  - R5 item 4: Unobserved follows Option Y (A41; R-D3). Proposed for B and C review.
  - R5 item 5: complete cleanup (CL7) means every nil condition of 6.4. After an overflow or observation error, the R5 text retained descriptors until process exit (proposed for B and C review). R6-2 supersedes that for CleanupComplete (section 16, R6-2). Reviewer C R-D1 asked for release after cleanup instead.
  - R5 item 6: gate 17.1(c) stays open pending R-D9. Decision 13 is not among the maintainer decisions given for R4; the maintainer confirms it (18.2 item 23).
  - R5 item 7: slices 3 and 4 land as one change set (R-D4). For merge purposes this replaces the separate-development wording of decision 11.
  - R5 item 8: CALL_BOUND, the drain call cap outcome, is not reached in the drain while the record cap and the EINTR cap hold. Production was to map it to overflow (proposed). Superseded by R6-5: ErrObservation (18.2 item 17).
  R6 decisions (corrective pass R6, request 88ac, R6 round). Recorded as maintainer decisions. None reopens an architecture decision.
  - R6-1: the maintainer accepts the corrected E10 labels for draft-start readiness only. Reviewer C R-D9 asks whether that statement confirms decision 13. The R6 final correction reads it as confirming decision 13 for draft-start readiness only, so gate (c) is MET on that scope (17.1; 18.2 item 23). The statement does not extend to slice merges, and the maintainer may still change that reading.
  - R6-2: descriptors are released after complete cleanup (CleanupComplete, 6.4 CL7), even when the drain recorded an overflow or observation error. This accepts reviewer C R-D1 and replaces the R5 retention reading (R5 item 5). Close still returns that error, not nil (CL7 nil rule).
  - R6-3: ErrObservation is a separate sentinel from ErrProtocolViolation (18.2 item 16).
  - R6-4: the architecture, the eight-record and eight-EINTR limits (decision 2, R5 item 1) and the production merge gates of 17.2 are unchanged. The R6 case list for T-DRAIN-UNIT (12.2) is the content of the slice 1 gate, not a new gate: cases (m) to (q) are added and case (l) moves to T-T2-POLL.
  - R6-5: CALL_BOUND is ErrObservation at the receive-call ceiling (17 recvmsg calls) without a conclusive result (3.4). The ninth record and the ninth EINTR return stay ErrProtocolViolation. R5 item 8 (overflow) is superseded. Per drain the ceiling is not reached while the caps hold; per receive it is reachable through repeated EAGAIN (18.2 item 29).

---

## 17. Implementation plan (for after review)

### 17.1 Start conditions

- Independent review (start gate (b) below): not done. The advisor calls and the R2 and R3 correction passes are not B or C signoff. Maintainer decisions D9, D10, D13 to D17 are recorded in section 16 as defaults; the R3 approvals are there too. D2 and D12 are needed only for slice 7.
- Draft implementation status: NOT CLEARED. Draft-start blockers, all required before any draft code is written: (a) PENDING: the focused changed-lines review of revision R6 final-2 by reviewers B and C (B and C returned REVISE on R6; the R6 final and R6 final-2 changes are listed in A51, A52 and A53, the R5 findings in 13.12 and the R6 dispositions in 13.13). (b) PENDING: the independent review in section 20 is not complete. Reviewer reports for (a) and (b) are separate artifacts. Each is bound to the immutable candidate hash it reviewed (source hash H2, and the archive sha256 once an archive is published). The archive under review does not contain its own future signoff; a signoff is recorded as a separate artifact. (c) MET for draft-start readiness only: the R6-1 maintainer statement accepts the corrected E10 labels for draft-start readiness, and the R6 final correction reads it as the confirmation of R4 decision 13 on that scope (section 16, R6-1; 18.2 item 23). The statement does not extend to slice merges. Items 3, 5 and 6 were approved in R3 (section 16). Item 12 of 18.2 was approved in R5. Item 16 is decided by R6-3 (ErrObservation). Item 17 is settled in R6 final by the per-receive and per-drain reading (3.4). Item 29 is decided as ErrObservation (R6-5); B and C review of that mapping is pending before slice 5 merges. Item 24 is updated in R6 final. Item 25 is accepted by R6-2 (maintainer decision, section 16). Items 15, 18 to 22, 26 to 28 and 30 of 18.2 stay open. D2 and D12 are needed for slice 7 only.
- Tier A status (12.2): T-N8, T-CAP-INH, T32, T-PTRACE-GO and T-PTRACE PASS on scratch evidence, not re-run in R2. T-ADM-FRAMING is label-level PASS on the R5 and R6 builds (E10-R5 and E10-R6, admission framing only; E10 label acceptance is MET for draft-start readiness only (R6-1); before them, the R4 build, E10-R4); production T-ADM-FRAMING is the slice 1 merge gate (18.2 item 7). Items 8 to 11 of 18.2 are merge gates for the slices named there, not start gates. D18 is not a start gate. D2 and D12 are needed only for slice 7.
- Repository rules (AGENTS.md): build tags for OS behavior; tests that use sockets carry the integration tag (channel tests use socketpair, so they carry it); ordinary tests deterministic and rootless; no em dashes; commit subjects short, imperative, with no Conventional Commit prefix; no attribution trailers (no Co-Authored-By, no Claude-Session); --help stays on standard fs.PrintDefaults formatting; version injection through -ldflags "-X main.version=..." is preserved.
- Build: CGO_ENABLED=0. Go 1.27.3 through the module.

### 17.2 Slices

| Slice | Scope | Tests and gates | Merge gate |
|---|---|---|---|
| 0 | Decisions only. Record D2, D9, D10, D12, D13 to D18, the R3 approvals (section 16), and the reading still open in 18.2 item 7. | Review record. No code. | None (no code) |
| 1 | Channel framing (channel_linux.go, pure parse file). Count rule, creds, MSG_TRUNC and MSG_CTRUNC, CmsgSpace sizes, record classes (class a and class b, D15), drain function (A40). Identity is an injected interface: slice 1 never calls PIDFD_GET_INFO. | Pure parse tests (rootless, deterministic): the framing rows of T-ADM-FRAMING except init_pidfd_not_sender and producer_not_child (slice 6). T32 production. Socketpair tests with the integration tag: T-DRAIN-UNIT with the R6 case list (12.2): cases (a) to (k) and (m) to (q); case (l) moved to T-T2-POLL. Optional parser fuzz (recommended, not required by AGENTS.md). Slice 1 production merge gates (R6 final): T32 production; T-DRAIN-UNIT with the R6 case list; T-ADM-FRAMING production with the 47-row set of E10-R6 (the E10-R6 build matched the E10-R5 labels in all 47 rows, 0 differences); the differential parser oracle (to be ported to the R6 grammar, 18.2 item 19; the generator is not in this branch, so NOT RUN), TestR6IntegerGrammarMatchesRefParse and a FuzzParseWireAgreement seed run; the A, B and C checks; the full E10 rerun on the production build with the 47-row set (18.2 item 8). Linux arm64: GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c must compile the channel files, and arm64 integration runs are required when the gate runs. No 386 obligations (3.2). Production gates: NOT RUN until run. | A: ./scripts/check. B: coverage shard with the integration tag, and netns_integration registration if the package needs it. C: ./scripts/check --race (channel change). 18.2 item 8: the full E10 (47 rows, E10-R6 cases) is rerun on the production build before merge (MB14, R3-8, R3-10). |
| 2 | pidfd admission primitives (pidfd_linux.go). PIDFD_GET_INFO wrapper with mask rule; namespace fds by ioctl; st_dev and st_ino comparison (C16); fail closed on ENOTTY and EINVAL. Non-Linux stubs (*_other.go). | Rootless: T-A-ADM rootless part (pidfd_open(self), own namespaces); fail-closed tests with injected errors; T120 (CI prints kernel, util-linux, Yama scope and uid) before any namespace test. The userns part is deferred to slice 6. | A: ./scripts/check. C: ./scripts/check --race. |
| 3 | Namespace launch and init (init_linux.go, launch_linux.go). Prerequisite: the slice prerequisites paragraph before 17.3 (R4 decision 11). Internal init entry (D13). L started by nsenter and unshare --pid --fork --kill-child on the base holder H0, without Pdeathsig (slice 4). R2 and R3 checks before init; R6 drop and assertion on the locked forking thread; FD_CLOEXEC on the channel child end before the fork of P; exec of P; exact post-exec fd assertion. | T-N8 production, T-CAP-INH production, T-PTRACE production with the drift guard, T-PTRACE-GO production, T-GETFD, T-HOST-REACH-D, T-SIG-INIT. Negative: fork-only path absent (S21). | B: coverage shard with the integration tag; package registered in netns_integration (ci.yml lines 371 and 387). C: ./scripts/check --race. |
| 4 | Launcher hardening (launcher_linux.go; namespace_linux.go). Prerequisite: the slice prerequisites paragraph before 17.3 (R4 decision 11). Pdeathsig SIGKILL on L set before the exec of nsenter, with the creator thread locked for L's lifetime; helper open-verify-exec (D7, A20); removal of the base killGroup (namespace_linux.go line 292), the PID-number holder branch (lines 289 to 291), and group signals (child_linux.go lines 275, 278, 287). | T-DEATH (5 runs, control, creator-thread exit), T-HOLDER, T-HELPER, T-HOLDER-KILL-GROUP-ABSENT, T-ORPHAN. | B and C as slice 3. |
| 5 | Lifecycle (lifecycle_linux.go). Done, Lost, Stop including the T2 drain and its overflow handling (status-result tests stay in slice 6), Close (CL0 to CL7, including the missing-H0 path and overflow at CL0a), watcher (6.6), mutex for Stop and Close, Start(ctx) cancellation (6.2). Lifecycle tests build handles through a test-only constructor in _test.go files (T-NO-BYPASS). | T-DONE, T-CL0 (mandatory pre-merge), T-WATCH (T07), T08 (subcases (a) to (c)), T-CLOSE-BOUND, T-ZAP-ORDER (mandatory pre-merge, D4), T-CLOSE-LIVE, T-STOP, T-REENTRY, T-DRAIN-FLOOD, T-CTX, T-NO-BYPASS (slice 5 part), T-T2-POLL (R6; the T2 readiness wait, 12.2), T-CL7-RELEASE and T-CL6-JOIN (R6 final-2, 12.2). Each with 5 runs where timing matters. | B and C. Mandatory before slice 5 merge: T-CL0, T07, T08, T-CLOSE-BOUND, T-ZAP-ORDER, T-DRAIN-FLOOD, T-T2-POLL, T-CL7-RELEASE, T-CL6-JOIN, TestCloseCommitIsFrozenAtCL0a, TestCloseWatcherJoinSharesOneDeadline. Items 9 (O-CL0) and 10 (O-CL7) are decided (R4 decisions 5 and 6). |
| 6 | End-to-end admission and order (admission_linux.go). Checks 1 to 10 in production; sender credentials; ordering; post-admission status rules. | T-A-ADM (userns part), T-ADM-PPID negatives (including init_pidfd_not_sender and producer_not_child), T-SENDER (including L), T-ADM-ORDER (including pre-admission status rows), T-STATUS-POST, T-DRAIN-STATUS, T-STOP-KNOWN, T-FINAL-COMMIT (R6 final-2, 12.2), T-NO-BYPASS (slice 6 part), T06b (mandatory pre-merge). | B and C. Mandatory before slice 6 merge: T06b, T-ADM-ORDER, T-A-ADM (userns part), T-ADM-PPID, T-SENDER, T-STATUS-POST, T-DRAIN-STATUS, T-STOP-KNOWN, T-FINAL-COMMIT. T117 in every slice. |
| 7 | RLIMIT (blocked by D2 and D12). P1, P1a, P5 policy. | T-LAUNCH-LIMIT, T-RL-AGG, T-F6b. Bounded loops only. | B. |
| 8 | Lease and metadata. | T-LEASE, T-HOST-REACH same-uid rows. Cross-uid rows deferred (Tier C). | B, plus the base E integration pattern. |

Slice prerequisites (R4 decision 11; R5). Slices 3 and 4 land as one change set (R5 item 7; R-D4). Neither may merge into a state that lets L or I survive supervisor death. Slice 3 starts L without Pdeathsig (row 3), so the first production merge of the combined slices 3 and 4 requires the combined launcher and Pdeathsig guarantees: T-DEATH (5 runs, with the control and the creator-thread exit case) and T-ORPHAN must pass on the combined slice 3 and slice 4 code.

### 17.3 Merge gates (per slice)

- A: ./scripts/check passes. Ordinary tests are deterministic and rootless.
- B: integration tests (tag integration) run in the coverage shard (ci.yml line 336). Any new package is registered in the netns_integration lists (ci.yml lines 371 and 387). Discovery covers only the integration tag.
- C: ./scripts/check --race for launcher or channel changes (AGENTS.md).
- Kernel floor: T-KERNEL-FLOOR is Tier C. Recorded in the merge notes of slices 2 and 4.
- T120 (slice 2): the CI prints kernel, util-linux, Yama scope and uid before any ptrace or namespace test runs.
- T-NO-BYPASS (slices 5 and 6): no exported path reaches Running without checks 1 to 10.
- Production merge tests added in R6 final-2 (not run): T-T2-POLL (slice 5, 5 runs), T-CL7-RELEASE and T-CL6-JOIN (slice 5), TestCloseCommitIsFrozenAtCL0a (slice 5, 88ac), T-FINAL-COMMIT (slice 6). The two-watcher join is part of T-CL6-JOIN. Arm64 execution of the production tests (slices 3 to 5) and the full production cleanup tests (T-CL0, T-ZAP-ORDER, T-CLOSE-BOUND, T-CLOSE-LIVE, T08) remain merge gates. The scratch harness is not evidence for them.
- Start gates are in 17.1. Merge gates per slice are in 17.2 and in the Tier B table of 12.2.

### 17.4 Test runtime budgets

- Each Done wait is 5 s, the watcher join is 1 s for all watchers together, Close is at most 26 s (section 6.4). Drain: at most 8 accepted records, at most 8 EINTR returns and at most 17 recvmsg calls per drain, every call non-blocking (A40); CL0a is non-blocking, and a poisoned drain makes zero recvmsg calls (R6). Admission: at most 17 recvmsg calls and at most 8 EINTR returns per admission receive, inside admissionDeadline (3.2). Tests that wait for these use the production constants and do not widen them (AGENTS.md runtime rules do not apply to this package; the test deadlines follow the same bounded-timeout rule).

---

## 18. Verify-and-stop

Checks run for this document. Results recorded in 18.1 after the checks run.

1. Every number in section A and section 12 matches out/evidence61_v61.txt or the named bundle file.
2. Every id in N1 to N17, ADV-1 to ADV-6, F1 to F12, C1 to C25 (reviewer B) and X1 to X5, Y1 to Y12, S14 to S20 (reviewer C) has a disposition row in section 13.
3. The owner notice in section 0.3 does not match the carried notice text byte for byte. The process identifier is removed (the original is held in restricted storage). The heading, item 3 and the status paragraph also changed; the 0.3 change record lists each change. No byte match is claimed.
4. The bundle has no host identifier (the host name, the user name, the home path, the temp path, session identifiers, reviewer directory names), no em dash, and no en dash, in the contract or in the bundle files.
5. The normalized outputs contain no host pid value at or above 65536, and no socket inode in raw form.
6. The bundle archive has owner 0 and group 0 on every entry.

### 18.1 Results

Commands are in `contract-v6.1-bundle/README.md`. Results for checks 1 to 6 above:

1. PARTIAL. Checked: the chain lines 3 to 11 (E9), the framing table (lines 43 to 66, 23 of 23 kernel-fact rows), the gocaps runs (run1 to run5), host metadata, and the normalized row counts (45 chain, 23 frame, plus 2 rerun rows in R2 and 2 in R3: 72 in total). Compared line by line to bundle evidence: A1, A6 (recorded values only; its class is set by D15 in section 3.4), A8, A9, A12, A13, A17, S14 and S15. Bundle-cited and not compared, so open: A2, A3, A4, A5, A7, A11, A14, A15, A16, A29, A31, S18 (E9 part), S19 and S20. Cited to v6 measurements outside this bundle, not re-run: A18, A19, and S18 (v6 E5 part). Cited to reviewer measurements outside this bundle, not re-run: A20 to A28, A30, A36, S16 and S17. Design, review or disposition text with no measurement: A10, A32 to A35, A37 to A44 and A46. Measured in this round for two cases only: A45 (out/frame-rerun-d15). Not measured, so no raw comparison exists: C16; a status record with wrong or missing creds; and the D15 labels of status_with_fd_after_producer and duplicate_producer (E10 lines 60 and 62, and line 75 by descriptor count), which recorded UNKNOWN where D15 expects CLOSE. R3 reran the two cases after the decide fix: both PASS on actual classification (out/frame-rerun-r3). This is label and fd-count evidence only; it does not show that the full Close ladder ran (T-STATUS-POST rows (d) and (f)). The full 23-case E10 is not rerun on the R3 build. The 12.1 carried rows match v6 verbatim; their v6 numbers were not re-run. The E10 references added in this pass (lines 59 to 63, 75 and 78 to 81) fall inside the 81-line evidence file. out/evidence61_v61.txt was produced in v6.1 with the v6.1 expectations (23 of 23) and was not re-run in revision R2.
2. PASS. Every id in N1 to N17, ADV-1 to ADV-6, F1 to F12, C1 to C25 (reviewer B) and X1 to X5, Y1 to Y12, S14 to S20 has a `| ID |` row in section 13 (S14 to S20 in 13.7, D1 to D12 in 13.8). Revision R2 adds 13.9 (SB1 to SB7: 7 rows; MB1 to MB15: 15 rows) and 13.10 (reasons 1 to 7: 7 rows; items 8 to 16: 9 rows; two correction rows). Revision R3 adds 10 rows to 13.10 (R3 items 1 to 10). Section 13 table rows: 172 in R4 by this script. The R3 snapshot gives 146 by the same script, which includes its 10 R3 rows; R4 adds 25 rows to 13.11 and row C25 to 13.4. The earlier figures (146 at R2, 156 at R3) do not reproduce with this script and are superseded. Checked by script over the section 13 tables (one row per id, no gaps). Content comparison for N, ADV, F, C, D, X and Y ran in v6.1; its mismatches are corrected in section 13 or open in 18.2.
3. PASS on the R2 text, which still held the process identifier (historical). Under R6 final-2 the notice differs from that text only in the process identifier, which is removed.
4. PASS for the user name, home path, temp path, session identifiers, reviewer directory names, and em or en dashes, checked by grep in revision R2 over the working contract, the bundle directory and the extracted archive. The host name is not checked in this round: this review does not run `uname -n`, and kernel metadata comes from `uname -srvm` only.
5. PASS, after one fix in this round. The first chain normalized file left 60 `tgid` values (host thread-group ids, all at or above 65536) unmapped, because the normalizer mapped only keys whose name contains `pid`. Revision R2 adds `tgid` to that rule (`src/tools/bundle61.py`), regenerates `out/chain/results.normalized.jsonl` from the same raw results, and copies it into the bundle. The frame file is byte-identical. Re-check of the 72 normalized rows (45 chain, 23 frame, 2 rerun in R2, 2 rerun in R3): no integer at or above 65536 except capability masks in the CapInh and CapAmb strings, which a decimal pattern matches; no `/tmp`, `/home` or `/run/` path; no bracketed 4-digit inode number. `kernel.pid_max` (4194304) and `user.max_user_namespaces` (126328) in `out/host_metadata.txt` are kernel limits, not host pids. `out/evidence61_v61.txt` has no socket inode numbers; its long digit runs are hex masks and flags. The gocaps values are CapBnd and CapPrm masks, not host identifiers.
6. PASS (checked after the final archive build). The R3 archive (renamed contract-v6.1-bundle-r3.tar.gz at the review root in R4) had 42 entries (R3 count: 39 in R2, plus the out/frame-rerun-r3 directory and its two files). All are owner 0 and group 0 (tar --numeric-owner).

Revision R4 results (checks run on the R4 edits; scratch commands; Python run with `python3 -I -B`):

- R4-1. Full E10 on the R4 build: 33 of 33 rows pass on labels (out/frame-rerun-r4). File descriptor count is 7 to 7 on every row. This is label evidence only. It does not show full Close execution; the production tests in 12.2 cover that.
- R4-2. Harness: `src/frame61/main.go` in the bundle is byte-identical to the source of the R4 build (go1.27.3 module toolchain, CGO_ENABLED=0). Against the R3 snapshot it has 39 added and 9 removed lines (`diff -u`).
- R4-3. Drain probe (E15, out/drain-probe/results.txt): an empty receive with no flags returns EAGAIN after about 2.04 s (5 of 5). With MSG_DONTWAIT it returns EAGAIN at once (5 of 5). A receive after the peer closes returns EOF at once (5 of 5). This is kernel evidence for AF_UNIX SOCK_SEQPACKET only. It supports decision 1.
- R4-4. Leak check: 105 normalized rows; 0 pid-keyed values and 0 other integers at or above 65536 (flags excluded). Text host-range numbers appear only in out/host_metadata.txt, as the sysctl values kernel.pid_max and user.max_user_namespaces.
- R4-5. Dash scan: 0 em dashes and 0 en dashes in the contract and in every bundle file. Every bundle file is UTF-8.
- R4-6. Identifier scan: no host name, user name, home path, scratch path or session identifier in the bundle (case-insensitive grep).
- R4-7. Owner notice (0.3): checked against the maintainer text before the process identifier was removed (R6 final-2).
- R4-8. Archive: built with `tar --owner=0 --group=0 --numeric-owner` into a fresh directory, extracted into a new empty directory, and compared with the bundle. Its entry checks are not repeated here, because the archive contains this section.
- R4-9. Not run in this round: the R4-changed 12.2 rows with no run result, each marked Not run in 12.2: T06b, T07, T08, T-CL0, T-CLOSE-BOUND, T-ZAP-ORDER, T-STATUS-POST, T-DRAIN-UNIT, T-DRAIN-STATUS, T-DRAIN-FLOOD, T-ADM-FRAMING production, T-SENDER. The production E10 rerun is the T-ADM-FRAMING production row (slice 1). These are production or test gates in 12.2 and 17.2.

Revision R5 results (checks run on the R5 edits; scratch commands; Python run with `python3 -I -B`). PASS, FAIL and NOT RUN are as stated.

| ID | Check | Result |
|---|---|---|
| R5-1 | E10 on the fresh R5 build (sha 917f42b8): 1000 iterations, 47 rows each, admission framing | PASS on labels: 47000 rows, 0 wrong labels, 0 failing iterations, 0 wrong fields. Poll EINTR 3, recv EINTR 0 (out/frame-rerun-r5) |
| R5-2 | E10 on the supplementary root build (sha e6685f56, source not recorded): three runs of 1000 iterations | PASS on labels: 141000 rows, 0 failing iterations. Poll EINTR 14 (4, 8 and 2), recv EINTR 0. Supplementary only |
| R5-3 | Totals across the four E10-R5 runs | PASS on labels: 4000 iterations, 188000 rows, 0 failing. Rule of three: 0.3% per iteration (fresh, n = 1000) and 0.075% (all, n = 4000) |
| R5-4 | R4 control binary (sha 1f207190), 2000 iterations | Not a gate. 42 first-attempt failing iterations (2.1%); cause inferred (EINTR), not measured. File counts 527 and 539 exceed 500 iterations; not reconciled |
| R5-5 | Frame harness unit tests (receive_test.go, fuzz_test.go), frozen files | PASS: 24 top-level tests, 59 PASS lines including subtests, 0 FAIL |
| R5-6 | FuzzDecideOracle, 10 s | PASS: 418108 execs |
| R5-7 | FuzzParseWireAgreement, 10 s | PASS: 274743 execs |
| R5-8 | TestParseWireEscapedNames | PASS |
| R5-9 | Generated differential oracle, 150 seeds | NOT RUN: encodes the R4 grammar and must be ported to the R6 grammar (3.2, 18.2 item 19) |
| R5-10 | Drain, overflow, observation error, V not 1, and recvmsg EINTR budget at a drain, under E10 | NOT RUN: E10-R5 measures receiveOne only. Seam and fuzz tests cover these (18.2 item 18) |
| R5-11 | Production T-DRAIN-UNIT and T-ADM-FRAMING production | NOT RUN (slice 1 merge gates) |
| R5-12 | Fuzz exclusion count | NOT RECORDED (18.2 item 20) |
| R5-13 | Post-edit checks 3 to 6 of section 18 (owner notice, dashes, identifiers, integers, archive owner) | Not repeated here, because the archive contains this section (same rule as R4-8) |

#### 18.1 addition: revision R6 results (checks run on the R6 edits; scratch commands; Python run with `python3 -I -B`; Go run with CGO_ENABLED=0 and go1.27.3). PASS, FAIL and NOT RUN are as stated.

| ID | Check | Result |
|---|---|---|
| R6-V1 | Unit tests on the R6 sources (go test -count=1 -v) | PASS on amd64 for the round 2 source H: 42 top-level tests, 89 PASS lines (round 2 record; the R6 final-2 counts are in A53) including subtests, 0 FAIL (out/frame-r6-frozen). The round-1 run on the pre-round-2 source was 38 top-level tests and 77 PASS lines (out/frame-r6-tests/unit-amd64-round1-authoritative.txt). |
| R6-V2 | Red reproducer: R5 sources with an R5-signature repro_test.go | FAIL as expected: the four TestR6Repro tests fail on R5, and 24 top-level tests pass (out/frame-r6-tests/red-r5-final.txt). The reproducer differs from the final repro_test.go in call signatures only (bundle README) |
| R6-V3 | Mutation A: descriptor-count case removed from the shared status gate | Caught: FAIL in TestR6StatusGateSameForDecideAndT2 and TestR6ReproDrainStatusWithFdIsNotKnown (out/frame-r6-tests/mutation-a-log.txt) |
| R6-V4 | Mutation B: -0 rejection removed | Caught: FAIL in TestR6StatusGateSameForDecideAndT2 and TestR6IntegerGrammarMatchesRefParse (out/frame-r6-tests/mutation-b-log.txt) |
| R6-V5 | E10 on the R6 build, 47 rows, one run (frame61 R6 sources, go1.27.3, CGO_ENABLED=0) | PASS on labels: 47 of 47 pass; 0 label differences from the E10-R5 summary (out/frame-rerun-r6). Admission framing only |
| R6-V6 | FuzzDecideOracle, 10 s | PASS: last progress line 263539 execs (final run) |
| R6-V7 | FuzzParseWireAgreement, 10 s | PASS: last progress line 146326 execs (final run) |
| R6-V8 | Production T-DRAIN-UNIT (R6 case list), T-T2-POLL, production T-ADM-FRAMING, production T32, T08 subcase (c), T-CLOSE-BOUND W3 and W6, T-CL0 | NOT RUN (slice gates, 17.2) |
| R6-V9 | Generated differential oracle (150 seeds) | NOT RUN (18.2 item 19) |
| R6-V10 | Checks 3 to 6 of section 18 on the bundle: owner notice, dashes, identifiers, integers at or above 65536 | The owner notice block (0.3) is byte-identical to the pre-correction contract. [Superseded in R6 final-2 (88ac): the block differs from the carried R6 text beyond the identifier; see the 0.3 change record.] The bundle scans are not repeated here, because the archive contains this section (same rule as R4-8) |
| R6-V11 | Final R6 correction: call ceiling, commit rule | Red on the pre-correction snapshot: TestR6CallCeilingIsObservation FAIL with `call ceiling poisoned with protocol violation: receive budget, want ErrObservation` (a behavioral red). The commit tests (TestR6FinalExitCommit) do not compile on the snapshot (`undefined: commitExit`): an absence-of-commit red, not a behavioral one. PASS on the R6 final sources: TestR6CallCeilingIsObservation, TestR6PollRawOnSocketPair (real socket pair), TestR6FinalExitCommit (four subtests). Mutations on the commit rule: removing the poison check fails poisoned_handle_is_never_known; removing the exitRecs check fails second_record_at_cl0a_is_unknown. No -fuzz run in this round: decide, parseWire, statusGate and fuzz_test.go are unchanged; their seeds run through go test (R6-V13). |
| R6-V12 | arm64 build checks: test compile and vet | On the frozen source H with CGO_ENABLED=0 and GOTOOLCHAIN=go1.27.3: GOOS=linux GOARCH=arm64 go test -c and GOOS=linux GOARCH=arm64 go vet, both exit 0 (out/frame-r6-frozen). arm64 tests NOT RUN. Integration on arm64 NOT RUN |
| R6-V13 | D's adversarial stop suite on frozen H (stop_test.go, sha256 818ae2bd91a5ca477a5b11cb133823609568010713ad2f0b8cb86b0fcc39a929 for the frozen file held outside this branch; the file in this branch differs by the build tag added in a356a15b) | TestStopRunCase PASS: 8 table cases, 9 PASS lines with the top-level test, 0 FAIL, on frozen source H = 6f86c04884ba5855d5b326ab6339c8867848ab3c98d04378dbc93efa08b34515 (SHA-256 of out/frame-r6-frozen/src-manifest.txt, which lists the SHA-256 of each file in src/frame61 except SHA256SUMS). Command: go test -count=1 -timeout 120s -run '^TestStopRunCase$' -v . The close_then_later_step_probe case logs only (launches 1, recvmsg 1, decision CLOSE:early_status). |
| R6-V14 | Per-receive and per-drain budget tests (r6_budget_test.go) | TestR6BudgetPerReceiveRestarts PASS: two receives, each 16 EAGAIN then one datagram, 34 recvmsg calls in total. TestR6BudgetDrainEndsOnFirstEAGAIN PASS: one call, End EAGAIN. Mutants on copies: a per-record reset of the drain count fails TestDrainCallCeiling; a drain that repolls after EAGAIN fails TestR6BudgetDrainEndsOnFirstEAGAIN and TestDrainCallCeiling. Full unit run on frozen H: 42 top-level tests, 89 PASS lines, 0 FAIL |
| R6-V15 | CLOSE terminal in runCase (r6_stop_close_test.go) | TestR6CloseIsTerminalInRunCase PASS: 1 sender launched, 1 recvmsg call, decisions exactly CLOSE:early_status. Mutant with the CLOSE stop removed on a copy: this test FAILS; D's probe then logs launches 2, recvmsg 4, decisions CLOSE:early_status, DISCARD, DISCARD, DISCARD. The probe does not assert, so TestStopRunCase still passes under the mutant |
| R6-V16 | E10-R6 matrix on the frozen binary (47 rows) | Binary built from frozen H with CGO_ENABLED=0 and go1.27.3; run with FRAME61_CASES unset: SUMMARY pass=47 total=47. Labels compared with E10-R5 (out/frame-rerun-r5/summary.txt): 0 label differences. out/frame-r6-frozen |

### 18.2 Unresolved risk after verification

- Check 1 is partial (see 18.1). The v6 raw results (`contract-v6-bundle.tar.gz`, outside this bundle) were not re-run here. The carried v6 rows in 12.1 match the v6 text verbatim.
- Scratch evidence on one host: kernel 7.2.11 on x86_64, util-linux 2.41.6, Yama scope 0. Other kernels and hosts are not measured.
- Reviewer-measured rows (RC-Y1, RC-Y2, RC-Y5, RC-Y11, and the others in section 12.1) were not re-run in v6.1.
- Gates not run: the production and Tier B gates listed in CHECKLIST.md sections 3 and 5 (the complete list). Not repeated here.
- S18 same-run condition is open: no single run yet holds the none control and the ptrace gate.
- Owner notice (D9, the PID in 0.3) is open. It needs the maintainer's action. Whether a PID-number signal was sent in this phase is not established; the text scan in 18.2 item 24 is not signal evidence.
- Open items after revision R4 (items 7 to 15 updated in R4; items 1 to 6 are unchanged from R3): (1) T06b is mandatory before merge of slice 6, not run (X4). (2) T07 (TestWatcherCancelJoinsWithinDeadline), T08 (TestCloseRetryRepeatsOnlyFailedSteps) and T-CLOSE-BOUND (testable bound, R3) are defined in 12.2 for slice 5 (Y9), not run. (3) D4: approved in R3 (request 88ac): T-ZAP-ORDER must pass before slice 5 merges. It never relaxes mandatory pidfd ownership or exit checks. (4) D13: approved in R3: I stays Go. The gates in 16 D13 are not run; a non-Go init needs separate evidence and approval (Y12). (5) D15: approved in R3: status records containing descriptors, and repeated producer records, are class (a) and require full bounded Close. Reviewer C (Y8) asked for full Close on all unknown or duplicate records; the maintainer rule separates status content from control records. (6) Detection latency: accepted for the initial draft and documented. No reader runs while Running in v6.1, so a class (a) record is acted on at the next read (Stop, Close or EOF). Stop and Close perform bounded validation. (7) T-ADM-FRAMING labels: decided in R4 (maintainer decision 13). The R2 rerun failed on the two superseded labels (E10-R2). The R3 rerun passed on actual classification (E10-R3). The full E10 passed on labels on the R4 build (E10-R4, 33 rows). The maintainer accepted the corrected labels for draft-start readiness; the R6-1 statement restates that scope as draft-start readiness only. Production T-ADM-FRAMING is the slice 1 merge gate. (8) decide() in the frame harness: R3 changed the post-admission branch (decidePost); R4 (decision 8) changed it again. Descriptors on a status record and repeated producer records return CLOSE. An unparseable record returns UNKNOWN:malformed only when its type field decodes to status, with creds pid(I), no descriptor and no truncation (R4 decision 8). Otherwise it returns CLOSE:malformed. Records after a valid status that are not statuses, or that fail a gate, now return CLOSE; before R3 they returned UNKNOWN:after_terminal. Before R4 no row exercised either change; the E10-R4 rows now do. The full E10 was rerun on the R4 build (E10-R4, 33 rows, all pass). It must be rerun on the production build before slice 1 merges (MB14, R3-8, R3-10), with the 47-row set of E10-R6 (the E10-R6 build matched the E10-R5 labels in all 47 rows). Merge gate, slice 1. (9) O-CL0: decided in R4 (maintainer decision 5). CL0 does not return at once. It skips CL1 and the H0 wait of CL5, continues through CL4b on the held pidfds (R6 final; the R4 wording was CL2 to CL4 on I and L), and returns ErrCleanupIncomplete with H0 unobserved (6.4 CL0, test T-CL0). No numeric PID or group signal. Merge gate, slice 5 (T-CL0). (10) O-CL7: decided in R3 (request 88ac) and restated in R4 (decision 6): retain every valid descriptor and state item needed for retry on incomplete cleanup; close unexpected received descriptors at once; release only after proven complete cleanup. CL7 and T06b now state the same retained set. Residual: a caller that never retries keeps those descriptors until the process exits. Document this in the Close API comment at slice 5. (11) S2 (C16): checks 1 to 3 (st_dev and st_ino) are not measured. E10 does not implement checks 1 to 4 for init or checks 6 and 8 for the producer, and must not be cited as S2 coverage. Gates: T-A-ADM rootless (slice 2) and userns (slice 6). (12) Drain cap: eight accepted records (R3 approval; R4 decision 2). The EINTR attempt budget is a separate finite limit. Value approved in R5: 8 EINTR returns per drain. Approved consequence: a ninth EINTR return counts as overflow (ErrProtocolViolation, item 13), and at admission a ninth EINTR return gives CLOSE:budget (3.2). The request fixes only that the budget is finite (section 16, R5 item 1; R-D7, D-B). At most 17 recvmsg calls per drain. T2 waits at most 1 s for readiness; the drain itself is non-blocking and adds no wait. (13) Overflow (3.4): decided in R4 (decisions 3 and 4). After overflow at T2, Stop runs T3 and returns ErrProtocolViolation, joined with any Lost. After overflow at CL0a, Close never returns nil; it returns ErrProtocolViolation, joined with ErrCleanupIncomplete when cleanup cannot be proven. Merge gate, slice 5 (T-DRAIN-FLOOD). (14) C16: decided in R4 (decision 7). C16 is namespace identity (3.3 checks 1 to 3). Sender-credential verification is C25 (3.3 check 10; T-SENDER).
- (15) Drain receive errors other than EINTR, EAGAIN and EOF (A40): R4 ended the drain with no status accepted and no Lost or Close consequence. R5 names this an observation error (ErrObservation; separation decided by R6-3; name and wording pending B and C confirmation, item 16). Consequences: ExitStatus Unknown; Stop returns an error wrapping ErrObservation, joined with any Lost, and never nil; Close never returns nil (3.4, 6.3, 6.4, S28). The name and wording remain pending B and C confirmation (item 16).
- (16) ErrObservation (R6-3): a separate sentinel from ErrProtocolViolation. The R6-3 maintainer decision fixes the separation. The sentinel name and wording await B and C confirmation before slice 5 merges.
- (17) CALL_BOUND: settled in R6 final. Per receive, the 17-call ceiling (EAGAIN included) is reached through repeated EAGAIN in receiveOne; the mapping is ErrObservation (3.4, section 16 R6-5). Per drain, the ceiling is not reached while the record cap of 8 and the EINTR cap of 8 hold: the 17th call is the last call a drain can make, so the drain check is defensive. R5 item 8 (overflow) is superseded. A ninth record and a ninth EINTR stay ErrProtocolViolation.
- (18) Drain path not measured on the kernel: E10-R5 measures receiveOne (admission framing). Overflow, observation error, V not 1 and the recvmsg EINTR budget at a drain are covered by seam and fuzz tests on the scratch harness only (receive_test.go, fuzz_test.go). Production T-DRAIN-UNIT (slice 1) is the gate.
- (19) Generated differential oracle (150 seeds): NOT RUN. It encodes the R4 grammar and must be ported to the R6 grammar (3.2) before it counts.
- (20) Fuzz exclusion count: NOT RECORDED, with reason. FuzzDecideOracle has one exclusion class: payloads longer than dataBuf (1024). The kernel truncates them, and MSG_TRUNC decides the outcome before any payload parsing (fuzz_test.go header). go test -fuzz reports no per-filter count, so the number of skipped inputs is not measured. The header names the deterministic coverage of the class: E10 rows init_oversize_1500 and known_then_status_truncated, and TestZeroByteBufferTruncIsRecordAndConsumes.
- (21) init_escaped_type_name is misnamed. The row has a plain payload, {"v":1,"type":"init"}, and tests no escape. Disclosed, not renamed. Escaped names are covered by TestParseWireEscapedNames and by escaped seeds in FuzzParseWireAgreement.
- (22) Root binary sha e6685f56: source not recorded. Used for three of the four E10-R5 runs, as supplementary evidence only. It is not the fresh build.
- (23) Decision 13 (R-D9): gate 17.1(c) is MET for draft-start readiness only, on the R6-1 statement (section 16). The statement does not extend to slice merges, and the maintainer may still confirm or change that reading. Start gate (c), scoped.
- (24) Owner notice (D9): OPEN. It needs the maintainer's action. The text in 0.3 changes the carried notice beyond the process identifier (the 0.3 change record lists each change); the identifier is removed, and restricted storage holds the original. The counts below are text-match counts from a scan of session files. A text match is not evidence that a signal was sent, and no count here is a signal count. Groups: (a) This session: the scan matched 3 kill-call tokens and 1 pkill token before the no-signal constraint text, and 1 kill-call token names a process group. Whether any signal was sent is not established by this scan, and neither the earlier no-signal statement nor its contrary is asserted here. (b) Other session files on the same account: the text scan matched 7 kill-call tokens and 1 pkill token before their constraint text, and 6 kill-call tokens in files with no constraint text. These are text matches, not signals. Attribution is not established from this view, and this item asserts no reviewer conduct. (c) Not checked and not asserted: whether the pgrep matches were read-only, and whether the R4 and R5 rounds sent any PID or process-group signal after the constraint text.
- (25) Descriptor release after an overflow or observation error (6.4 CL7, A27, R6-2): descriptors are released on CleanupComplete, and Close still returns the sticky error. ACCEPTED in R6 by the maintainer. The B and C review of R6 is pending.
- (26) Option Y for Unobserved (A41) and counting of zero-length records (3.2, A40). R5 proposals. For B and C review.
- (27) Known restoration after an observation error, and a status read after a poisoned drain, are not reached by the runCase harness, because each step is a new sender process. Seam tests only (TestR6ObservationErrorWrapsAndPoisons, TestR6OverflowPoisonsLaterStatus, TestR6PostStatusErrorIsNotKnown). Production T-DRAIN-UNIT is the gate (R6).
- (28) T-T2-POLL: the T2 readiness wait (POLLNVAL, a poll error other than EINTR, EINTR inside the deadline) is not in the R6 harness and is not run. It is a slice 5 test (R6).
- (29) CALL_BOUND mapping: decided in R6 final as ErrObservation (3.4; section 16, R6-5). The harness agrees (TestR6CallCeilingIsObservation). R5 item 8 (overflow) is superseded. B and C review of the mapping is pending before slice 5 merges.
- (30) Integer rule on a 32-bit build: 3.2 requires the integer to fit the Go int of the build target. The check runs on amd64 only; a 32-bit build is not built or measured (R6). Portability (R6 final): arm64 is test-compiled and vetted on scratch, not run; there are no 386 obligations.

---

## 19. Harness limitations (honest record)

- The flat harness is test-only Python (E9, E11). The frame harness is test-only Go (E10). The gocaps oracle is test-only Go (E12). None is product code.
- The producer and init in E9 are Python. Production will be Go. Timing and signal handling of a Go init are not measured.
- The holder H0 is `unshare --user --map-root-user --net`, a stand-in (D6), in E9. The base holder is not measured.
- Only x86_64, one kernel (7.2.11), util-linux 2.41.6, Yama scope 0.
- The frame harness uses the same syscall shape as section 3.2 on the receive side. The sender side is a test helper.
- The v6 E1 to E8 raw data is in contract-v6-bundle.tar.gz and carried unchanged. Reviewer probes (RB-P1 to RB-P6) and reviewer C results (RC-Y1 to RC-Y12) were not re-run in v6.1, except that the per-thread oracle (E12, E13) was re-run on go1.27.3.
- Normalization in the bundle maps host pids (values at or above 65536) and socket inode numbers to ordinals. Namespace-local pids (1, 2) are kept. Filesystem paths in fd targets are reduced to their basename under a scratch placeholder.
- Revision R2 adds a FRAME61_CASES filter to the frame harness (off by default). The filter changes no decision. R3 changed the post-admission branch (decidePost, A48), and its header comment is updated. The bounded rerun output is in out/frame-rerun-d15 (R2: both FAIL on the label) and out/frame-rerun-r3 (R3: both PASS on actual classification). The full E10 rerun on the R3 build is open (18.2 item 8). Its probe lines, which carry host pids, are not copied into the bundle.
- R4: the drain probe (E15) is a Python script in src/flat61. It is kernel evidence for MSG_DONTWAIT and blocking receives on AF_UNIX SOCK_SEQPACKET only. The frame harness (E10-R4) is test-only Go with 33 rows. Whether its kill calls target only processes it created is not verified in this revision (0.3). Its raw stdout is kept in scratch; the bundle copy is normalized.
- R5: E10-R5 exercises receiveOne only (admission framing). The drain, overflow, observation error, V not 1 and the recvmsg EINTR budget at a drain are not measured by E10; seam and fuzz tests only. Poll EINTR was absorbed 17 times in 4000 iterations; recv EINTR was 0. The fresh build is sha 917f42b8 (binary 334717de, build-path dependent). The root build e6685f56 has no recorded source. Single host, kernel 7.2.11. The fuzz exclusion count is not recorded.
- R6: the R6 harness fixes two drain bugs (A51) and adds the final correction (A52), including round 2: CLOSE is terminal in runCase, and the per-receive and per-drain budgets are tested separately (A52 (9) and (10)). Their evidence is unit tests, seam tests, D's stop suite on the frozen source, a red run on R5 sources (an R5-signature repro_test.go; call signatures only), mutations, and final call-ceiling and commit-rule reds on the pre-correction snapshot. E10-R6 measures receiveOne again: 47 of 47 labels match E10-R5, and it does not exercise the drain fixes. The runCase harness cannot show Known restoration after an observation error (each step is a new process). In the drain, CALL_BOUND is not reached while the caps hold; receiveOne reaches the ceiling through repeated EAGAIN. Its mapping is ErrObservation (R6-5, 18.2 item 29). The T2 readiness poll is not in the harness (18.2 item 28). The R6 scratch evidence is amd64 only: arm64 was test-compiled and vetted but not run; the 32-bit integer path is not built (18.2 item 30). The harness uses stdlib syscall.SYS_PPOLL and has no golang.org/x/sys dependency; production may use golang.org/x/sys/unix.Ppoll (the repo go.mod requires golang.org/x/sys v0.49.0; slice 1 decides). Scratch only: no production code was changed.

---

## 20. Review request and completion checklist

Review request: reviewers B and C, please make the changed-lines re-review of R6 final-2 (17.1 gate (a)). This revision approves no implementation and no merge, tag, release or deployment. D9 stays OPEN. Maintainer decisions remain in section 16.

Specification-readiness checks (bundle level; scratch harness; not production):

- [ ] CS1. gofmt, go vet, unit suite (41 Test functions and 2 Fuzz functions, which are 43 top-level entries; 52 subtest entries; 95 PASS lines; 0 FAIL; TestMain is not a test), stop suite (TestStopRunCase: 1 top-level entry and 8 subtests; 9 PASS lines; 0 FAIL), arm64 compile and vet, build: PASS on linux/amd64 and for arm64 compile and vet only. Arm64 execution: NOT RUN. Record: out/frame-r6-final2/RUN-INFO.txt.
- [ ] CS2. `TestR6FinalUnknownIsFrozen`: green on the candidate, red on the R6 baseline, mutants red. Green: RUN HERE (integration-tagged suite, 5 subtests PASS, 2026-11-05). Red run and mutants: RECORDED, not re-run here. The red run used a scratch shim that is not published. The mutant logs are not published; whether they ran on the candidate source is not verified in this round.
- [ ] CS3. 47-row matrix (FRAME61_CASES unset): 47 of 47 pass, 0 label differences against the frozen R6 summary (out/frame-r6-final2/label-comparison-r6.txt). The matrix does not call commitExit and is not evidence for CS2.
- [ ] CS4. Owner notice (0.3) does not match the carried text byte for byte: the process identifier is removed, and the heading, item 3 and the status paragraph changed (0.3 change record). The original is in restricted storage outside the bundle. Count-only scan (88ac): no shipped bundle file contains the identifier. The unredacted working copy is kept outside this repository and was not changed in 88ac.
- [ ] CS5. Branch scan of the tracked tree, as recorded in out/branch-scan.txt (counts only). Checks: (a) incident label shape: count zero. (b) a process-identifier value after a process-identifier label: count zero, with every raw hit reviewed by hand. (c) home, scratch, user, account, host and working-copy folder names: count zero. (d) em and en dashes: count zero. (e) IPv4 addresses: count zero. Session identifiers are not checked: no pattern is defined. The scan of the R6 candidate bundle (out/frame-r6-final2/scan.txt) is historical and does not cover this tree.
- [ ] CS6. Tier A and E10 status rows cite E10-R6 (47 rows); the 33-row E10-R4 run appears only as history.
- [ ] CS7. No advisor call is cited as evidence.
- [ ] CS8. E10 label acceptance: MET for draft-start readiness only (R6-1). Production T-ADM-FRAMING: NOT RUN (slice 1).
- [ ] CS9. D9 (owner notice): OPEN.

Production test requirements (merge gates; none run; the scratch harness is not evidence for them):

- [ ] CP1. Slice 5, 5 runs: T-T2-POLL (TestStopT2ReadinessPoll).
- [ ] CP2. Slice 5: T-CL7-RELEASE. Release only after CleanupComplete; a later Close returns the retained sticky error; pidfd slots are invalid after release, so a later Close sends no signal.
- [ ] CP3. Slice 5: T-CL6-JOIN. One joint watcher-join deadline of 1 s; a watcher not joined by then is Lost.
- [ ] CP4. Slice 5: full production cleanup tests T-CL0, T-ZAP-ORDER, T-CLOSE-BOUND, T-CLOSE-LIVE and T08 (merge gates).
- [ ] CP5. Slice 6: T-FINAL-COMMIT, the production form of CS2.
- [ ] CP6. Slices 3 to 5: arm64 execution of the production tests.
- [ ] CP7. Slice 1: production T-ADM-FRAMING and T32.

Remaining independent-review scope (not complete):

- (i) The changed-lines re-review of R6 final-2 by B and C (17.1 gate (a)).
- (ii) The six Tier A gates of 12.2, which have scratch PASS evidence from earlier rounds and were not re-run in R6 final-2 except the 47-row matrix.
- (iii) The full Close ladder in 6.4, including the pidfd(L)-missing branch and the required-exit set.
- (iv) The full STOP list (section 15).
- (v) The maintainer decisions in section 16 (R6-1 scope, decision 13, R6-5, D2, D9, D12).
