# A54 revision 2: review record

This record accompanies `A54-revision-2.md` in this directory (SHA-256 `034d8274c5aa2ff36be7bde0842c13b01d6b1568b134e03dd9e4762779c7738f`). It is not part of A54. A54 stays byte for byte as reviewed, so the corrections below are recorded here.

It changes documentation only. It is a review record, not a merge approval, and the PR stays a draft.

## Identities

- PR #464 head: `6c3d4ee2e58d36608b133d32fe5bd4c1652a52fb`.
- Base: `main` at `153e723644a5db0099e7339a3bc5e652073030f7`.
- Frozen contract: `research/pidns-supervisor/contract-v6.1.md` at research commit `9d8c55efc62bfbdb479f10acc16255ae0ae9f0ca`, SHA-256 `8172756b2f4a581017365ae50fee52f3ec87a6f1c3d4a629d7a5c06d4952e91a`. Not edited.
- Reviews: Reviewer C accepted the production code at `6c3d4ee2` (review 5793989464). Reviewer B accepted A54 revision 2 and the production commits (review 5794378324).

## 1. Escaped value key (R3(a)): closed

Reviewer B closed R3(a) in review 5794378324. `chanMembers` in `contrib/frr-correlation/supervisor/channel_parse.go` reads member names with `json.Decoder.Token`, which returns the unescaped name. The type count, the duplicate check, the allowed-set check and the lookup all use that decoded name. An escaped value key therefore takes the same path as the escaped type key, which already has a row. No new row is needed.

A54 section 7 still says OPEN and proposes `{"v":1,"type":"status","kind":"exit","value":0}`. That input has no escape and is already the "status exit" row at `channel_parse_test.go:144`, so the proposal is struck and not added. For R3(a) only, this record replaces section 7.

## 2. T32 source reference: corrected

A54 section 1 cites `channel_linux_test.go`, line 434, for the T32 cell `bufV61_4_fds`. At `6c3d4ee2` the relevant lines in `contrib/frr-correlation/supervisor/channel_linux_test.go` are:

| Line | Content |
|---|---|
| 432-433 | Doc comment of `TestChannelRejectsWrongDescriptorCount` |
| 434 | `func TestChannelRejectsWrongDescriptorCount(t *testing.T) {` |
| 442 | `bufV61` row. The expected label for 4 descriptors is `CLOSE:count`. |
| 447 | `name: fmt.Sprintf("%s_%d_fds", sz.name, n)`, which produces `bufV61_4_fds` |

The subtest name is built at line 447, so that is the source line for the T32 cell. Line 434 is the function declaration. Reviewer B's review also gives 447 and describes 434 as the doc comment.

## 3. Nine unused-declaration obligations (A54 C8)

These are preserved as written in A54 C8. At `6c3d4ee2`, each `//nolint:unused` directive in `contrib/frr-correlation/supervisor/channel_linux.go` sits on the line above the declaration it suppresses:

| Directive line | Declaration line | Declaration |
|---|---|---|
| 48 | 49 | `realChanSys` |
| 53 | 54 | `chanRecvmsg` |
| 62 | 63 | `chanPoll` |
| 94 | 95 | `chanRecvd.facts` |
| 236 | 237 | `chanDrainOut` |
| 250 | 251 | `chanEnd.drain` |
| 289 | 290 | `chanPoison` |
| 298 | 299 | `chanCloexecAll` |
| 309 | 310 | `chanCloseFds` |

Rules, from A54 C8:

1. A production caller is a reference from a non-test file of the package that builds on linux. A reference from a `_test.go` file does not count, with or without the integration tag. A reference from another declaration that is still suppressed does not count.
2. When a declaration gains a production caller, its directive and reason comment are removed in the same change.
3. By the end of slice 6, a declaration with no production caller is deleted, together with its directive. The check is made at the slice 6 merge.
4. The slice 6 check is that none of the nine directives remains above these declarations.

Notes:

- The reason text on each directive expects the slice 3 launcher to be the first production caller. Rule 2 applies when that caller lands. Rule 3 is the backstop at slice 6.
- Reviewer B's optional wording, adding "or is absent" to rule 4 so that it enforces rule 3 directly, is not applied. A54 is unchanged. The maintainer decides whether to adopt it.

## 4. Escaped names: production tests and research evidence are separate

Production, gating at `6c3d4ee2`:

- `TestChanEscapedRecordGrammar`, `contrib/frr-correlation/supervisor/channel_parse_test.go:192`. Seven rows. Each raw input contains a literal JSON `\u` escape, and each row fails if its escape is missing (A54 C9).
- `FuzzParseWireAgreement`, `channel_parse_test.go:300`. Its 20 seed payloads contain no backslash, so the seeds give no escape coverage. The seed run remains a slice 1 requirement (contract 17.2).

Research, historical and frozen:

- `TestParseWireEscapedNames`, `research/pidns-supervisor/src/frame61/fuzz_test.go:395` at `9d8c55ef`. It is a scratch harness test (R5-8). It has no definition in the production tree at `6c3d4ee2`, so it is not production evidence (A54 C10).

Reviewer runs, which are not tracked tests:

- Reviewer B's uncommitted scratch test of the decode path, which is the basis for item 1.
- Reviewer C's 10 second fuzz run of `FuzzParseWireAgreement` (2.87M executions, no failure).
