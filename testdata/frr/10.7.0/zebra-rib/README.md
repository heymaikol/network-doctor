# FRR 10.7.0 zebra RIB capture, steady run

The operator recorded this steady run on 2026-10-12 UTC, on two isolated FRR
10.7.0 routers, r1 and r2. For each router it took the ospfd captures of the
bracket that `../lsdb/` also uses (A, B, E, and D), and one zebra RIB capture
(R) between E and D. The operator recorded zebra's vty on TCP port 2601. The run
has no ospfd version record.

## Status

The operator's 21 original capture files are preserved under `steady/` with a
`SHA256SUMS` manifest computed from those same source bytes. The tests require
every file and reject missing files, altered contents, and invalid framing.
The captures have not been decoded or compared with the kernel FIB.

## Files

`steady/` holds these 21 files and `SHA256SUMS`, and nothing else:

| Role | Command | Daemon | Files for r1 and for r2 |
| --- | --- | --- | --- |
| A | `show ip ospf json` | ospfd | `rN-A-show_ip_ospf_json.raw`, `.collected_at` |
| B | `show ip ospf database detail json` | ospfd | `rN-B-show_ip_ospf_database_detail_json.raw`, `.collected_at` |
| E | `show ip ospf route json` | ospfd | `rN-E-show_ip_ospf_route_json.raw`, `.collected_at` |
| R | `show ip route json` | zebra | `rN-R-show_ip_route_json.raw`, `.collected_at` |
| D | `show ip ospf json` | ospfd | `rN-D-show_ip_ospf_json.raw`, `.collected_at` |

That makes 10 `.raw` files and 10 `.collected_at` files. `zebra-version.txt` is
the zebra version record for this run. `SHA256SUMS` is the manifest, and it is
not one of the 21 captures.

The file names match the layout that `lab/lsdb.sh` writes when `ZEBRA_VTY_PORT`
is set. The operator record does not say which script produced this run, and
this README does not assume one.

## Framing

Each `.raw` is the vty transcript: the echoed command and CRLF, the output, CRLF,
and the node's prompt, `r1> ` or `r2> `, with its trailing space and nothing
after it. The output may hold CRLF inside it, but it does not start or end with
a blank line. `.gitattributes` marks `testdata/frr/10.7.0/**/*.raw` as `-text`,
so git keeps these bytes. The tests here check the framing as written and do not
convert CRLF to LF.

The R output is one JSON object. Its top-level keys are prefixes that
`netip.ParsePrefix` accepts, and no top-level key repeats. r1 has 6 keys and r2
has 7. Values are not read.

## Stamps and order

Each `.collected_at` holds one RFC 3339 UTC time with nine fraction digits, a
`Z`, and an LF. On each node the stamps run A, B, E, R, D in that order, and
r1's D is before r2's A. The two R stamps are exact:

- r1: `2026-10-12T14:16:20.821906515Z`
- r2: `2026-10-12T14:16:36.536488001Z`

## Pinned R bytes

The tests pin each R `.raw` by its byte length and by the SHA-256 of the whole
file. The pin does not come from `SHA256SUMS`.

| Node | Bytes | SHA-256 |
| --- | --- | --- |
| r1 | 3313 | `f1dfe82b6c10b36853edf3ac24c93c2e27e33c80a0ae2c8a06945e3deffe4bcf` |
| r2 | 3857 | `9e4dc0621bce7464a89b597095eafbf19a70a1b00ef49033dcf5c5526e41c525` |

## SHA256SUMS

The manifest uses the GNU `sha256sum --binary` format. It has one line for each
of the 21 capture files, each line is `<64 lowercase hex> *<name>` followed by
an LF, and the lines are sorted by name in byte order. It does not list itself.
To check the copy by hand, run `sha256sum -c --strict SHA256SUMS` inside
`steady/`. The Go test checks the same digests.

## What the capture does not show

- A and D are the same process-state command, taken before and after the
  bracket. Their agreement does not show that zebra's RIB held still during the
  run.
- R is one snapshot of zebra's RIB, taken between E and D. Nothing compares it
  with another capture.
- R is zebra's RIB as zebra printed it, not the kernel forwarding table
  (FIB). The JSON contains route-selection and installation fields, but these
  tests do not interpret them or independently verify kernel FIB entries.
- The operator record covers this run only. Its ports, versions, and times come
  from that record, and the repo does not reproduce them.
