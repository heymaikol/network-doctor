# Sonar review at 7df7be1

Reviewed PR #407 head: `7df7be121846490ebc5cf389eee2e4f1e15cca56`.
This is a new review record. Earlier reviews and evidence remain unchanged.
No project security rule, scanner, quality gate, remote issue status, or
unrelated finding was changed.

The exact-head SonarCloud check `121446410641` and analysis check
`121446405780` both report 37 annotations: one high and 36 low.
`annotations.json` retains the exact GitHub finding identities and locations;
`triage.json` records each rule, validity, actual impact and action. The broader
Sonar issue API returns 40 entries, including three historic entries absent
from the exact-head annotations. Those entries are explicitly distinguished,
not counted as new alerts or silently treated as remotely resolved.

## High finding, inspected rather than assumed safe

`AaF3ExOYI5fXcO_YEVtK`, `pythonsecurity:S8707`, is at
`contrib/frr-correlation/v1/bundle.py:51`. Its security impact is HIGH even though
the legacy severity field says MAJOR. `high-detail.json` preserves the flow and
`high-rule.json` preserves the rule metadata.

The reported flow is `argparse.parse_args()` at line 301, through `args.build`
at line 303 and `read_source` at line 49, to `os.open` at line 51. The flow labels
`parse_args` as an HTTP-request source. The actual reviewed source is a local
CLI with explicit operator-supplied paths. Repository callers are the documented
lab commands and tests; there is no in-repository HTTP or agentic wrapper that
passes an untrusted path to a more-privileged reader. Exact reviewed-source
SHA256 values are recorded in the triage.

The reader really can open any regular file permitted to its process. An agent
or server forwarding untrusted path choices under broader authority could
therefore expose files. No-follow, nonblocking access and bounded reads mitigate
symlink, FIFO and resource hazards, but do not provide a path allowlist. They
are not presented as a universal path-traversal fix.

For the verified local CLI use, the operator already authorizes the explicit
input path, no privilege is added, captured fields never choose that path, and
claims require an exact pinned manifest. This is a documented safe-use rationale
requiring independent approval. The high finding remains OPEN. Reuse in an
agent/server context requires a separately authorized input-root or capability
policy before that use is supported. No such integration is added here.

## Other findings

The 35 `python:S1313` annotations are fixed expected addresses in the offline
preserved-evidence verifier. The assertions neither connect to those addresses
nor configure networking. Their exact bytes remain unchanged.

The `docker:S6471` annotation identifies container UID 0. That is required to
install pinned build packages inside the supported rootless container. Builds
use network isolation, a read-only producer mount and scratch-only write mounts.
Rootful/privileged service deployment or broad writable host mounts are not
approved by this rationale.

Three older path entries, `AaF2ULZxcJVNBoyMYmyh`, `AaF2ULZxcJVNBoyMYmyi`, and
`AaF2ULZxcJVNBoyMYmyj`, are absent from the current 37 annotations but still OPEN
in the broader API. The original overwrite/symlink-following output operation
was a real evidence-loss defect. Commit `39bff54` changed output to exclusive
creation and added preservation tests, plus bounded no-follow regular-file input
handling. The current high input-path finding is evaluated separately above.

## CI snapshot and gate

`check-runs.json` is the exact reviewed-head snapshot: ordinary CI and CodeQL
passed; deployment was skipped; both Sonar checks failed. No green security
gate is claimed. Safe-use classification is a review decision, not suppression.

Stop for independent ChatGPT review of this threat model and the no-replace
producer implementation before any importer or forwarding-rating work.
