# Network Doctor reference

This file is the authoritative reference for `netdoc`'s probes, flags, and
output contracts, the detail that changes in the same commit as the code
beside it. [README.md](../README.md) is the landing page; the wiki's
[How Network Doctor Works](https://github.com/heymaikol/network-doctor/wiki/How-Network-Doctor-Works)
and [Understanding Your Diagnosis](https://github.com/heymaikol/network-doctor/wiki/Understanding-Your-Diagnosis)
explain why these probes are built this way and what a result means for you.

## How it diagnoses

Probes form a **dependency graph with independent branches**, so an unrelated failure never hides a working one:

- **Direct-egress path** (independent of DNS): `Interface → Internet (TCP
  egress)`. Always runs, so "DNS down but internet up" stays diagnosable.
- **QUIC path**: `Interface → QUIC / UDP 443`. It resolves the fixed
  connectivity endpoint itself and completes a real QUIC handshake, so a
  successful local UDP send cannot masquerade as reachability.
- **Proxy-egress path** (independent of both): `Interface → Internet (env
  proxy)`. Native probes deliberately bypass proxies, so this row reports the environment-configured proxy separately: a proxy-only corporate network reads "online via proxy" rather than offline.
- **Public-DNS path** (independent of system DNS): `Interface → DNS (public)`. Failing to reach the third-party resolver is N/A; differing answers warn about split DNS or filtering but never fail the run on their own. `--public-dns` picks a different resolver, and `--public-dns ""` removes the row.
- **Encrypted-DNS path** (independent of both plaintext DNS rows): `Interface →
  DNS (encrypted DoH/DoT)`. Plain DNS and encrypted DNS are separate network capabilities, so this row hangs off the interface rather than under the DNS row: a network can carry ordinary DNS while blocking DoH and DoT.
- **Wi-Fi metadata path**: `Interface → Wi-Fi network`. SSID discovery runs beside network checks, so slow OS lookup never delays them.
- **Plain HTTP path**: `Interface → DNS → HTTP :80`.
- **Selected target path**: `Interface → DNS → TCP → TLS → HTTPS` for secure web targets, or applicable protocol row for other ports.
- **Path-MTU branch** (hangs off connect, not off any protocol): `TCP → Path
  MTU`. Black hole breaks SSH and SMTP exactly as thoroughly as TLS.

Each row lands in one of five states: **✓ Pass**, **! Warn** (reachable but degraded: high latency, some addresses failing, an ambiguous source interface), **✗ Fail**, **⊘ Skip** (a prerequisite failed), or **– N/A** (doesn't apply, e.g. DNS on an IP literal). Warn never counts as a failure.

| Probe | Passes when | Notes |
|-------|-------------|-------|
| **Interface** | A non-loopback interface is up and running | |
| **Internet (TCP egress)** | A TCP connect to a fixed pair of well-known anycast `:443` reference endpoints succeeds | IPv4 and IPv6 probed independently in parallel; either family passes, both are reported. This row samples those reference destinations rather than the internet: a failure is evidence about the paths to them, and the diagnosis only widens it where nothing else in the run reached a public destination directly |
| **QUIC / UDP 443** | A certificate-validated QUIC handshake negotiates HTTP/3 with the fixed connectivity endpoint | A timeout says only that this endpoint did not complete the UDP/443 exchange; browsers and applications normally fall back to TCP |
| **Internet (env proxy)** | The `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` proxy grants a tunnel | HTTP `CONNECT`; `socks5` resolves locally and sends an address, while `socks5h` sends the hostname for proxy-side DNS; N/A when no proxy is configured or `NO_PROXY` exempts the probe host |
| **DNS** | The host resolves to an IPv4 or IPv6 address (system resolution) | IP-literal targets are N/A; all A/AAAA records are retained |
| **DNS (public)** | A direct query to Google Public DNS provides a second opinion | Queries `8.8.8.8`, and `2001:4860:4860::8888` when the first cannot be reached, so an IPv6-only host still gets a second opinion; the row names the resolver that answered. N/A when outbound DNS is unavailable, and when this machine answers the name without DNS at all, since a hosts-file entry is a local override rather than a second opinion; disagreement is Warn, not Fail, and the warning names the comparison prefix (the /16 for IPv4, /32 for IPv6, the same masking `answersAgree` uses, and no claim about allocation or ownership) each side's answers masked to, so a reader can see which prefixes the comparison actually found disjoint; `--public-dns` pins one resolver or removes the row |
| **DNS (encrypted DoH/DoT)** | A correlated DNS response arrives over DoH **or** over DoT | `NOERROR` or `NXDOMAIN` passes; a standard-query resolver error warns without claiming the transport is blocked; it never falls back to port 53 |
| **TCP** | A TCP connect to the target port succeeds | races A/AAAA records Happy-Eyeballs style (RFC 8305), pins the winner |
| **Path MTU** | the peer acknowledges some of a 24 KiB write | finds evidence consistent with an MTU/PMTU black hole, never a Fail, see below |
| **TLS** | The TLS handshake (SNI + cert verification) succeeds | certificate time, hostname, issuer, protocol, timeout, early-close, and TCP failures receive stable JSON causes |
| **HTTP** | Port 80 returns any HTTP response (incl. 3xx/4xx/5xx) | Independent HEAD after DNS, redirects off, proxy off |
| **HTTPS** | The selected TLS port returns any HTTP response | HEAD against the TLS-validated IP, redirects off, proxy off |
| **SSH/SMTP banner** | TCP connects (banner read best-effort) | bounded read; connected but silent → Warn (not a failure) |

### Path MTU without root

A path MTU smaller than the local interface's, on a path that also filters the ICMP that would say so, breaks TCP the moment either side sends a real packet, the classic tunnel/VPN/PPPoE mystery that `ping` and `curl` can't diagnose, and confirming it normally means raw sockets and the DF flag.

The **Path MTU** row finds it from an ordinary socket instead. The TCP handshake is the control: SYN/SYN-ACK are small enough to cross a narrowed link, so a completed connect already proves small packets arrive. The probe then writes 24 KiB and asks the kernel how much of it the peer has acknowledged, the only proof of forward progress an ordinary socket can offer, and a strict one, since TCP fills segments from the front of the payload.

- some of the payload is acknowledged → full-size packets cross, **Pass**, with the connection's TCP MSS when the OS exposes it,
- the whole payload is written and none of it is acknowledged before the deadline → **Warn**, naming the evidence and an MSS/MTU experiment,
- the peer hangs up first → **N/A**: inconclusive, and it will not guess,
- the platform cannot read the send queue and the write was accepted → **N/A**: the local kernel took the bytes, which is not evidence they crossed.

A completed write is deliberately not the test: Linux treats the send-buffer size as an accounting hint rather than a ceiling, so an 8 KiB send buffer can swallow a 24 KiB write whole without a byte reaching the wire. Linux and macOS read the socket's outstanding send queue directly instead. Windows exposes no equivalent query, so it cannot tell a delivered payload from a buffered one and never reports Pass: an accepted write is N/A, naming what it could not verify. A write that stalls against the small send buffer is still a Warn there, and the TLS/HTTP timeouts beside it still show up.

It deliberately never Fails: a peer that accepts the connection and then stops accepting data stalls the write the same way, and a normal socket cannot discover the exact path MTU when ICMP feedback is filtered. The row reports bytes written and acknowledged, the TCP MSS when available, and the local interface MTU as context, never as a measured path MTU. Only when both this write and a protocol exchange time out does the overall verdict identify a probable network-path problem; certificate and other immediate protocol failures remain service failures.

The 24 KiB payload is inert, self-labelling filler; TLS targets get a record header in front so the TLS server reads it instead of resetting on the first byte. This is the only probe that sends bulk data: under `--watch` that is 24 KiB once every 5 seconds.

Three other fixed third-party endpoints are involved, all bounded by the normal per-probe timeout and ignoring configured proxies. The **Internet (TCP egress)** row's captive-portal check sends one small plain-HTTP `GET` with no body to each of two independently operated connectivity endpoints on every pass. They run concurrently with each other and with the row's TCP dials, share that one probe deadline, and are never retried. `connectivitycheck.gstatic.com/generate_204` answers `204` with no content on a clean path; `www.msftconnecttest.com/connecttest.txt` answers `200` carrying the payload `Microsoft Connect Test`, and only that many bytes are read, so an arbitrary `200` is not accepted as a clean answer. Neither follows redirects: an interception normally announces itself as the `302` that would otherwise be chased to a sign-in page. **One endpoint answering something other than what it documents is not enough for the captive-portal diagnosis.** A block aimed at that one name, that provider's own outage, a hijacked DNS answer for it, and a portal all look identical from a single observation, so a lone discrepancy degrades the row to a Warn that names what was seen and stops there. Both endpoints intercepted on the same pass is corroborated HTTP interception: that is what fails the row, carries the `portal` object, and supports the `captive_portal` finding. An endpoint that could not be reached at all is the absence of an observation rather than evidence of trouble: it never corroborates the other endpoint, and it never turns otherwise-working direct egress into a failure. **QUIC / UDP 443** reuses the `connectivitycheck.gstatic.com` host for a certificate-validated QUIC/HTTP-3 handshake on UDP/443 with no application data, so a timeout there says only that this endpoint didn't complete the exchange, not that a firewall was responsible. **DNS (encrypted DoH/DoT)** dials `cloudflare-dns.com` directly at `1.1.1.1`/`2606:4700:4700::1111`, sending one A query for `connectivitycheck.gstatic.com` per pass over each transport: an RFC 8484 `POST` with DNS ID 0 to `/dns-query`, and an RFC 7858 length-framed query with a random DNS ID on port 853. It proves a **correlated DNS exchange**, not a particular answer: it checks the DNS header and echoed question (except where a valid `FORMERR`/`NOTIMP` response may omit it) but does not parse answer records or test the user's configured resolver. `NOERROR`/`NXDOMAIN` pass even with no answer records; a standard-query error such as `SERVFAIL` warns rather than fails, since the resolver was reached but didn't complete the query. Either transport succeeding is enough, both are tried concurrently, and it never falls back to plain DNS. These endpoints, the fixed anycast addresses the direct-egress row dials, the automatic second-opinion resolver, and the compiled-in host the proxy row tunnels to are exactly what [`--no-reference-egress`](#usage-details) removes.

No verdict depends on ICMP: a failed `ping` proves nothing and a successful one proves less than a TCP connect, so RTT is measured from the TCP-connect handshake instead, with no ICMP and no root. `ping` remains available as a drill-down tool. The source IP and interface are read from the winning connection's `LocalAddr`, with a UDP-connect fallback (which sends no packets) for path identity on failure. Every probe is bounded by a 4-second timeout.

## Usage details

`--timeout` overrides the per-check probe timeout; see `netdoc --help` for the default. `--watch` starts another pass five seconds after each run; in the TUI it shows the last 20 states plus a failure count for every check, and with `--json` it streams the same report on stdout, one compact JSON object per line, until the process is interrupted. Those lines carry an extra `ts` field (RFC 3339, UTC) and are otherwise the one-shot report unchanged; one-shot output stays pretty-printed, with no `ts`.

The TUI also reconstructs bounded incidents. A transition from a working pass
to a failing pass opens one incident. Further failing passes increase its pass
count and retain only semantic state changes, rather than opening another
incident each time. The first later working or degraded pass closes it as a
recovery. The existing per-check strip retains the last 20 outcomes. Incident
reconstruction separately retains at most 10 incidents and at most eight state
changes inside one incident. Press `i` to inspect the
latest incident, left/right to select another retained incident, and `w` there
to save the selected incident as `.ndoc`. A target restart clears the incident
timeline because the new endpoint is a new Watch session.

The onset and recovery views use the same canonical snapshot conversion and
semantic comparison as `--save` and `--compare`. A path change observed in the
same pass as a failure is reported as a temporal coincidence. It is not called
the cause unless the saved diagnosis carries independent causal evidence for
that conclusion. Cancelling Watch during a failure leaves the incident active;
it never invents a recovery that was not observed.

`--check` accepts comma-separated stable probe IDs and limits the run to those probes plus the prerequisite closure from the existing DAG. `--skip` removes IDs and any dependent probes whose prerequisites are then unavailable. Both flags are repeatable and combine by union; their argument order never changes row order. Unknown or empty IDs are rejected with exit `2`, before diagnostics start, and the error lists every valid stable ID. A known ID that does not apply to the current target is harmless: `--check` may select no rows, while `--skip` changes nothing. Omitted probes do not run and do not appear in the TUI or JSON. The same selection policy is retained by `--watch`, TUI restarts, and target changes.

`--list-checks` prints every stable probe ID accepted by `--check` and `--skip`, followed by its human-readable base name, and exits `0` without running probes. The order is the same deterministic inventory order used to validate selections. The command cannot be combined with a target or another operational flag; such a combination exits `2` instead of silently ignoring the extra argument. As elsewhere, `--help` and `--version` retain their normal immediate behavior.

`--no-reference-egress` makes no connections to netdoc's own built-in reference services. Everything netdoc contacts on its own account leaves the probe DAG for that run: the fixed anycast `:443` endpoints behind the direct-egress row, both captive-portal observation points, the automatic second-opinion resolver, the fixed QUIC/HTTP-3 endpoint, the encrypted-DNS provider, the compiled-in host the proxy row asks a proxy to tunnel to, and the compiled-in hostname a run with no target would otherwise resolve just to have a DNS question to ask. Checks that depended on a removed row go with it, through the same closure `--skip` walks; the removed rows are absent from the TUI and from the JSON report rather than reported as skipped.

What still happens is everything with a destination someone other than netdoc chose. The target you named is resolved and connected to. An explicitly selected `--profile` still contacts the endpoints that define it, because choosing the profile is what named them; it just stops dragging the generic reference rows along behind each component. This machine's own configuration is still used: the system resolver answers the target's name, and the routing table still chooses the path. The proxy row is not the exception it looks like. An `HTTP(S)_PROXY` is this machine's configuration, but the only destination netdoc ever asks a proxy to tunnel to is its own compiled-in connectivity host, so that row goes with the mode; no other check has ever routed through a proxy, with or without this flag. A `--via` destination is still reached, and the remote run applies the same policy. **This is not an offline mode and not a LAN-only mode.** The distinction it draws is provenance, not whether an address belongs to a third party: a public host you asked about is your traffic, and a public host netdoc picked for you is not.

Two options can name a prohibited destination explicitly, and the two answers differ because the provenance does. `--public-dns 9.9.9.9` names the second-opinion resolver, which makes that row's destination the user's choice, so it survives the mode; without the flag the row is netdoc's own automatic pick and does not. `--check` naming one of the removed probes is a contradiction rather than an override: netdoc exits `2`, names both halves, and runs nothing. Flag order does not enter into it, and no later selector can put a removed row back. `--skip` composes normally, since it only ever removes more. Peer mode rejects the flag outright: it runs no probe DAG at all, only authenticated traffic between two endpoints you established yourself, so there is nothing there for the mode to remove. In a targetless run the mode leaves very little: with no endpoint to ask about and no reference service to substitute for one, what remains is the local interface and link state.

`--via` runs the checks on an SSH destination rather than on the local machine; see [Remote diagnosis over SSH](#remote-diagnosis-over-ssh). It is headless, so it needs no terminal, and an ordinary remote run cannot be combined with `--toolbox`, `--watch`, `--compare`, or peer mode. With `--two-sided`, it instead acquires one local and one remote ordinary run for the same target; that form's complete flag matrix is under [Two-sided diagnosis](#flags-in-live-two-sided-mode).

`--iface` binds IPv4 and IPv6 probe connections and DNS lookups to the interface's first usable address of the matching family. IPv4-only and IPv6-only interfaces use only their available family; pass an exact local IP to restrict probes to that address's family.

The path drill-downs follow the same selection where the native tool supports it. On Linux and macOS, `ping`, `traceroute`, `mtr`, and `curl` use the selected interface name, or the selected address when `--iface` names an exact IP. Windows tools bind by source address instead: `pathping` and `curl.exe` use the resolved address, while `ping` and `tracert` can do so only for IPv6 destinations. `curl.exe` cannot bind by interface name, but can use that interface's resolved source address.

Address-only binding follows the literal target's family first, then the address selected by the target TCP check. With neither, a single-family selection is unambiguous and may be used; a dual-stack selection is left unbound rather than guessing. A missing matching source family is always left unbound.

Left deliberately unchanged and unbound: `dig` and `nslookup`, which query the system resolver (often a loopback stub) rather than the target; the `nmap` connect scan, whose `-S` is a spoofing option rather than documented connect-scan binding; and the SSH and SMTP handshake checks. Local-state tools (`ip route`, `ss`, `netstat`, `route print`) open no sockets. The LAN scan already follows the selection through the probe source address from which it derives its subnet.

`--public-dns` sets the resolver behind the second-opinion DNS row. Left alone, the row is automatic: it queries Google Public DNS on IPv4 (`8.8.8.8`) and falls back to the same operator's IPv6 resolver (`2001:4860:4860::8888`) when the first cannot be reached at all, so a host with only IPv6 keeps the second opinion instead of losing the row to an address it cannot dial. A resolver that answered, refused, or said the name does not exist has answered the row, so only an unreachable one is retried, and the fallback attempt is bounded by a share of the same probe budget rather than an extra one. The row is labelled `DNS (public)` while the choice is open and names the resolver that answered once it has. Passing the flag pins one resolver instead: `--public-dns 8.8.8.8` queries `8.8.8.8` and nothing else, including when it is unreachable, because an address the user typed is a choice rather than a preference. It takes an IP literal, IPv4 or IPv6, and nothing else; a hostname or any other word is rejected with exit `2`, since resolving it would go through the very resolver the row exists to cross-check. An empty value (`--public-dns ""` or `--public-dns=`) removes the check: the row is absent from the TUI and from the JSON report, and no query is sent, which is what a strict egress policy or a privacy requirement needs. The value applies to `--watch` and `--json` runs and to target switches inside the TUI. Under `--via` the resolver address crosses the wire as typed, and whether it was typed at all crosses beside it, so the remote machine decides the automatic fallback for the address families it actually has rather than the caller's. Note that this flag governs only the DNS second opinion; the direct-egress row still connects to fixed anycast `:443` endpoints, the captive-portal check still reaches `connectivitycheck.gstatic.com` and `www.msftconnecttest.com`, and the encrypted-DNS row still reaches `cloudflare-dns.com`. `--no-reference-egress` is the flag that covers all of them at once; naming a resolver here keeps this one row alive under it, because then the resolver is your choice rather than netdoc's. A plaintext resolver IP is not a DoH/DoT provider, so `--public-dns` is never reinterpreted as one.

The target parser has two independent axes: **port** (explicit `:port` > scheme default > 443) and **protocol rows** (an explicit `http`/`https`/`ssh`/`smtp` scheme wins; otherwise it is inferred from the port: `443/8443`→HTTP+TLS+HTTPS, `80`→HTTP, `22`→SSH, `25/587`→SMTP). Hosts are validated against a strict allowlist; IPv6 literals are accepted bare (`::1`) or bracketed with a port (`[::1]:443`).

The TUI's default key bindings:

| Key | Action |
|-----|--------|
| `space` | the Actions menu: everything the run can do right now, each with its own key; `↑`/`↓` select, `enter` runs, `esc` closes |
| `↑`/`↓` (`k`/`j`) | select a probe row, or a device or service in the network map |
| `a` | expand the checks a finished run collapsed, and collapse them again |
| `e` | show why the selected diagnosis follows from the observed checks, and return to normal details |
| `i` | in Watch Mode, inspect recorded incidents; use left/right to choose one, and `w` to save it as `.ndoc` |
| `v` | run a LAN scan and show a network map of the local private `/24` (unprivileged `nmap`) |
| `enter` | open the selected map device, then diagnose one of the services it answers on, or open the current tool job's output |
| `/` (viewer) | filter the viewer to matching lines (`enter` commits, `esc` clears it, a second `esc` leaves) |
| `home`/`end`, `pgup`/`pgdn` (viewer) | jump to top/bottom (`end` re-enables follow) or page through the output |
| `y` / `w` (viewer) | copy / save the viewer's retained output (up to 5,000 lines; respects its filter) |
| `r` | restart with a new target |
| `R` | retest: rerun the same checks on the same target, after acting on the remediation the Details panel shows |
| `S` | SSH login: a form for username, key, and password, then hands the terminal to `ssh` (hinted only once the SSH banner check passes, but usable against any target) |
| `tab` | switch between running tool jobs |
| `esc` | cancel the focused job only (`tab` picks which), or leave an opened device on the map; `q` is the stop-everything path |
| `y` / `w` | yank / write (copy / save locally) a reviewable report of the chain plus every tool job |
| `T` | pick a colour theme, previewed as you move; `enter` keeps it, `esc` restores the one you had |
| `?` | full-screen key cheatsheet; any key closes it |
| `q` | quit (cancels running jobs first, then exits) |

`--keys vim` adds `gg`/`G` for first/last, `ctrl+b`/`ctrl+f` for page up/down, and `ctrl+u`/`ctrl+d` for half-page up/down; the existing keys continue to work.

`space` opens the Actions menu: the actions and drill-down tools that apply to the current state, each labelled with the key that runs it under the active preset. Up/down or `j`/`k` move, `enter` runs the selected row, `esc` closes, and any shortcut pressed while it is open runs exactly as it does outside it, the confirmation gate on the active scans included. The rows are generated from the same table that drives dispatch, the help bar, and the cheatsheet, and from the same tool definitions as the hotkeys, so the menu can neither offer a key that does nothing nor miss one that works. It is discovery only: no probe, diagnosis, report, or exit code changes with it.

`T` opens the theme picker: up/down or `j`/`k` move through the built-in themes and apply the highlighted one at once, `enter` keeps it, and `esc` restores the theme that was active when the picker opened. It is presentation only, so no probe, diagnosis, status, report, snapshot, or exit code changes with it, and every status keeps the glyph and word it always had. The built-ins are `terminal` (the default, the 16 ANSI colours, which follow your terminal's own palette), `harbor`, `ember`, `contrast` (high contrast), and `monochrome` (colour-free, with bold and faint emphasis). There is no `--theme` flag: the picker is the way to choose one. `NO_COLOR=1 netdoc ...` disables colour for a run; an empty `NO_COLOR` value does not.

The chosen theme persists as a single name in `$XDG_CONFIG_HOME/netdoc/theme` (normally `~/.config/netdoc/theme`) on Linux, `~/Library/Application Support/netdoc/theme` on macOS, or `%AppData%\netdoc\theme` on Windows. It is convenience state: a missing file, an unreadable one, and an unknown or obsolete name all mean the default theme, and a preference that cannot be written never stops a run. `--no-history` does not affect it, since that flag is about the targets you type. Exit `netdoc` and delete the file to go back to the default.

The TUI saves up to 50 recent targets between sessions in `$XDG_CONFIG_HOME/netdoc/history` (normally `~/.config/netdoc/history`) on Linux, `~/Library/Application Support/netdoc/history` on macOS, or `%AppData%\netdoc\history` on Windows. `--no-history` turns that off for one run: the file is neither read nor written, so the targets you type stay in that session only. It leaves an existing file untouched, so exit `netdoc` and delete it to clear what is already saved.

### Exit codes

| Situation | Exit |
|---|---|
| Chain completed, no failed row (Skips allowed) | `0` |
| Peer tests completed with authenticated traffic passing both ways | `0` |
| Any failed row | `1` |
| Peer diagnostic failed, stayed incomplete, or the session errored | `1` |
| `--two-sided`, saved or live: no comparable check failed on either machine | `0` |
| `--two-sided`, saved or live: a failure was placed, or the evidence could not place one | `1` |
| `--two-sided`, saved or live: the two snapshots observed different targets | `2` |
| Live `--two-sided --via`: SSH or remote protocol acquisition failed | `2` |
| Quit before the chain finished | `1` |
| Bad arguments, pairing-input reject, validation reject, or no terminal for the TUI | `2` |
| `--via`: SSH failed, no usable `netdoc` on the SSH host, or a remote protocol mismatch | `2` |

The per-situation table for `--via` is [below, in the remote section](#exit-codes-1).

## Service profiles

`--profile` turns a service troubleshooting question into a finite plan of
ordinary Network Doctor runs:

```sh
netdoc --profile github
netdoc --profile ssh server.example.com
netdoc --profile smtp mail.example.com
netdoc --profile web status.example.com
netdoc --profile list
```

Profiles are typed orchestration, not protocol implementations. Every
component goes through `ParseTarget`, `BuildProbesFromSources`,
`ProbeSelection`, the normal dependency closure and timeout runner,
`Interpret`, the causal-evidence and counterfactual passes, remediation, JSON
report conversion, and snapshot conversion. Profile code opens no socket and
duplicates no DNS, TCP, TLS, HTTP, SSH, SMTP, routing, VPN, or path-MTU logic.

### Built-in plans

The initial registry has four lowercase, version-1 profiles. Its order is
stable and is also the component output order.

| Profile | Target | Components |
|---|---|---|
| `github` | Forbidden; the endpoints are canonical | `web`: HTTPS at `github.com:443`; `api`: HTTPS at `api.github.com:443`; `ssh`: SSH banner at `github.com:22`; `ssh-alt`: SSH banner at `ssh.github.com:443` |
| `ssh` | Required | One requested SSH endpoint, using port 22 when omitted, with its DNS, route, TCP, path-MTU, and banner evidence |
| `smtp` | Required | SMTP banner at the requested port, or relay port 25 when omitted; an independent SMTP banner on submission port 587. When 587 is primary, port 25 is the comparison path |
| `web` | Required | Certificate-validated HTTPS at the requested port, or 443 when omitted; an independent plain HTTP response on port 80 |

GitHub's web and API components issue the existing bounded, redirect-free
HTTP `HEAD` checks. The profile does not claim a Git repository operation or
an authenticated API request. The SMTP profile does not claim STARTTLS or
implicit-TLS SMTP support because those primitives do not exist in the
ordinary engine. These limits keep the profile answers tied to evidence the
current diagnostic layer can actually collect.

Each component's minimum selection contains its service probe plus the
existing direct-Internet, environment-proxy, public-DNS, and path-MTU context.
The dependency closure supplies interface, target DNS, TCP, and TLS where
needed. This context lets the component's existing findings distinguish a
local egress problem, proxy-only network, resolver problem, route or VPN path,
target port failure, path-MTU evidence, TLS failure, and application-layer
failure without profile-specific networking code.

### Aggregate result

The component status comes from the service check and its ordinary report. A
component is `PASS` when its service check and report are healthy, `WARN` when
the path works with degraded evidence, `FAIL` when the component run fails,
and `SKIP` when selection removed the service check or a prerequisite made it
unavailable.

The aggregate is `PASS` only when every component passes. It is `WARN` when at
least one component still works and another is unavailable, skipped, or
degraded. It is `FAIL` when no component completes its service check. A working
declared fallback, currently GitHub's SSH-over-443 path, produces the stable
`<profile>_fallback_available` finding; an unavailable fallback beside a
working primary produces
`<profile>_fallback_unavailable`; other partial and total failures use
`<profile>_partial_reachability` and `<profile>_unreachable`. Findings carry
stable affected and working component IDs. The detailed cause remains the
ordinary report finding and causal evidence inside each component.

Human output lists every component and endpoint, then the aggregate verdict.
For affected components it shows the existing finding ID and the check rows
that support it. It does not replace the evidence model with profile prose.

The JSON shape keeps profile state as data and embeds each unchanged ordinary
report:

```json
{
  "schema": "netdoc.profile-report.v1",
  "profile": "smtp",
  "profile_version": 1,
  "title": "SMTP",
  "description": "Tests SMTP relay and message-submission banner paths independently.",
  "components": [
    {
      "id": "smtp",
      "label": "SMTP service on port 25",
      "target": {"host": "mail.example.com", "port": 25, "protocol": "smtp"},
      "focus": "smtp_banner",
      "status": "FAIL",
      "report": {"version": "1.2.3", "target": {"host": "mail.example.com", "port": 25, "protocol": "smtp"}, "checks": [], "summary": "…", "verdict": "service", "ok": false}
    },
    {
      "id": "submission",
      "label": "Message submission on port 587",
      "target": {"host": "mail.example.com", "port": 587, "protocol": "smtp"},
      "focus": "smtp_banner",
      "status": "PASS",
      "report": {"version": "1.2.3", "target": {"host": "mail.example.com", "port": 587, "protocol": "smtp"}, "checks": [], "summary": "…", "verdict": "ok", "ok": true}
    }
  ],
  "aggregate": {
    "status": "WARN",
    "summary": "Some SMTP components are unavailable or degraded while others work.",
    "finding": {"id": "smtp_partial_reachability", "affected_components": ["smtp"], "working_components": ["submission"]}
  },
  "ok": true
}
```

Branch on `schema`, `profile`, `profile_version`, component `id` and `status`,
and aggregate finding `id`. Component `report` contains the stable ordinary
check, finding, causal-evidence, counterfactual, route, and remediation fields;
derived sentences remain display text.

### Flags and execution modes

- `--json` emits one `netdoc.profile-report.v1` object. Non-profile JSON stays
  the existing `report.Report` byte shape.
- `--save` writes a `netdoc.profile.v1` `.ndoc` containing the identity and
  aggregate plus one complete `netdoc.snapshot.v1` per component.
- `--support` applies `support-v1` locally with one pseudonym mapping shared by
  all embedded snapshots. Combined `--json` output remains full fidelity, the
  same as an ordinary support run.
- `--watch` is supported with `--json` and streams one compact profile object
  per pass with `ts`. A profile has no multi-pane TUI, so profile watch without
  `--json` is rejected. As with ordinary remote execution, `--watch` and
  `--via` cannot be combined.
- `--via` sends one ordinary remote protocol version 1 request per component.
  Targets and selections travel as JSON data, never shell text. The remote
  binary does not need to know the profile name, so a version-1 remote worker
  that predates profiles can still run the component plans. Reports and
  snapshots are interpreted on the remote OS and aggregated locally.
- `--iface`, `--public-dns`, and `--timeout` apply independently to every
  component. Interface names are resolved on the machine that probes, as in
  every ordinary local or remote run.
- A profile's check list is its minimum plan. Explicit `--check` IDs are added
  to every component, with duplicates removed. `--skip` takes precedence over
  the profile minimum and explicit checks, then the normal dependency-removal
  rules apply.
- Profiles are headless and never read or write TUI target history.
  `--no-history` is accepted and therefore redundant rather than becoming an
  incompatibility.
- `--toolbox` and `--keys` require the single-run TUI and are rejected with a
  profile. Peer mode is a different live two-machine protocol and is also
  rejected. `--compare` and offline `--two-sided` accept only single-run
  snapshots and reject the separate profile artifact schema. Live
  `--two-sided --via` rejects `--profile` because a profile is a multi-target
  plan rather than one target observed from two vantage points.

Target requirements are checked before any probe starts. `github` rejects a
positional target rather than silently replacing a canonical endpoint. The
other profiles reject a missing target. A scheme that conflicts with the
profile, such as `https://host` under `--profile ssh`, is rejected rather than
reinterpreted. Profile endpoints are finite, deterministic, documented, and
limited to the selected service, so a plan cannot become a port scan.

## Peer diagnosis

Peer mode is a separate, headless two-ended diagnosis. It does not run the
ordinary target DAG twice or concatenate two reports. One authenticated control
connection coordinates independent TCP, TLS, and application-payload attempts
in both directions, exchanges those observations as data, and runs one combined
truth table on each machine.

It answers one half of the two-machine question: the path **between** the two
machines. For the other half, a target that fails from one machine and works
from the other, see [two-sided diagnosis](#two-sided-diagnosis), which reads two
ordinary runs. Those runs can already be saved, or the live form can acquire
them locally and over SSH before applying the same reading.

### Pairing workflow

The listening machine binds one exact local unicast address. Port zero asks the
kernel to select a temporary port:

```sh
netdoc --peer-listen 192.168.1.20:0
```

To offer both families, repeat the flag once:

```sh
netdoc \
  --peer-listen 192.168.1.20:4242 \
  --peer-listen '[2001:db8:1234::20]:4242'
```

An IPv6 link-local address must carry the interface scope that makes it
reachable, so the bare address is rejected. Windows writes that scope as a
number, such as `%12`:

```sh
netdoc --peer-listen '[fe80::20%eth0]:4242'
```

The listener prints each direct endpoint and one `ndp1.` pairing string. On the
other machine, run:

```sh
netdoc --peer-connect
```

Paste the string at the `Temporary pairing string:` prompt. On a terminal the
prompt disables echo. The credential is read from standard input, never argv,
the target history, a file, or an environment variable. A script may pipe one
line to the prompt, but then owns the security of that pipe.

`--iface` may accompany `--peer-connect`; it supplies the connector's source
address and reverse listener address for each available family. The listening
form already names exact bind addresses, so combining `--iface` with
`--peer-listen` is rejected. Peer mode cannot be combined with a target,
`--watch`, `--toolbox`, `--check`, `--skip`, `--no-reference-egress`,
`--public-dns`, `--no-history`, `--keys`, or `--save`. It does not enter the TUI.

The listener waits at most five minutes for one authenticated control session.
After connection, the complete exchange is bounded to one minute. `--timeout`
sets each dial, TLS handshake, frame read, and write budget as it does for an
ordinary probe, but peer mode caps it at 30 seconds. The two control reads that
wait for peer evidence allow three times that budget because the peer must
finish its bounded connection, TLS, and application phases first; the one-minute
session limit remains the hard cap.
Ctrl+C and SIGTERM cancel pending accepts, dials, handshakes, reads, and writes
and close all listeners and connections.

### Authentication and encryption

Every listening run generates, with `crypto/rand`:

- a fresh Ed25519 self-signed server certificate,
- a fresh 256-bit session token,
- fresh request nonces and fixed-payload challenges.

The pairing string contains protocol version 1, its expiration, at most one
IPv4 and one IPv6 direct endpoint, the certificate's SHA-256 pin, and the token.
It uses only URL-safe printable characters and is easy to paste, but it is a
secret until the session ends. Do not post it in a ticket or chat archive.

TLS 1.3 encrypts every control and probe connection. The connector accepts only
the exact pinned certificate, and the listener compares the decoded token in
constant time before accepting a control or probe request. Each authenticated
request needs a fresh 128-bit nonce; repeats are rejected. One listener accepts
one control connection, no more than eight concurrent connections, and no more
than eight authenticated nonces. Excess sockets are closed without ending the
pending session. A wrong token does not consume the one valid session. A
stopped or expired listener makes an old pairing string useless.

An unauthenticated client can temporarily occupy all eight TLS handshake slots
until the per-operation timeout. A legitimate connection is rejected while all
slots are occupied, but the listener remains alive and accepts it after a slot
expires or closes. This availability limit prevents unbounded socket and
goroutine growth; authentication and diagnostic state remain unaffected.

The token and certificate pin never appear in the peer result, ordinary report,
or returned error. Listener readiness and the pairing string go to stderr in
both output modes so stdout contains only the final result. Stderr is therefore
a deliberate secret-bearing pairing channel for that invocation and must be
handled accordingly.

### Wire protocol

Protocol version 1 uses TLS-protected messages framed by a four-byte
big-endian length followed by UTF-8 JSON. JSON was chosen because it is
deterministic for the defined structs, inspectable in tests, and does not add a
serialization dependency. Go `gob` is not used.

Every message carries `version` and a fixed `type`:

| Type | Direction | Purpose |
|------|-----------|---------|
| `hello` | connector to listener | authenticate the control connection, echo a random challenge, and offer the connector's bounded reverse endpoints |
| `hello_ok` | listener to connector | prove the listener completed the authenticated application exchange and identify itself |
| `probe` / `probe_ok` | either test direction | authenticate one family-specific connection and echo a fixed 32-byte random payload |
| `evidence` | each side once | exchange at most two structural observations, one per family |
| `done` | connector to listener | confirm both sides received the evidence before closing |

Frames are limited to 16 KiB. Endpoint and peer-name fields are bounded,
endpoint offers and evidence collections contain at most two entries, each
session has a fixed message sequence, and JSON with unknown fields, trailing
values, malformed encoding, an unknown type, or a different version is
rejected. Reads allocate only after checking the frame length. Peer strings are
sanitized before display. There is no message for a filename, command, target
port range, shell input, configuration change, or arbitrary diagnostic action.

The listener makes at most one bounded TLS probe per address family to the port
offered by the authenticated connector. It replaces the offered IP with the
source IP actually observed on an authenticated connection in that family. If
it has not observed that family, it records `peer_address_unverified` and does
not dial the offered address. A peer therefore cannot select another host as a
probe target.

Version 1 is intended to remain compatible across releases. A release may add
optional result fields without changing the wire. Any incompatible message or
semantic change requires a new protocol version and pairing prefix; version 1
peers reject it instead of attempting a downgrade. There is no cross-version
negotiation in the first protocol.

### Evidence and diagnoses

The authenticated control channel is recorded separately from the diagnostic
attempts. Each independent attempt records:

- semantic direction (`listener_to_connector` or
  `connector_to_listener`),
- IPv4 or IPv6,
- actual source and destination socket addresses where known,
- `PASS`, `FAIL`, or `N/A`,
- cross-platform cause such as `connection_refused`, `timeout`, or
  `unreachable`,
- whether TCP connected,
- whether the pinned TLS peer authenticated,
- whether the 32-byte application payload completed,
- elapsed milliseconds.

This supports the following combined diagnosis IDs:

| ID | What the evidence proves |
|----|--------------------------|
| `peer_bidirectional_ok` | authenticated small application traffic passed in both directions |
| `peer_directional_failure` | at least one direction passed and the other failed; wording names the traffic direction, not a device firewall |
| `peer_symmetric_failure` | the independent bounded attempts failed in both directions while the control channel remained available |
| `peer_address_family_asymmetry` | one tested family carried peer traffic while the other tested family did not |
| `peer_listener_local_only` | the failed destination for the tested family was definitively bound only to loopback |
| `peer_application_failure` | TCP and pinned TLS succeeded but the fixed application payload did not |
| `peer_security_failure` | TCP connected but the endpoint did not authenticate as the paired TLS peer |
| `peer_incomplete_evidence` | too little independent evidence exists to distinguish a directional or endpoint failure |

`connection_refused` proves that the tested address actively refused the TCP
connection. It does not distinguish no listener from an active rejecting
filter. A timeout or unreachable result does not distinguish endpoint
filtering, routing, address translation, a stale address, or another
reachability failure. Directional and address-family diagnoses therefore set
`ambiguous: true` and list the remaining explanations. They never claim a
firewall, NAT, or routing root cause without independent proof.

Peer version 1 exchanges only the fixed 32-byte challenge plus its small
protocol messages. It does not reuse the ordinary 24 KiB Path MTU probe because
the peer protocol's own reader changes the control evidence that probe relies
on. It cannot diagnose "small succeeds, large stalls" and makes no MTU or PMTU
claim. It also does no traceroute orchestration, packet capture, raw sockets,
port scanning, remote shell, or repair.

### Direct-connect and privacy limits

There is no Network Doctor service, hosted rendezvous, relay, account,
telemetry, UPnP, NAT-PMP, or automatic firewall change. The connector must
reach at least one address printed by `--peer-listen`. If the listener is behind
NAT, its operator must already have a directly reachable address and port; peer
mode does not create one. The reverse test uses the connector's temporary
listener and the source address the listener actually observed for that family.
An unobserved family is not dialed. A NAT or stateful filter may still prevent
that new reverse connection. The result says so without pretending to know
which device or rule caused it. A relay could later carry the same evidence
messages without changing their semantics, but version 1 implements no relay
transport.

The peers exchange their sanitized host names, the temporary listener
addresses they offer, the actual local and remote socket addresses seen during
the session, address families, phase outcomes, and timing. A reverse address
that could not be verified is recorded as `N/A` with cause
`peer_address_unverified`. This can reveal
private addresses, public NAT addresses, interface choices, and host names.
Nothing is sent anywhere except the paired direct endpoints, and no telemetry
exists, but review a saved result before sharing it.

### Peer JSON output

`--json` in peer mode emits `netdoc.peer.v1`, not the ordinary report schema:

```json
{
  "schema": "netdoc.peer.v1",
  "version": "1.2.3",
  "protocol_version": 1,
  "local": {
    "role": "connector",
    "name": "machine-b",
    "listen_addresses": ["192.168.1.21:53122"],
    "observed_address": "192.168.1.21:49018"
  },
  "remote": {
    "role": "listener",
    "name": "machine-a",
    "listen_addresses": ["192.168.1.20:4242"],
    "observed_address": "192.168.1.20:4242"
  },
  "channel": {
    "established": true,
    "family": "ipv4",
    "local": "192.168.1.21:49018",
    "remote": "192.168.1.20:4242",
    "ms": 3
  },
  "observations": [
    {
      "direction": "listener_to_connector",
      "family": "ipv4",
      "source": "192.168.1.20:49410",
      "destination": "192.168.1.21:53122",
      "status": "PASS",
      "tcp_connected": true,
      "tls_authenticated": true,
      "application_traffic": true,
      "payload_bytes": 32,
      "ms": 2
    },
    {
      "direction": "listener_to_connector",
      "family": "ipv6",
      "status": "N/A",
      "cause": "family_unavailable",
      "tcp_connected": false,
      "tls_authenticated": false,
      "application_traffic": false,
      "payload_bytes": 0,
      "ms": 0
    },
    {
      "direction": "connector_to_listener",
      "family": "ipv4",
      "source": "192.168.1.21:49022",
      "destination": "192.168.1.20:4242",
      "status": "PASS",
      "tcp_connected": true,
      "tls_authenticated": true,
      "application_traffic": true,
      "payload_bytes": 32,
      "ms": 2
    },
    {
      "direction": "connector_to_listener",
      "family": "ipv6",
      "status": "N/A",
      "cause": "family_unavailable",
      "tcp_connected": false,
      "tls_authenticated": false,
      "application_traffic": false,
      "payload_bytes": 0,
      "ms": 0
    }
  ],
  "diagnosis": {
    "id": "peer_bidirectional_ok",
    "verdict": "ok",
    "summary": "Authenticated peer traffic succeeds in both directions.",
    "evidence": ["listener_to_connector/ipv4", "connector_to_listener/ipv4"],
    "ambiguous": false
  },
  "ok": true
}
```

`observations` is always ordered listener-to-connector IPv4, listener-to-
connector IPv6, connector-to-listener IPv4, connector-to-listener IPv6. An
unavailable family has an explicit `N/A` observation with
`cause: "family_unavailable"`. The two machines reverse only `local` and
`remote`; directions keep their semantic names. Field names, ordering rules,
status/cause values, diagnosis IDs, and the meaning of `ok` are stable for this
schema. `ok` is true only when small authenticated traffic passes in both
directions. A diagnostic failure exits `1`; bad peer CLI arguments or an
unreadable pairing input exit `2`. Existing ordinary exit meanings and JSON
fields are unchanged.

## Drill-down tools

Press `e` after a completed diagnosis to replace the focused Details panel with
its causal explanation. It opens with the [confidence](#diagnosis-confidence) in
the answer, then separates observations supporting it, observations that rule
out or contradict alternatives, and relevant checks that were not evaluated. Press `e` again for the ordinary row details. The full key
cheatsheet behind `?` is generated from the same binding, so custom key presets
cannot make dispatch and help disagree.

Each diagnosis row is *evidence*; when you want proof beyond the built-in observations, run the real tools as cancellable streaming jobs: several run at once, and `tab` switches between the live ones. The Actions menu shows the tools available for the current target with their hotkeys and omits missing binaries. Output is bounded and sanitized (no terminal-escape injection from a hostile server); reports include version/OS metadata plus each job's command, status, duration, and last 15 output lines.
Review your local copy before sharing, since tool evidence may contain sensitive data.

The same hotkeys map to each OS's built-in tools:

| Key | Linux | macOS | Windows |
|-----|-------|-------|---------|
| `I` | `ip route` | `netstat -rn` | `route print -4` |
| `s` | `ss -tunp` | `netstat -an -p tcp` | `netstat -ano` |
| `p` | `ping -c 4 -W 2` | `ping -c 4` | `ping -n 4 -w 2000` |
| `d` | `dig +time=2 +tries=1` | `dig +time=2 +tries=1` | `nslookup` |
| `c` | `curl … -w '…'` (concise summary) | same | `curl.exe` (bypasses the PowerShell 5.1 `curl` alias) |
| `c` (SSH target) | `ssh -v -o BatchMode=yes …` (bounded banner/handshake check) | same | same |
| `c` (SMTP target) | `openssl s_client -starttls smtp` | same | same |
| `t` | `traceroute -w 2 -q 1 -m 20` | same | `tracert -w 2000 -h 20` |
| `m` | `mtr --report --report-cycles 5` | same (via brew) | `pathping -h 20 -q 5 -p 100 -w 500` (own 90 s budget) |
| `n` | `nmap -sT -Pn --host-timeout 110s` (the explicit target port, else nmap's default top 1000) | same | same |

`n` and `v` are gated behind an explicit confirmation before their active probes run. `n` uses a plain connect scan with nmap's default timing and no version/OS detection. `v` runs host discovery without raw sockets or root, and caps its scope at the source address's `/24`.

The `c` slot is protocol-aware: HTTP(S) and unknown-port targets get `curl`, while SSH (port 22) and SMTP (ports 25/587) targets get a protocol-appropriate handshake probe rather than an HTTPS-oriented `curl` line. The SSH check uses a throwaway known-hosts file (no prompts, no writes) and disables authentication with `PreferredAuthentications=none`, stopping after the banner and key exchange.

The routes and sockets tools are target-independent; the rest need a host. Tools run with an argument slice (never a shell string), in their own process group on Unix (so cancelling kills descendants too), and without privilege escalation. The displayed command is copy-pasteable in a POSIX shell (Linux/macOS) or PowerShell (Windows; cmd.exe paste is not supported).

`--toolbox [<host>]` starts without auto-running the chain (press `space` for the Actions menu or `r` to run the checks). With no host, only the target-independent tools are offered.

### Local devices

`v` answers "I cannot reach the printer" in two steps, so neither one has to be known in advance. The first is the map: unprivileged `nmap -sn` across the source address's `/24`, which finds a device only if it accepts or refuses a TCP connect on port 80 or 443. This machine is listed separately rather than as a device to diagnose, and an address gains a name when mDNS, reverse DNS, or an `ssh_config` alias supplies one.

`enter` on a device opens it and asks what it answers on: one round of ordinary TCP connects, run in parallel inside a single probe timeout, against a fixed list of fifteen ports (21, 22, 23, 53, 80, 443, 445, 515, 631, 2049, 3389, 5900, 8080, 8443, 9100). This is a chooser, not a scan: the list is fixed rather than a range, and nothing is sent after the connect, so the name beside a port ("IPP", "JetDirect") is that port's registered service name and not a claim about what the device is.

`enter` on a service makes it the target and runs the normal checks against it, so a printer picked off the map becomes `192.168.1.23:631` instead of an HTTPS check against a port it never had. Ports whose protocol netdoc probes add their rows (`http`, `https`, `ssh`); the rest stop at the TCP rung, which is all a connect can honestly report. `esc` returns to the device list, and `r` still accepts a port typed by hand for a service the list does not carry.

When nothing answers, the panel says which of the two things happened: refused connections show the device is on the network with nothing listening on those ports, while silence leaves powered off, gone, and dropping traffic all open. A target on this machine's own network is also diagnosed as one: a failed connect to it is never explained by the state of internet egress, which it does not use.

### SSH login

`S` logs in to the current target, the machine the checks are about, so it needs one (`r` sets it). The form asks for the three things that are yours rather than the target's: `tab` moves between fields, `←`/`→` picks the key, `enter` connects, and `esc` backs out.

```
╭────────────────────────────────────────────────────╮
│ SSH login to 192.168.1.50:2222                     │
│   Username  mplaczek                               │
│ ▸ Key       id_rsa  (3 of 4)  ←/→                  │
│   Password  *******                                │
╰────────────────────────────────────────────────────╯
```

Unlike the drill-down tools, this is not a bounded job: `netdoc` suspends itself and gives `ssh` the real terminal, so the session is fully interactive and anything the form left blank (a key passphrase, a host-key check, a 2FA code) is asked by `ssh` on screen. When the session ends the TUI comes back with `ssh`'s stderr in the job pane, so a `Permission denied` is still readable afterwards instead of being painted over.

The form fills in `ssh` options, nothing more:

| Field | Effect |
|-------|--------|
| (host) | the target, plus `-p` when it named a non-default port |
| Username | `-l <login>`, not `login@host`, so a name starting with `-` stays a name |
| Key | `-i <path> -o IdentitiesOnly=yes`, so a loaded agent can't spend the server's auth attempts before this key is tried |
| Password | see below |

The key list is the private keys in `~/.ssh`, each recognized by its `.pub` half sitting next to it, and no key file is ever opened or parsed. `none` (the first entry) leaves key selection to `ssh`, i.e. to the agent and `ssh_config`, which is also where a key kept outside `~/.ssh` belongs.

The typed password is echoed as dots and never reaches a command line, notice, or report. It is passed to `ssh` through the environment (`SSH_ASKPASS`), where `ssh` re-executes `netdoc` as its askpass helper and reads the secret from the helper's stdout. What that buys: the secret stays out of argv, which every process on the machine can read, and out of your shell history, though not out of memory. The password field is cleared once connecting starts, but by then the value has been copied into `ssh`'s environment, where it stays until `ssh` exits and is inherited by the whole subtree `ssh` starts: `ProxyCommand`, `LocalCommand`, and `ProxyJump`'s own `ssh`. On Linux that environment is readable through `/proc` by your own processes and by root; anything your `ssh_config` runs sees it too. `-o NumberOfPasswordPrompts=1` stops `ssh` re-offering a rejected one.

On Windows, this password handoff requires OpenSSH_for_Windows 8.6p1 or newer. Network Doctor checks `ssh -V` before connecting; an older or unrecognized client leaves the form open with an explanation instead of launching `ssh` with an ignored password. Leave the password field blank on that client to have `ssh` ask on the terminal.

Because forced askpass routes *every* prompt to the helper, the helper answers only password and passphrase prompts and refuses the rest. So the first connection to an unknown host, where `ssh` asks you to verify the host key, needs one run with the password field blank, which puts that question back on your terminal where it belongs.

The whole `ssh` subtree inherits the askpass setting, so with `ProxyJump` in your `ssh_config` the jump host's `ssh` asks the helper too. The prompt names the machine it is asking for (`user@host's password:`), and the helper answers only when that host matches the target, so the jump host's prompt goes back to your terminal. Prompts naming no host (a key passphrase, a PAM keyboard-interactive `Password:`) are still answered on a direct connection, where only one machine can be asking; refusing those would break ordinary logins. Add a proxy and they name no host *and* could be either end, so the helper refuses all of them. Wording is no help there, since keyboard-interactive text is written by the far end, so a jump host can call its question a passphrase, and that run wants the password field blank anyway, which puts the prompt back on your terminal. All of this depends on netdoc being able to read your resolved config (`ssh -G`); when that lookup fails there is no way to tell whose prompt is whose, so password-assisted login is refused outright and the form says so.

### JSON output

`--json` runs the same probe DAG headless, with no TUI, and prints one JSON document to stdout:

```json
{
  "version": "1.2.3",
  "target": {"host": "github.com", "port": 443, "protocol": "tls+http"},
  "checks": [
    {"id": "dns", "name": "DNS github.com", "status": "PASS", "ms": 12, "detail": "github.com → 140.82.113.3 (resolver tried: 127.0.0.53)", "addrs": ["140.82.113.3"], "resolver_targets": ["127.0.0.53:53"]}
  ],
  "summary": "All checks passed. github.com:443 looks healthy.",
  "verdict": "ok",
  "ok": true
}
```

`status` is one of `PASS`, `WARN`, `FAIL`, `SKIP`, `N/A`, or `INCOMPLETE`. `target` is `null` in generic (no-target) mode. `ms` is the check's wall time truncated to milliseconds but floored at `1`, so `0` means the check never ran. Optional per-check fields (`cause`, `address_families`, `fix`, `addrs`, `resolver_targets`, `selected_ip`, `source`, `iface`, `network`, `portal`, `attempts`, `routes`) are omitted when empty. `resolver_targets` is the sorted, unique set of DNS service addresses recorded from Go's resolver `Dial` hook. It proves that those servers were dialed, not which one returned a response or supplied any particular address: Go resolves A and AAAA as independent queries that fail over independently, so one hostname lookup can be answered by more than one server. It is absent when a lookup was satisfied without dialing DNS, including a hosts-file result reached before any query. The `detail` text follows the same rule and credits the answer to no server, however few were dialed: one reads `resolver tried: …` and two or more read `resolvers tried: …`. A single dialed server is not provenance either, because a host configured `hosts: dns files` reads its hosts file after a query that came back with nothing, so a lookup there can dial one server, be answered by none, and still return addresses. `internet_tcp.address_families` records the independently tested IPv4 and IPv6 state as `reachable` or `unreachable`. `target_tcp.address_families` records the same states for a dual-stack target after comparison with the host's independent family paths. Under `--iface` or an explicit source address, a family the selected source has no address for is never dialed and its key is omitted, meaning untested rather than unreachable. A target family is also omitted when the target publishes it but the host did not prove a usable local path for it. A selection leaving no usable family at all reports the whole egress row as `N/A`, as the QUIC and encrypted-DNS rows already do. A configured egress family whose path fails while the other succeeds warns with `ipv4_unreachable` or `ipv6_unreachable`. Failed QUIC, encrypted-DNS, proxy, and TLS checks populate `cause` so automation can distinguish failure stages without parsing `detail`; QUIC uses `timeout` or `quic_handshake_failure`, encrypted DNS uses `timeout` or `encrypted_dns_unavailable`, while TLS values include `certificate_expired`, `certificate_not_yet_valid`, `hostname_mismatch`, `untrusted_issuer`, `tls_handshake_failure`, `tcp_unreachable`, `timeout`, and `connection_closed`. Failed direct egress may use `no_default_route`, `gateway_unreachable`, `selected_path_failed`, or `preferred_route_failed`, read from the local routing and neighbor tables on Linux, macOS, and Windows. When both families fail, the cause comes from a family that has default routes to describe: a host with no IPv4 default route at all is not reported as routeless when the IPv6 routing it actually uses is what broke. macOS route entries carry no preference metric, so `preferred_route_failed` comes only from Linux and Windows, and `gateway_unreachable` needs a neighbor cache entry that exists and shows the next hop unresolved, so an unseen next hop leaves the weaker `selected_path_failed` rather than a guess. The `portal` object marks HTTP interception corroborated by both fixed connectivity endpoints, and includes `redirect_url` only when one of those responses supplied a valid HTTP(S) sign-in URL; where both did, the first endpoint in netdoc's fixed order wins, so the value never depends on which request finished first. The app displays that URL but never opens it. A single endpoint answering unexpectedly leaves the object absent and warns instead. Field names and the status vocabulary are stable, so they are safe to script against. Exit codes follow the [table in Usage details](#exit-codes) (`ok: false` ⇒ exit `1`).

`INCOMPLETE` is the one status value no probe can return, and it carries the same meaning here as it does in [a snapshot](#diagnostic-snapshots). The check was in the run's check set but never reported a result at all, which is what a cancelled or interrupted run leaves behind. It is not a `SKIP`: nothing decided to leave it out, the run ended first. An `INCOMPLETE` row is never a pass, and a report holding one is never `"ok": true`, so the absence of an observation can never be read as a passing check. The row itself is still emitted, so a reader can see that the check existed and was not reached.

`routes` is the operating system's own route decision for each destination the check was about, one entry per address, since route selection is per address and not per hostname. netdoc asks the kernel the same question `ip route get` asks and records the answer; it does not read a routing table and re-run the selection itself, and it never dumps one. The lookups are unprivileged and bounded: the general Internet endpoints on the `iface` row, each recorded resolver target on the `dns` row, and each resolved target address on the `target_tcp` row. They describe netdoc's own flows: under `--iface` or an explicit source address every dial in the run leaves from a chosen local address, and the lookup carries that source too on the platforms whose route API accepts one, so a rule selecting on source address is resolved the same way it would be for the real connection. Linux passes it to the FIB lookup and Windows passes it to `GetBestRoute2`; a macOS routing socket takes no source, so the answer there is the machine's own decision for the destination, as it is for any unbound run.

Each entry carries `destination`, `family`, and whatever the platform supplied: `interface`, `gateway` (absent when the destination is on-link), `source`, `prefix` (the route entry that matched), `metric`, `table`, `table_known`, `interface_mtu`, `tunnel`, `tunnel_kind`, `unreachable`, `reason`, and `competing`. An absent field means the platform did not supply it and is never to be read as zero, which is why `metric` is omitted rather than written as `0` where none was reported. `routes` itself is absent on a platform netdoc cannot ask, which is not the same as having no route: `"unreachable": true` is how "no route" is said.

`tunnel` is `tunnel` when the operating system itself names the device an encapsulating kind (`tunnel_kind` then carries which: `wireguard`, `tun`, `gre`, `ppp`, and so on), `likely` when the link only has the shape of one, and `direct` for an ordinary interface. It is absent when nothing classified the interface, which reads as unknown and not as direct. There is no list of VPN product names anywhere in netdoc; a product that installs an ordinary Ethernet device is deliberately not detected rather than guessed at.

`table` names the routing table or routing domain the decision came from, and `table_known` is whether the platform named one at all. The two are needed together because the main table is written as an absent `table`: an operating system that says "this came from the main table" and one that says nothing about routing domains both leave the field out, and only `table_known` tells them apart. Linux reports the table the FIB lookup resolved the destination in, so `table_known` is true there and a policy table keeps its number, which is the whole point of recording it. macOS and Windows expose no routing domain in their route APIs, so `table_known` is absent on both and a reader must take that as unknown rather than as the main table. A snapshot written before the field existed has no table knowledge either, which is the same unknown. A table the operating system consults on its own is not a routing domain anything selected, and comparisons read it as the ordinary case: a Linux machine with no policy routing at all resolves its own addresses in `local` and everything else in `main`, so localhost lands in a different table per family, and treating that as a difference would report one on every dual-stack host. A selected table outside that set is evidence that the kernel resolved this flow through another routing domain, and it is not evidence of which rule, firewall mark, VRF, or application policy sent it there: a route lookup does not report that, and netdoc does not read policy rules on any platform.

`prefix` is the route entry the operating system said it matched, and it is present only where the platform reports one. macOS and Windows do; Linux does not. A Linux route lookup echoes the length the query asked about rather than the length of the entry it matched, so every answer to a host lookup comes back at the full address length whatever the table holds. Reading that back as a matched prefix would report every destination as a host route, so the field stays absent there rather than carrying a number the kernel never meant. Everything that follows from a named entry follows only on the platforms that name one: `competing` and a `lower_metric` reason need both the entry and a preference metric, so they come from Windows alone today, and even there the list is the other default routes that were available rather than an enumeration of every route that could have covered the destination. netdoc reads no policy rules on any platform.

`reason` is the only derived field, and it is what answers where `prefix` cannot. It is drawn from the route entry where the platform names one, and otherwise from comparing this destination's decision with the decision the same kernel gave for general Internet traffic, which is two answers from the operating system rather than a guess about its table. Those two kinds of evidence do not support the same claims, and the vocabulary keeps them apart. `default_route` (the destination matched the default route), `more_specific_than_default` (a narrower entry than a default route matched it, which is the split-tunnel case at the level of the routing table), `host_route`, and `lower_metric` are statements about which entry won, and are reported only where the platform named it. `same_path_as_default` (this destination leaves by the same interface and next hop as general Internet traffic, and out of the same routing table where the platform named one) and `differs_from_default_path` (it leaves by a different interface, a different next hop, or a different named routing table) are the weaker answers available where the entry is unnamed, and they say nothing about why. That distinction is not pedantry: a policy rule, a separate routing table, a VRF, source-specific routing, or a multipath route choosing another next hop each send one destination down a different path with no narrower prefix anywhere in it, and a rule pointing at a table whose winning entry is itself a default route is indistinguishable from here. `on_link` (no next hop between here and the destination) and `no_route` are read from the decision itself on every platform. `interface_mtu` is the selected link's own MTU and is never the end-to-end path MTU, which only the `path_mtu` row measures.

Resolver failures can add `dns_timeout` or `dns_temporary_failure`; a target TCP
check whose every attempted address explicitly refuses the connection adds
`connection_refused`; a peer that accepted TCP before resetting adds
`connection_reset`. Each target attempt can add the same stable connection
`cause`. `aborted: true` means cancellation or the enclosing probe deadline
ended that attempt, so it is not evidence that the individual address failed.
These are optional additions to the existing check objects.

`fix` is the one-line remedy netdoc prints as that row's `Fix:` line, on a Warn row as well as a failed one, and is omitted where there is nothing useful to suggest. Some hints name the thing to change by whatever the host OS calls it. A name-resolution failure directs Linux users to `/etc/resolv.conf` and DNS settings, while macOS points at System Settings and Windows at `ipconfig /all`. Others, such as the certificate and routing hints, carry no OS-specific wording at all.

`failed_stage` names the first check that failed (`dns`, `target_tcp`, `tls`, …) and is omitted when none did, which is enough to route a bug report without reading any prose.

`--json --watch` prints the same document once per pass, compacted onto a single line (NDJSON), five seconds apart, until the process is interrupted, for the intermittent failure you can't sit and watch:

```sh
netdoc --json --watch github.com | jq -c 'select(.ok | not) | {ts, failed_stage, summary}'
```

Those lines add a `ts` field (RFC 3339, UTC) saying when the pass ran; nothing else changes. The exit code is the last completed pass's.

`verdict` is the summary as a machine-readable class, for the question a script actually asks: *is my network broken, or is theirs?*

| `verdict` | Meaning |
|---|---|
| `ok` | Every check passed |
| `degraded` | Everything asked for works, but some rung is impaired: high latency, a proxy-only network, direct egress blocked while the target is fine |
| `dns` | The name did not resolve |
| `network` | **The path is unavailable**: the link is down, there's no egress, or the target is unreachable with nothing else proving the network usable |
| `service` | **The path works, the far end does not**: TCP refused while the general internet is reachable, or TLS/HTTP/banner failing on top of a good connection |
| `incomplete` | A check has no result (the chain did not finish) |

The `network`/`service` split is decided by evidence, not guesswork: an unreachable target is only blamed on the service when direct egress independently succeeded. With no working egress to compare against, netdoc says `network` rather than accusing a host it never reached.

### Diagnosis findings

`verdict` says what kind of problem this is. `findings` says which problem it is.

Every run is interpreted once, and that one interpretation produces the summary, the verdict, the row the app puts your cursor on, and this array. They cannot disagree with each other, because nothing reconstructs the diagnosis a second time.

```json
"findings": [
  {
    "id": "tls_certificate_expired",
    "focus": "tls",
    "confidence": "high",
    "evidence": ["tls", "target_tcp"],
    "causal_evidence": [
      {"kind": "support", "check": "tls", "observation": "cause"},
      {"kind": "support", "check": "target_tcp", "observation": "status_pass"},
      {"kind": "ruled_out", "check": "target_tcp", "observation": "status_pass", "candidate": "tls_tcp_unreachable"}
    ],
    "remediation": {
      "id": "renew_certificate",
      "action": "Renew the certificate, or check this machine's clock",
      "why": "The handshake was rejected because the certificate is outside its validity window. Either it really has expired, or this machine's clock runs far enough ahead to make a valid one look expired.",
      "steps": [
        "Compare the validity dates on the TLS row with today's date.",
        "Confirm this machine's clock before blaming the certificate."
      ],
      "command": ["timedatectl", "status"],
      "expect": "A certificate whose validity window covers now, on a machine whose clock is right."
    }
  }
]
```

`id` is a stable identity to branch on, and never changes when the English sentence beside it is reworded. `focus` is the check id whose `detail` and `fix` belong to this finding, so the row's own hint stays on the row that wrote it rather than being restated here. `confidence` is how strongly the observations support this finding as an explanation, described in [Diagnosis confidence](#diagnosis-confidence). `evidence` remains the original compatibility list of observed check IDs, `focus` first. `causal_evidence` is its typed form and may also name a relevant check that was not evaluated. A `value` identifies a member of a structured observation, such as `ipv6` or one attempted address. `counterfactual` names the variable that changed and the observed alternatives, each of which references causal evidence already carried by the finding. `remediation` is what to do about the finding, described below.

Each causal item has a `kind`, a check ID in `check`, and, when an observation
exists, its typed identity in `observation`. The value itself remains on the
referenced check. This keeps a measured fact separate from what that fact means
for a diagnosis.

| `kind` | Meaning | Additional field |
| --- | --- | --- |
| `support` | The observation directly supports the selected diagnosis | none |
| `contradiction` | The observation weakens a named alternative but does not exclude it | `candidate` diagnosis ID |
| `ruled_out` | Independent positive evidence excludes a named alternative | `candidate` diagnosis ID |
| `not_evaluated` | The check supplied no observation and remains unknown for this run | `reason` |

The observation vocabulary is `status_pass`, `status_warn`, `status_fail`,
`status_skip`, `status_not_applicable`, `cause`, `dns_answers`,
`dns_not_found`, `captive_portal`, `timeout`, `clock_offset`,
`status_downgraded`, `family_reachable`, `family_failed`,
`address_succeeded`, `address_failed`, `route_tunneled`, `route_direct`,
`route_unreachable`, `route_path_differs`, `route_next_hop_differs`,
`route_table_differs`, `route_family_split`, and `route_interface_mtu`. Not-evaluated reasons are `prerequisite_failed`,
`not_selected`, `not_applicable`, and `incomplete`. A skipped, not-applicable,
missing, or incomplete check is never enough to rule out a cause. An absent
`causal_evidence` field means this producer did not record an explanation; it
does not mean the listed alternatives were tested.

The eight `route_*` observations describe the path a row's own traffic took, and
each is a fact about that one row: which interface it left by, whether that
interface encapsulates, and whether the operating system had a route at all.
None of them is a verdict. A tunnel is not a fault, and no diagnosis is reached
because one exists; route observations only ever attach to a conclusion the
checks had already proved on their own. Where the interesting fact is that two
rows took different paths, it is recorded as two observations, one on each row,
because a single item must be checkable against the row that carries it:
`route_path_differs` on the `dns` row names the target's interface in `value`,
and a split tunnel appears as `route_tunneled` on one row beside `route_direct`
on the other. Two flows can leave by one interface and still be routed apart,
which is what the other two path observations are for. `route_next_hop_differs`
is this row being handed to a router other than the one named in `value`, down
what is otherwise the same link, and it is reported only where both paths have
a next hop, since "on-link here, through the router there" is the ordinary
shape of a destination on the local network rather than a routing decision
worth reporting. `route_table_differs` is the kernel having resolved this row's
destination in a named routing table other than the ones it consults by
itself, which is evidence that another routing domain was selected and never
evidence of what selected it; it carries no `value`, because the fact is about
this row's own table and the other side is either an ordinary table or
unknown. Both of those read exactly as strongly as the row's `tunnel`
state: where the operating system named the device kind, the app says the
traffic left through that tunnel, and where only the link's shape suggested it,
the app says the link has the shape of one, since a mobile broadband modem has
the same shape. `route_direct` is the absence of any such classification and
never a proof that nothing encapsulates the path, which is why a VPN presenting
an ordinary Ethernet device is not detected. A resolver on loopback records no
path at all: a local stub is reached over `lo` by definition, so it would
always look like a different path while its own upstream path, the one that
matters, stays invisible. `route_family_split` is one target's two
families taking materially different routes, compared on the dimensions that
are not family-scoped: the interface and a routing domain something selected. A next hop
and a source address are different in IPv4 than in IPv6 on every dual-stack
host, so neither can be a split. `route_interface_mtu` reports that the
selected link is narrower than the one general traffic uses; it is the link's
own MTU, never a measured path MTU.

The same interpretation branch creates the diagnosis and its causal items.
There is no pass that receives a final diagnosis ID and reconstructs plausible
reasons afterwards. The ordered array is deterministic, rejects duplicates in
snapshots, and keeps every relationship tied to the check observation that
actually occurred.

The array is omitted when the run reached no specific conclusion: everything passed, the run is still going, nothing was selected, or the only impairment is on a row no diagnosis is about. Those runs answer with `summary` and `verdict` alone rather than being given an identity the probes did not support. The primary finding remains first and supplies the headline. Additional counterfactual findings can preserve a separate partial impairment proved by the same run.

| `id` | What netdoc concluded |
|---|---|
| `no_usable_interface` | No interface is up, so the link is down |
| `captive_portal` | Traffic is intercepted by a sign-in portal |
| `offline` | Neither DNS nor direct egress to the reference endpoints is working |
| `direct_egress_blocked` | Direct TCP egress to the reference endpoints failed while something else still works, and nothing in the run reached a public destination directly |
| `reference_egress_unreachable` | The reference endpoints are unreachable while the endpoint under test answered a direct connection, so egress itself works |
| `direct_egress_degraded` | Direct egress carries traffic but is impaired |
| `proxy_only_network` | Only the environment proxy has egress |
| `local_egress_failure` | Local routing state classified this machine's own path as broken, so nothing beyond it was fairly tested |
| `probable_path_mtu_problem` | A protocol exchange and a bulk write both stall, which is what a path MTU black hole looks like |
| `system_dns_failure` | The configured resolver fails on a name public DNS resolves |
| `dns_name_not_found` | Neither resolver has A/AAAA records for the name |
| `dns_failure` | Name resolution is failing, with no second opinion separating the two above |
| `dns_disagreement` | System and public DNS answer with different networks |
| `encrypted_dns_unavailable` | DoH/DoT cannot complete a verified exchange while plain DNS works |
| `quic_unavailable` | UDP/443 fails while TCP/443 works, so applications fall back |
| `proxy_failure` | The configured environment proxy check failed |
| `tcp_connection_refused` | Every connection attempt was explicitly refused |
| `target_unreachable` | The target does not answer though DNS and the internet work |
| `local_device_unreachable` | A device on the local network is silent while this machine's network works |
| `reachability_untested` | The target is silent and direct egress was not checked, so neither end can be blamed |
| `reachability_unlocalized` | The target and the reference endpoints were both silent and nothing observed where the path breaks |
| `ipv4_target_unreachable` | The target works over IPv6 while its IPv4 alternatives fail despite an independently proved IPv4 path |
| `ipv6_target_unreachable` | The target works over IPv4 while its IPv6 alternatives fail despite an independently proved IPv6 path |
| `partial_endpoint_reachability` | An attempted resolved address fails while another address for the same target and port succeeds |
| `tls_certificate_expired` | The certificate is outside its validity window |
| `tls_certificate_not_yet_valid` | The certificate's start date has not arrived |
| `tls_hostname_mismatch` | The certificate is for a different name |
| `tls_untrusted_issuer` | The certificate is signed by a CA this machine does not trust |
| `tls_clock_skew` | A measured clock offset explains the certificate rejection |
| `tls_timeout` | The handshake spent its whole budget without answering |
| `tls_connection_closed` | The peer closed or reset during the handshake |
| `tls_tcp_unreachable` | The TLS dial itself could not reach the port |
| `tls_handshake_failure` | The handshake failed with no cause the client could classify |
| `https_no_response` | TLS completes but no HTTPS response arrives |
| `http_no_response` | No HTTP response arrives |
| `service_banner_failure` | The port accepts TCP but the banner check failed |
| `service_banner_missing` | The port accepts TCP and sent no banner |
| `selected_dns_check_failed` | A `--check`/`--skip` selection left a failed DNS row no other case explains |
| `selected_service_check_failed` | The same, for a service row |
| `selected_network_check_failed` | The same, for a network row |

The TLS identities are drawn from the same classification the `cause` field publishes, so a finding stays as precise as the handshake was. The sentence in `summary` is deliberately more hedged than the identity for the failures a client genuinely cannot tell apart, and `tls_handshake_failure` is what an unclassifiable handshake gets rather than a specific accusation.

Nothing here claims a wrong default route, a missing subnet route, or an operator's intent, because no probe proves those. `id` values are added over time; treat an unrecognized one as "some specific problem" and fall back to `verdict`.

### Diagnosis confidence

Every finding carries a `confidence`: how strongly the run's observations
support that finding **as an explanation of what is happening**, given the
alternatives netdoc was able to evaluate.

It is not a probability, and none of these words stands in for a number. It is
also not the severity, not the `verdict`, not a check's status, not how bad the
network is, and not a count of how many checks passed. Being certain a service
is down is not the same as knowing why, and this field is about the why.

| `confidence` | What it claims |
|---|---|
| `high` | A probe observed the specific condition that separates this conclusion from its alternatives, and nothing relevant is left open |
| `medium` | The best explanation the run supports, with an ambiguity remaining: an inference no probe observed directly, an alternative weakened but not excluded, or an observation the run could not make |
| `low` | A real basis for naming the failure, but the evidence identifies the rung rather than the cause, and several causes stay equally consistent with it |
| `insufficient_evidence` | No causal claim is warranted at all. This is what an explicitly untested or unexplained run gets, and it is deliberately not high confidence in knowing nothing |

Two things about a finding decide it. The first is what kind of claim the
identity makes, which never varies between runs: `captive_portal` and
`tcp_connection_refused` name conditions a probe can observe outright, while
`probable_path_mtu_problem` is a correlation, `dns_failure` names a rung with
several live causes, and `reachability_untested` says in its own name that the
distinguishing observation was never made. The second is what this run's
`causal_evidence` left standing. A `ruled_out` item excludes an alternative; a
`contradiction` only weakens one, so a candidate that is contradicted and never
ruled out is still a live explanation and keeps a finding off `high`. Presence
is what counts, never quantity: a second ruled-out alternative buys nothing the
first did not.

A few identities need one named exclusion on the record before they can reach
`high`, because their supporting observation is not by itself the differential.
`tls_certificate_expired` and `tls_certificate_not_yet_valid` are read against
this machine's own clock, so a clock that is wrong produces either of them from
a perfectly good certificate, and netdoc has a separate `tls_clock_skew` for
that case. Unless the run took a clock reading and ruled the skew out, those
two stay at `medium`: a run that never looked must not read like one that
looked and settled it.

A `not_evaluated` item is read by its `reason` rather than treated as a hole.
`prerequisite_failed` and `not_applicable` describe checks that did not run
*because* of the failure being diagnosed, so a TLS row skipped behind a dead
resolver says nothing about the resolver and never lowers its confidence.
`not_selected` and `incomplete` are the opposite: an observation that could
have separated two explanations was simply not taken, and that caps the claim.

Confidence is descriptive metadata. It is computed last, once counterfactual
and route evidence have been attached, and nothing in the engine reads it back:
it can never change which finding wins, the ordering, the verdict, the focused
row, the remediation, or the exit code.

It appears as `confidence` on each finding in `--json`, in the `diagnosis`
block of a `.ndoc` snapshot (including `--support` artifacts, where it survives
redaction because the vocabulary is closed), and in the TUI under `e`, above
the evidence it qualifies. A snapshot written before the field existed has no
`confidence`, which means the producer recorded no assessment rather than a
weak one. New values are not added silently; the vocabulary is closed for this
schema.

The four categories are meant to be calibrated against the growing real-world
[field corpus](https://github.com/heymaikol/network-doctor/tree/main/testdata/field),
which can record an expected confidence beside its expected findings. Today
that corpus is small, so the values are a stated policy rather than a measured
one, and nothing here claims that `high` has an established hit rate yet.

### Remediation

A finding says what is wrong. Its `remediation` says what to do about it, as data rather than a sentence to be parsed out of `fix`.

```json
"remediation": {
  "id": "restore_default_route",
  "action": "Restore a default route",
  "why": "Nothing in the routing table leads off this network, so traffic for the internet has nowhere to go. That is usually DHCP not completing, a VPN that dropped its route, or a static configuration with no gateway.",
  "steps": [
    "Renew the DHCP lease, or reconnect the VPN that installs the route.",
    "On a static configuration, check that the gateway is set and sits on this machine's own subnet."
  ],
  "command": ["ip", "route"],
  "expect": "A default route (0.0.0.0/0 or ::/0) pointing at the gateway."
}
```

`id` is a stable identity to branch on, from the table below. `action` is the next step in one line, `why` is what makes it the right one given the evidence this run collected, `steps` breaks it down in the order worth trying, and `expect` is what success looks like, so a script or a person knows whether a rerun is worth it yet. `why`, `steps`, `command` and `expect` are omitted when empty, as every other optional field is; `id` and `action` are always present.

`command` is an **argv array, never a shell string, and netdoc never runs it**. It is offered for you to read and run yourself. Every command in the table is a read-only inspection of local state (routes, links, neighbors, resolvers, the clock, interface MTUs), chosen per OS: Linux gets `ip route`, macOS `netstat -rn`, Windows `route print -4`. None of them changes configuration, none escalates privilege, and none carries the target inside it, because investigating the target itself is what the [drill-down tools](#drill-down-tools) are for. A remediation with nothing local worth inspecting has no `command` at all.

The advice is chosen from the finding's `id` and, where the focused check classified its failure further, that check's stable `cause`. So one conclusion can lead to several remediations: `offline` with `no_default_route` says to restore the route, with `gateway_unreachable` says to get the gateway answering, and with `selected_path_failed` says the break is past a router that looks fine from here. A cause netdoc does not have specific advice for keeps the conclusion's general answer rather than losing the remediation.

Where netdoc genuinely cannot tell two causes apart, the remediation says what to investigate instead of presenting a guess as fact: `narrow_tls_failure` lists what is still possible rather than naming one, and `rerun_with_egress_check` says the run itself was too narrow to blame either end.

In the TUI the same advice appears in the Details panel of the row the diagnosis focuses, and `R` reruns the identical checks against the same target once you have acted on it.

| `id` | Next action |
|---|---|
| `bring_up_link` | Bring a network interface up |
| `sign_in_to_portal` | Sign in to the network |
| `check_local_path` | Check this machine's own path off the network |
| `restore_default_route` | Restore a default route |
| `reach_gateway` | Get the default gateway answering |
| `check_router_uplink` | Check the router's own uplink |
| `fix_preferred_route` | Check the interface holding the preferred default route |
| `fix_local_egress_first` | Fix this machine's connection before judging the target |
| `use_proxy_path` | Send the traffic the way this network allows |
| `check_proxy_config` | Check the configured proxy |
| `check_proxy_reachable` | Check that the proxy itself is up |
| `check_proxy_resolution` | Check name resolution on the proxy |
| `check_proxy_egress` | Check what the proxy is allowed to reach |
| `restore_ipv4_egress` | Restore IPv4 egress, or accept an IPv6-only path |
| `restore_ipv6_egress` | Restore IPv6 egress, or accept an IPv4-only path |
| `read_egress_warning` | Read what the egress row is warning about |
| `fix_system_resolver` | Fix or replace the configured resolver |
| `check_the_name` | Check the name itself |
| `check_name_resolution` | Check name resolution on this machine |
| `confirm_split_dns` | Confirm which of the two DNS answers is right |
| `choose_encrypted_dns` | Decide whether encrypted DNS has to work here |
| `expect_tcp_fallback` | Expect the TCP fallback, and open UDP/443 if speed matters |
| `start_the_service` | Start the service, or check the port |
| `trace_the_path` | Work out where the packets stop |
| `check_the_device` | Check the local device itself |
| `rerun_with_egress_check` | Rerun with the general connectivity check included |
| `lower_path_mtu` | Try a lower MTU on the path |
| `renew_certificate` | Renew the certificate, or check this machine's clock |
| `await_certificate_validity` | Check the clock, then the certificate's start date |
| `set_the_clock` | Set this machine's clock |
| `match_certificate_name` | Connect with the name the certificate is for |
| `resolve_untrusted_issuer` | Find out who signed the certificate |
| `check_tls_path` | Check the path before blaming the service |
| `check_tls_termination` | Check what is terminating the handshake |
| `retry_tls_dial` | Retest, since the TLS check could not open its own connection |
| `narrow_tls_failure` | Narrow the handshake failure down by hand |
| `check_application_layer` | Check the service on top of a working connection |
| `check_banner_service` | Check the service behind the open port |
| `identify_listener` | Confirm which service is on that port |
| `rerun_full_chain` | Rerun without the check selection |

`remediation` is additive: it appears alongside the fields findings have always carried, and `fix` on each check is unchanged. A row's `fix` is still the one-line hint that row wrote about itself, with the certificate dates and measurements only that probe held; the remediation is the finished diagnosis's answer for the run. New `id` values are added over time, so treat an unrecognized one as "some specific advice" and show `action` and `steps` rather than branching on it.

## Diagnostic snapshots

`--save file` runs the checks headless and writes a **diagnostic snapshot** of the finished run, conventionally with a `.ndoc` extension:

```sh
netdoc --save incident.ndoc github.com      # just the artifact
netdoc --json --save incident.ndoc github.com  # the report on stdout too
netdoc --support support.ndoc github.com    # sanitized for sharing
```

A snapshot is one finished run, recorded so it can be reopened later without probing anything again: the target as you typed it and as netdoc parsed it, the run settings, every check with its status, timings and evidence, and the diagnosis that was drawn from them. It is meant for the failure you cannot reproduce on demand and for [comparing two runs](#comparing-two-snapshots). Use `--support` instead when preparing a file to share.

`--save` implies headless operation, so it needs no terminal, and it is independent of `--json`: give both to get the usual report on stdout as well. It cannot be combined with `--watch` (a snapshot is a finished run, and a watch never finishes) or with `--toolbox`. The snapshot never changes the diagnosis or the exit code: a run that fails still exits `1` and still saves. A destination whose directory does not exist is rejected with exit `2` before any probe runs, and a write that fails once attempted also exits `2`, since the artifact the run was for does not exist. The file is written through a temporary file in the same directory and renamed into place, so a failed write leaves any previous snapshot intact rather than a truncated one.

### Snapshot format and versioning

The file is JSON, indented and newline-terminated, so it reads in a pager and diffs line by line. Encoding is deterministic: the same run always produces the same bytes.

```json
{
  "schema": "netdoc.snapshot.v1",
  "created_at": "2026-01-02T03:04:05Z",
  "tool": {"version": "1.2.3", "os": "linux", "arch": "amd64"},
  "target": {"raw": "example.com", "host": "example.com", "port": 443, "protocol": "tls+http", "port_explicit": false},
  "options": {"probe_timeout_ms": 4000, "public_dns": "8.8.8.8", "public_dns_auto": true},
  "checks": [
    {
      "id": "dns", "name": "DNS example.com", "deps": ["iface"],
      "status": "PASS", "ran": true, "duration_ms": 12,
      "detail": "example.com resolved to 2 addresses",
      "observed": {"addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"], "resolver_targets": ["192.0.2.53:53", "[2001:db8::53]:53"]}
    }
  ],
  "diagnosis": {"verdict": "network", "summary": "…", "blamed": "internet_tcp", "failed_stage": "target_tcp", "findings": [{"id": "local_egress_failure", "verdict": "network", "summary": "…", "focus": "internet_tcp", "evidence": ["internet_tcp", "target_tcp", "dns"], "causal_evidence": [{"kind": "support", "check": "internet_tcp", "observation": "status_downgraded"}]}]},
  "ok": false
}
```

`schema` is the first field and the artifact's identity. A reader must check it before anything else and refuse a schema it does not know, rather than guessing at the fields underneath. The version moves only for a change an older reader would misread, such as a renamed field, a changed unit, or a changed meaning; adding an optional field is not that, so decoders ignore keys they do not recognize and treat every absent optional field as "not known" rather than as zero.

A support snapshot adds `"redaction": {"sanitized": true, "policy":
"support-v1"}`. Absence means a full-fidelity snapshot. Readers use this
metadata rather than guessing from placeholder-looking values. The field is an
additive v1 extension, so the schema stays `netdoc.snapshot.v1` and older v1
files continue to load unchanged.

`options` records only the settings that decide what the probes did: the per-check timeout, the second-opinion resolver (an IP address, empty when `--public-dns ""` switched that row off), the `--check`/`--skip` selection in the order it was given, and the `--iface` binding netdoc resolved. `public_dns_auto` is present and `true` when the run named no resolver, which is what let that row fall back to the other address family; it is an additive v1 field, absent when the resolver was named, so `public_dns` keeps the address-or-empty meaning every v1 reader already has. `check`, `skip`, and `source` are absent when the run used none of them. Flags that only affect presentation are not recorded, because a comparison never reads them.

Every check the run built appears in `checks`, including the ones that never produced an answer, and `status` says on its own which is which. It is always present and never empty. Alongside the `PASS`, `WARN`, `FAIL`, `SKIP`, and `N/A` used everywhere else, there is one more value that no probe can return, the same one [JSON output](#json-output) uses:

- `SKIP` is a check deliberately left out, because a prerequisite failed.
- `INCOMPLETE` is a check that never reported at all, which is what a cancelled or interrupted run leaves behind. Nothing decided to leave it out; the run ended first.

An `INCOMPLETE` row is never a pass, and a run holding one is never `"ok": true`. That is enforced when the file is written rather than left to readers to remember, so a snapshot in which absent evidence could be read as a passing check does not exist.

`ran` answers a narrower question, and only that one: did the probe body execute. It is what `duration_ms` alone cannot say, since a check that finished in under a millisecond also reports `0`. A skipped row and an incomplete row both report `ran: false`, so `ran` is not how a reader tells them apart; `status` is.

`observed.resolver_targets` holds the same attempted DNS service addresses as the JSON report. It is additive and optional, so an older snapshot with no field makes no resolver-provenance claim. `observed.routes` holds the same per-destination route decisions the JSON report documents above, in the same shape and with the same rule that an absent field is unknown rather than zero. It is an additive optional field: a snapshot written before it existed simply has none, and every reader treats that as "this run recorded no route decisions", never as "there was no route". Nothing stores a routing table; the entries are the answers to the bounded set of lookups the run already had to make.

Within a check, `observed` is what the probe measured and `derived` is what the cross-probe reasoning pass concluded about that row afterwards. Two fields live under `derived`. `status_downgraded` marks an observed egress failure that was relaxed to a Warn because another path proved the network still carries traffic, so its presence says the row's status is a conclusion rather than a reading. `answer_comparison` is on the `dns_public` row and records what that pass concluded when it compared the two resolvers' answers: `agree` or `disagree`, and absent when there was nothing to compare. It is stored because the comparison is made from the addresses the resolvers returned, and a `--support` artifact holds only pseudonyms of those, so a reader that recomputed it would be asking a different question than the run did. Absent never means the answers agreed, and an artifact written before the field existed has none. A row can therefore carry `derived` without its status having been rewritten. `cause`, `verdict`, and the finding IDs use exactly the vocabularies documented for [JSON output](#json-output) and [diagnosis findings](#diagnosis-findings).

Findings also persist their optional `causal_evidence` and `counterfactual`
fields. They record the interpretation made during the incident rather than
asking a future Network Doctor version to reinterpret old observations.
Attempt `cause` and `aborted` fields retain whether an address supplied usable
failure evidence. These are additive v1 fields, so existing `.ndoc` files remain
loadable and the schema stays `netdoc.snapshot.v1`. Loading an older file
without the fields leaves them absent; the decoder never invents historical
relationships. New files validate that every observed relationship points to a
matching check fact, that counterfactual alternatives reference evidence the
finding carries, that not-evaluated reasons match the check state, and that no
item is duplicated.

An `.ndoc` saved from the Watch incident viewer adds an optional `incident`
field to the same v1 snapshot. The root snapshot is the first failing pass. The
incident holds its start and optional recovery time, the number of failing
passes, the last working or degraded run before onset when one exists, the
latest distinct failing run when the failure evolved, and the first recovered
run. These nested states are complete canonical snapshots. Differences are not
stored beside them; readers derive onset and recovery changes with the normal
snapshot comparison rules, so stored answers cannot drift from stored evidence.

The incident field is an additive v1 extension, so the schema remains
`netdoc.snapshot.v1`. Older files continue to load with no incident information,
and no reader may infer history that was never recorded. New incident artifacts
validate UTC RFC 3339 timestamps, chronology, failing and non-failing state
roles, and the one-level nesting bound. An active incident has no recovery time
or recovery state. Incident export remains bounded to the onset plus at most
the pre-failure, latest distinct failing, and recovered snapshots.

Remediation text is deliberately not stored. Fix advice lives on the check rows as `fix`, and the structured next action is regenerable from a finding's `id` together with `tool.os`, so a snapshot does not carry a second copy to fall out of step.

### What a snapshot contains, and what it does not

A snapshot holds only what the run already gathered. Nothing is collected for the file's benefit: no packet capture, no scan of unrelated interfaces or routes, no environment variables, no configuration files, and nothing is uploaded anywhere.

Treat the file as network information about the machine that produced it. It deliberately retains, because a diagnosis is not readable without them:

- resolved IP addresses, the address netdoc selected, and per-attempt errors
- the local source address and interface name probes used
- the connected Wi-Fi network name (SSID), on the `ssid` row
- the target hostname as typed, which may be a private or internal name
- the proxy host and port from `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`, where one is configured
- the second-opinion resolver, and the local clock's offset from a connectivity endpoint's, which is read only from a response that matched what that endpoint documents
- per-destination route decisions under `observed.routes`: the interface chosen, the next hop, the local source address, the matched prefix, the routing table's name and whether the platform named one, and the interfaces of any competing default routes. These describe the local network's shape, and a tunnel's device kind says a VPN is in use

It contains no credentials. Userinfo in a target is rejected by the parser before a run starts, and the proxy rows record only the proxy's host and port, never the username or password from a proxy URL. Probe text is sanitized on the way out of the runner, so a hostile hostname or server banner lands in the file as inert bytes.

## Support snapshots

`--support file` runs the same headless diagnosis as `--save`, then applies the
`support-v1` policy to the structured snapshot before the normal `.ndoc`
encoder writes it:

```sh
netdoc --support support.ndoc github.com
jq '.redaction, .target, .checks' support.ndoc
```

Creation is local-only. Network Doctor does not upload, submit, encrypt, or
send the file. The user chooses whether and how to share it. `--support` can be
combined with `--json`, but not with `--save`, `--watch`, `--toolbox`, or peer
mode. It prints one confirmation on standard error after the sanitized file is
written. The policy applies to the file rather than to the stream: a combined
`--json` run still prints the ordinary full-fidelity report on standard output,
because that stream is live output for scripts rather than something prepared
for sharing. Share the `.ndoc`, not a captured report.

The policy sanitizes the target spelling and hostname, Wi-Fi SSIDs, interface
and custom route-table names, local names and search domains found in text,
filesystem paths, URL hosts, paths, queries and userinfo, credential-bearing
headers and values, private-key blocks, and certificate names found in derived
text. The machine's own hostname and account name are pseudonymized too. Those
two are in no field of the format and have no shape a pattern could match, so
they are read from the system and registered before the snapshot is walked;
a machine answering to both `buildbox.corp` and `buildbox` gets one alias for
the two, and a name that identifies a role rather than a person or a machine
(`root`, `localhost`, `admin`) is left alone. It applies to check names, details, fixes, attempt errors, diagnosis and
finding summaries, counterfactual values, captive-portal URLs, and every
snapshot nested in an incident. Passwords, bearer or basic credentials,
cookies, proxy credentials, tokens, and private keys are replaced rather than
copied.

Pseudonyms are assigned in stable traversal order within one artifact. The same
hostname, SSID, interface, route table, path, address, or prefix therefore gets
the same alias everywhere in that file, including incident before, during, and
recovered states. Different originals get different aliases. No original-to-
alias map, salt, key, or reversible secret is stored, and aliases are not meant
to be stable across separately created support files.

IP addresses follow an explicit policy:

- Public second-opinion DNS resolver addresses remain exact because resolver
  choice is diagnostic evidence and does not identify the local endpoint.
- All other IPv4 and IPv6 addresses are replaced with valid reserved
  pseudonyms. Separate ranges preserve whether an original was loopback,
  link-local, private, multicast, or public. Equality is preserved, so a
  gateway that is also a resolver or an address repeated across DNS, attempts,
  routes, and incident states still compares as one host.
- Route prefixes receive distinct repeatable pseudonyms. Default routes remain
  `0.0.0.0/0` or `::/0`. Prefix lengths of at least `/16` for IPv4 and `/48`
  for IPv6 are retained; broader prefixes are narrowed to those bounds so
  distinct aliases do not collapse.
- Ports, address-family results, route selection reasons, tunnel state and
  device kind, MTU, metrics, and whether routes or paths agree remain intact.
- A field the format declares as an address that does not hold one is written
  as `<address-redacted>` rather than passed to the text pass. The text pass
  keeps what it does not recognize, which is right for a sentence and wrong for
  a field that should have held an address.

The sanitizer constructs a new snapshot field by field. New schema fields are
therefore omitted from support output until they are deliberately classified,
rather than inheriting full-fidelity behavior by accident. Ordinary `--save`
artifacts and live output are not changed.

That classification is enforced rather than remembered. A test walks the schema
by reflection, puts a distinct sentinel in every string it declares, sanitizes,
and fails on any sentinel that survives serialization without being listed in
one of two sets: the fields kept verbatim because they are a closed vocabulary,
a build fact, or a timestamp, and the fields that hold a human sentence and are
rewritten by pattern. A field added to the format later belongs to neither set,
so it fails the test until somebody decides which it is.

To see that a file was prepared for sharing, read its `redaction` object, or
hand it to `--compare`, which names each side as `full` or `sanitized`:

```sh
jq .redaction support.ndoc
netdoc --compare support.ndoc support.ndoc
```

Support snapshots intentionally retain exact capture times, Network Doctor
version, operating system and architecture, selected probe IDs, ports,
durations, statuses, causes, findings, and the broad network relationships
above. They remain loadable and comparable like normal `.ndoc` files. The file
is readable JSON, so inspect it with `less`, an editor, or `jq` before sharing
when working in a particularly sensitive environment. Free-form probe errors
can originate in operating-system and network libraries; `support-v1` covers
known identifiers plus credential, URL, path, address, hostname, and
certificate patterns, but cannot assign meaning to an arbitrary opaque string
that carries no identifying syntax.

## Comparing two snapshots

`--compare` reads two saved snapshots and reports what changed between them. The two files are arguments, the earlier or known-good run first:

```sh
netdoc --compare good.ndoc bad.ndoc         # the table
netdoc --compare --json good.ndoc bad.ndoc  # the same comparison, machine-readable
```

It runs no probes and opens no socket. Everything reported comes out of the two artifacts, so a comparison works long after the fact and on a machine that has never seen either network. It is headless, needs no terminal, and cannot be combined with any flag that describes a run netdoc would perform (`--toolbox`, `--watch`, `--save`, `--support`, `--check`, `--skip`, `--no-reference-egress`, `--iface`, `--public-dns`, `--no-history`, `--keys`, `--timeout`, and either peer flag). Those settings are already recorded in the files.

Exit `0` means the two snapshots describe the same diagnostic state, `1` means they differ, and `2` means an argument or an artifact was unusable. A snapshot that records a failed run is not itself an error here: the question `--compare` answers is whether anything moved, not whether the network is healthy.

### What counts as a difference

The comparison is semantic, not a JSON diff. Every field it reads is named in the implementation on purpose, which is what lets it ignore the parts of a snapshot that change on their own, and what decides which collections are ordered:

| Compared | How |
| --- | --- |
| Target | `host`, `ip`, `port`, `protocol`, and `port_explicit`, then `raw` on its own, so "the same host, entered differently" and "a different host" are separate answers |
| Tool | `version`, `os`, and `arch`, because a diagnosis and its advice are chosen per platform |
| Run settings | the probe timeout, the second-opinion resolver, the `--iface` binding, and the `--check`/`--skip` selection as **sets** |
| Diagnosis | `ok`, `verdict`, `blamed`, `failed_stage`, the findings as a **set** keyed by `id`, the first finding as the primary conclusion, and each finding's ordered `evidence` and `causal_evidence` |
| Checks | membership, `status`, `cause`, `ran`, and `deps` in order |
| Reasoning | `derived.status_downgraded`, so an inferred outcome and a measured one are not read as the same state, and `derived.answer_comparison`, so two runs whose resolvers went from agreeing to disagreeing are not read as the same state either |
| Evidence | everything under `observed`: resolved addresses, resolver targets tried, and connection attempts as **sets**, and the selected address, source address, interface, SSID, second-opinion resolver, per-family reachability, captive-portal state, and timeout flags as values |
| Routes | `observed.routes` keyed by destination address, so a destination present on one side only is reported as such rather than as a changed path; then that entry's matched prefix, interface, next hop, source, metric, table, tunnel state and kind, selection reason, interface MTU, and competing routes |
| Paths | the derived reading of those routes: the target's interface, matched route, selection reason and tunnel state, the general Internet interface, every resolver target interface, and whether all DNS and application paths agree |

The paths section is derived from the routes both snapshots already carry rather than stored a second time, so the two can never describe different runs, and two files written by different netdoc versions are read the same way. It answers the question a person asks first, in normalized words rather than an operating system's route syntax:

```text
target interface changed from wlan0 to wg0
target matched route changed from 0.0.0.0/0 to 10.20.0.0/16
target route selection changed from same_path_as_default to differs_from_default_path
target tunnel state changed from direct to tunnel
DNS and application traffic changed from same path to different paths
```

The matched route is reported only where both snapshots recorded one, which on Linux is neither of them. The line above it carries the same news there, in the weaker words that platform can support: a destination that stops taking the way out general traffic takes is a changed selection whether or not the entry behind it can be named.

A split between DNS and application traffic is reported as a difference and nothing more. Split DNS is a design as often as it is a fault, and the comparison says what moved, never whose fault it is.

Absence is never collapsed into a zero. `SKIP`, `N/A`, and `INCOMPLETE` stay three different things that happened to a row. A resolver that answered with no records is not the same as one that did not answer. A captive portal that advertised no sign-in URL is not the same as no portal, so interception is its own field rather than something inferred from an empty URL. A second opinion switched off with `--public-dns ""` is reported as a removal, not as a change to nothing.

### What is intentionally ignored

These change between two runs of a machine that did not change, so treating them as differences would bury the ones that matter:

- `created_at`, the capture time. It is shown in the header of the report as context, and is never a difference.
- `duration_ms` on a check and on a connection attempt. Both are the measurement itself.
- `detail` and `fix` on a check, `summary` on the diagnosis and on a finding. All four are derived sentences that quote measurements ("in 41ms"), and the format documents them as never parsed back. `status` and `cause` are the machine-readable form of what they say, and those are compared.
- `name` on a check, which is display text built from the probe and the target.
- The order of resolved addresses, connection attempts, findings, and the `--check`/`--skip` selection. Order there is the resolver's, the dialer's, or the order you typed, and it is not the shape of anything. Order **is** kept where it carries meaning: a check's `deps`, a finding's `evidence`, and its `causal_evidence` are compared as ordered lists.
- Sub-second movement in `clock_offset_ms`. The offset is compared at whole-second resolution, which keeps the sign and the magnitude the diagnosis reasons about and drops the jitter of a clock that is fine.

An optional field added to a future snapshot version is not compared until it is named here, which is deliberate: a new field cannot start producing differences on its own.

### Ordering and determinism

The same two files always produce the same bytes and the same text. Nothing is sorted after the fact and no map decides what gets printed: differences come out in section order (target, tool, run settings, diagnosis, checks), and within the check section in the order the later run executed its probes, followed by any check only the earlier run had, in that run's order. Set membership is the one thing sorted, so that a resolver's answer order cannot reach the output.

### Version compatibility

Both files go through the same decoder every other reader uses, so the schema rule is stated once. A file whose `schema` is not the one this build reads, including a future version, is refused by name with exit `2` rather than half understood, and so is a file that is not JSON or that holds a check row with no `status`. There is one schema version today, so there is no cross-version comparison to perform; when there is one, it will be the decoder's migration, not a second copy of the rules inside `--compare`.

### Different targets

Comparing snapshots of two different endpoints is allowed. A snapshot keeps the typed spelling next to the parsed host precisely so a comparison can tell "the same host, entered differently" from "a different host", and refusing the second case would throw away an answer it is equipped to give. It is not allowed to be quiet about it: when the two runs did not observe the same endpoint, the report says so above the table, because every row underneath then describes two different things. The machine-readable form carries the same fact as `same_target`. A generic run against a targeted one is reported as one change rather than as a field-by-field list of a target only one side ever had.

### Interpretation

The report states direct facts about the two readings and stops there. "The DNS resolver changed from X to Y", "the DNS check changed from PASS to FAIL", "traffic used wg0 instead of wlan0" are all statements about what the files say. `--compare` does not claim that one of them caused another. A status move between `PASS`, `WARN`, and `FAIL` is marked `better` or `worse`, which is a comparison of two outcomes and not a cause; `SKIP`, `N/A`, and `INCOMPLETE` have no rank, so a move to or from one of them carries no direction rather than a guessed one.

### Machine-readable comparison

`--json` prints the comparison as its own versioned document, separate from the snapshot schema it reads because scripts consume it:

```json
{
  "schema": "netdoc.comparison.v1",
  "before": {"created_at": "2026-03-04T05:06:07Z", "tool": {"version": "1.2.3", "os": "linux", "arch": "amd64"},
             "target": "github.com:443 tls+http", "verdict": "ok", "summary": "…", "ok": true},
  "after":  {"created_at": "2026-03-04T18:22:41Z", "tool": {"version": "1.2.3", "os": "linux", "arch": "amd64"},
             "target": "github.com:443 tls+http", "verdict": "dns", "summary": "…", "ok": false},
  "same_target": true,
  "checks": [
    {"id": "iface", "before": "PASS", "after": "PASS", "kind": "unchanged", "differs": true},
    {"id": "dns", "before": "PASS", "after": "FAIL", "kind": "changed", "direction": "worse", "differs": true}
  ],
  "changes": [
    {"section": "diagnosis", "path": "diagnosis.verdict", "label": "verdict", "kind": "changed",
     "before": "ok", "after": "dns", "summary": "verdict changed from ok to dns"},
    {"section": "check", "check": "iface", "path": "checks.iface.observed.interface",
     "label": "iface interface", "kind": "changed", "before": "wlan0", "after": "wg0",
     "summary": "iface interface changed from wlan0 to wg0"}
  ]
}
```

`path` is a difference's stable identity, spelled as the field path inside the snapshot, so two runs name the same difference the same way and a script can key on it. `kind` is `added`, `removed`, or `changed`, and it is what says whether an empty `before` or `after` is an absent value: an `added` change always has an empty `before` and a non-empty `after`, and `changed` has neither empty. Both keys are always present, so an empty string is a value rather than a key a reader has to interpret.

`checks` is every check in either snapshot, unchanged rows included, so the same document answers "what stayed the same". Its `kind` is about the status alone, while `differs` is true whenever anything about that check moved, including evidence underneath a status that held. `direction` is `better` or `worse` where the outcomes have an ordering, and absent otherwise.

A side carries `"sanitized": true` when that artifact was written by `--support`, read from the file's own [redaction metadata](#support-snapshots) rather than guessed from values that look like placeholders. The key is absent on a full-fidelity snapshot. The text report grows a `Fidelity` row saying `full` or `sanitized` for each side, but only when one of them is: on two ordinary snapshots it would say the same word twice on every comparison anybody ever runs. Comparing two support artifacts is meaningful, and comparing a support artifact against a full-fidelity one is not: the same host is a hostname on one side and a pseudonym on the other, so every value differs.

An empty `changes` array is the machine-readable form of "no meaningful differences", and it is what exit `0` means.

### What a comparison cannot tell you yet

A snapshot holds only what the run gathered, so a comparison can only report what is in there. Today that leaves some questions unanswerable from two `.ndoc` files:

- **Answer provenance.** The snapshot records each resolver target Go tried (`observed.resolver_targets`), but the resolver API does not reveal which target returned a response or supplied a particular A or AAAA address, nor whether any of them did: where the host resolves `hosts: dns files`, an answer that no server supplied can still follow a query. A single recorded target is therefore an attempt like any other. The second-opinion row is the one place this had to be settled rather than recorded, because a `dns_public` answer is spent as proof that an independent resolver resolved the name: that row resolves the name a second time with every DNS dial refused, and reports N/A instead of an answer whenever the machine can answer without DNS. So `dns_public` addresses are the public resolver's, while `dns` addresses are whatever this machine resolves the name to, from whichever source.
- **Routes.** No route or default-route state is captured, so a route change is visible only through its effects: the source address, the selected interface, and the reachability rows.
- **The proxy.** The proxy host and port appear in the proxy row's `detail`, which is derived text and not compared. A proxy change registers as that row's status or `cause` moving, not as the proxy itself.
- **Path MTU.** The path-MTU row records its outcome, not a measured MTU number, so there is no MTU value to compare.
- **VPN and tunnel state as such.** There is no tunnel field; a VPN shows up as the interface name and source address on the rows that observed them, which is usually enough to see it, and never enough to name it.

Adding fields to the snapshot for the sake of a fuller comparison is deliberately not done here. Each one is a change to a published format, and a comparison is worth more trustworthy than complete.

## Two-sided diagnosis

`--two-sided` asks which vantage point a failure is specific to, rather than what changed between two runs. It has two ways to obtain the same pair of canonical snapshots.

The live form starts the same ordinary diagnosis on this machine and an SSH-accessible machine, as close together in time as practical, then applies the existing two-sided reading:

```sh
netdoc --two-sided --via other-host github.com
netdoc --two-sided --via other-host --json github.com
netdoc --two-sided --via other-host                    # two generic diagnoses
```

Side A is always the local run. Side B is always the `--via` run. Human output labels them `LOCAL (SIDE A)` and with the sanitized SSH destination as side B. Labels are presentation metadata and never affect localization.

The artifact form remains unchanged:

```sh
netdoc --save here.ndoc github.com                     # this machine
netdoc --via other-host --save there.ndoc github.com   # the other machine
netdoc --two-sided here.ndoc there.ndoc                # where is it broken?
```

The two files are arguments, this machine's run first. This form runs no probes and opens no socket: both machines already did their probing, and this is the reading of what they recorded. The second file can come from anywhere a snapshot comes from, whether that is `--via` over SSH or a run somebody did by hand and sent you, so the reading works even when the other machine is one you cannot log in to.

Live acquisition does not introduce another report or reasoning model. The local run builds its ordinary report and `netdoc.snapshot.v1` artifact through the normal path. The remote worker returns the same two canonical artifacts over remote protocol version 1. Network Doctor passes those snapshots directly to `compare.TwoSidedSnapshots`; it never parses rendered prose. The two runs start concurrently so changing network conditions have less time to weaken the differential. They retain independent probe dependency graphs and bounded timeouts.

Exit `0` means no comparable check failed on either machine, `1` means a failure was placed or the evidence could not place one, and `2` means an argument or artifact was unusable, the effective targets differed, or live remote acquisition failed. A remote diagnostic `FAIL` is a completed measurement and is localized normally; it is not confused with an SSH or protocol failure. Both forms are headless and need no terminal.

### Flags in live two-sided mode

The artifact form accepts only `--json` because every other run setting is already recorded in its two files. The live compatibility decisions below are enforced before either diagnosis starts:

| Flag | Live behavior |
|---|---|
| `--via HOST` | Required to select live acquisition. With two file arguments, it is rejected with an instruction to remove `--via` rather than guessed to be an artifact reading. |
| `--json` | Accepted. Emits the existing `netdoc.twosided.v1` document, not either ordinary report. |
| `--check`, `--skip` | Accepted. The same validated probe selection and dependency rules apply locally and remotely. |
| `--no-reference-egress` | Accepted. Both runs come from the same settings, so neither side contacts a built-in reference service. |
| `--timeout` | Accepted. The same positive per-probe timeout is sent to both runs. |
| `--public-dns` | Accepted. The same validated resolver IP, including an empty value that disables the row, applies to both runs. Left unset, each machine chooses its own automatic fallback family. |
| `--iface` | Rejected. One local interface name or source IP cannot honestly identify corresponding interfaces on two different machines. Use two separately saved snapshots when each side needs its own binding. |
| `--profile` | Rejected. A profile is a multi-target plan, while two-sided localization requires one equivalent target per vantage point. |
| `--save`, `--support` | Rejected. Each names one output path and neither can represent the two input snapshots without inventing a new artifact contract. Save or sanitize two ordinary runs separately and use the artifact form instead. |
| `--watch` | Rejected. Watch is a repeated session, not one matched pair of completed runs. |
| `--compare` | Rejected. Comparison asks what changed between saved states; two-sided diagnosis asks where a same-target differential appears. |
| `--peer-listen`, `--peer-connect` | Rejected. Peer mode measures direct authenticated traffic between Network Doctor endpoints, not their independent paths to an external target. |
| `--toolbox`, `--no-history`, `--keys` | Rejected. They belong to the interactive TUI and have no meaning in this headless orchestration path. |

`--help` and `--version` retain their normal immediate behavior. A user interrupt cancels both acquisitions and exits `1`. A remote SSH, worker, or protocol error cancels the local run, emits no two-sided result, and exits `2`; cancelling the SSH process also closes the worker channel so remote probes do not continue unnecessarily.

### Why it is a separate command from `--compare`

The two readings draw opposite conclusions from the same row moving. A check that is `PASS` in one file and `FAIL` in the other is a change over time to a comparison and a difference between two vantage points to a localization, and a reader has to have said which they meant. `--compare` deliberately never claims that one reading caused another; `--two-sided` exists to say which side the evidence puts a failure on, which is a claim, so the two are separate commands with separate schemas and separate exit-code meanings.

There is one rule `--two-sided` has that `--compare` does not: **two snapshots of different targets are refused with exit `2`.** A comparison of two endpoints is a question with an answer, and a localization across two endpoints is not, because a row that failed against one host and passed against another says nothing about which machine is at fault. Two generic runs with no target are one question asked from two places, so those are read.

[Support artifacts](#support-snapshots) follow from that rule rather than needing one of their own. Sanitization renames the target, and it assigns the same pseudonym to the same endpoint on both machines, so two `--support` artifacts of one target read normally and a sanitized file paired with a full-fidelity one is refused as two different targets. That is the right outcome either way: the pair whose names line up is the pair whose rows can be set against each other.

### What it reads, and what it refuses to read

Only rows **both machines measured** are read. `PASS`, `WARN`, and `FAIL` are measured outcomes; `SKIP`, `N/A`, and `INCOMPLETE` are three different reasons nothing was measured, and none of them is evidence about a machine. A check present in only one file is not comparable either. Every unread row is marked `comparable: false` and counted in the caveats, so a reading never quietly rests on a row that was not there.

`WARN` is a row that worked, the same reading the snapshot's own `ok` field and netdoc's exit code take. A warned row is not a failure to place.

### Placements

| ID | `side` | What the evidence proves |
|----|--------|--------------------------|
| `two_sided_no_failure` | `none` | no check that both machines measured failed on either of them |
| `two_sided_one_side_fails` | `a` or `b` | every failed check passes from the other machine, so the failure is specific to that machine's vantage point |
| `two_sided_one_side_fails_more` | `a` or `b` | some checks fail from both machines and one fails others besides, so at least one failure is specific to that machine |
| `two_sided_shared_failure` | `shared` | every failed check fails from both machines, which places it on neither one in particular |
| `two_sided_divergent_failures` | `both` | each machine fails checks the other passes, which is two findings rather than one failure to place |
| `two_sided_no_comparable_checks` | `unknown` | no check produced a measured outcome on both machines |

### What a placement does and does not prove

"Specific to side A's vantage point" is the strongest claim two snapshots support, and it is narrower than it sounds. Side A's own network state, side A's path, and an endpoint that treats the two machines differently all produce exactly this evidence, so all of them are listed as alternatives and none is chosen. Every placement except an unqualified pass carries `ambiguous: true`.

It never claims a firewall, router, NAT, VPN, or host is responsible. Two snapshots cannot establish that: they record what each machine observed, not what any device in between did. A `--two-sided` reading is a statement about **which machine**, never about **which box**.

It also cannot see anything the snapshots do not carry, which is the same list as [what a comparison cannot tell you yet](#what-a-comparison-cannot-tell-you-yet).

### Caveats

Conditions that weaken the reading are reported as caveats rather than left for the reader to notice. They are prose for a person and are not parsed back:

- **A gap between the two captures.** Anything that changed in between is inside the evidence. Runs started together produce no caveat; the gap is reported from a minute upward, in minutes, hours, or days.
- **Settings the two runs did not share.** Different probe timeouts (a timed-out row may be a shorter budget rather than a slower path), different second-opinion resolvers (the public DNS row asked two different questions), or a different `--check`/`--skip` selection. The selection is compared as a set, so a reordering is not a caveat.
- **Rows only one side measured**, counted.
- **Mixed fidelity**, when one side is a sanitized `--support` artifact and the other is full fidelity, because the names and addresses are then not comparable. This arises only for two generic runs: on a targeted run, sanitization renames the target itself, so the pair fails the same-target rule above and is refused before any row is read.

Two machines is the premise, so a different operating system, architecture, or netdoc build on the other side is the expected case and is never a caveat.

### How it relates to peer mode and `--via`

Two machines produce six kinds of observation. netdoc gathers them with commands that do not overlap, and then reads two of the groups together:

| Observation | Where it comes from |
|---|---|
| this machine's own network state, and this machine to the target | an ordinary local run |
| the other machine's own network state, and the other machine to the target | the same ordinary run over there, with `--via` as the transport from here |
| this machine to the other machine, and the other machine back | [peer mode](#peer-diagnosis) |

| Reading | Command |
|---|---|
| what changed between saved states, usually on one machine at different times | `--compare A.ndoc B.ndoc` |
| where a failure against the target is, given the first two observation rows | `--two-sided A.ndoc B.ndoc`, or acquire both live with `--two-sided --via HOST` |
| whether the path between the two machines fails in one direction or both | peer mode's own combined diagnosis |

Peer mode and `--two-sided` answer different halves of "is the failure on this machine, on the other machine, or between them". Peer mode measures the path **between the two machines** directly, with live authenticated traffic in both directions, and is the only one of the three that can prove directional asymmetry. `--two-sided` reads two finished ordinary diagnoses and places a failure **against a target** on one vantage point or the other. Live two-sided acquisition happens over SSH, but SSH is only the control transport and contributes no peer-mode observation. Neither mode reads the other's output, and neither is a substitute for it: peer mode makes no claim about an external target, and `--two-sided` makes no claim about the direct path between the Network Doctor endpoints.

Offline `--two-sided A.ndoc B.ndoc` needs no reachability and opens no connection. Live `--two-sided --via HOST` needs the same one-way SSH access as ordinary `--via`, but no pairing string, reverse listener, relay, or direct peer reachability. Peer mode needs direct peer reachability because that path is exactly what it measures.

### Machine-readable two-sided reading

`--json` prints the reading as its own versioned document, separate from the snapshot and comparison schemas because scripts consume it:

```json
{
  "schema": "netdoc.twosided.v1",
  "a": {"created_at": "2026-03-04T05:06:07Z", "tool": {"version": "1.2.3", "os": "linux", "arch": "amd64"},
        "target": "github.com:443 tls+http", "verdict": "service", "summary": "…", "ok": false},
  "b": {"created_at": "2026-03-04T05:06:09Z", "tool": {"version": "1.2.3", "os": "windows", "arch": "amd64"},
        "target": "github.com:443 tls+http", "verdict": "ok", "summary": "…", "ok": true},
  "same_target": true,
  "checks": [
    {"id": "iface", "a": "PASS", "b": "PASS", "comparable": true},
    {"id": "target_tcp", "a": "FAIL", "b": "PASS", "comparable": true},
    {"id": "ssid", "a": "N/A", "b": "N/A", "comparable": false}
  ],
  "caveats": ["1 check did not produce a measured outcome on both machines and was not read."],
  "diagnosis": {
    "id": "two_sided_one_side_fails",
    "side": "a",
    "summary": "Every failed check passes from side B, so the failure is specific to side A's vantage point rather than to the endpoint alone.",
    "evidence": ["target_tcp"],
    "ambiguous": true,
    "alternatives": ["side A's own network state", "side A's path to the endpoint",
                     "the endpoint treating the two machines differently, by address or by policy",
                     "the endpoint or the path changing between the two runs"]
  }
}
```

`checks` is every check in either snapshot, in the order side A executed them, followed by the ones only side B had. `comparable` is what says whether the placement was allowed to read the row. Field names, the `side` and ID vocabularies, and the meaning of the exit code are stable for this schema. `caveats` and `summary` are derived sentences and are never parsed back; branch on `diagnosis.id`, `diagnosis.side`, and `diagnosis.evidence`. `same_target` is always `true` in a document that exists at all, since the other case is refused, and it is carried so the document is self-describing.

Live acquisition emits this exact schema. It does not add ordinary diagnosis confidence: two-sided epistemic limits remain represented by `diagnosis.ambiguous`, `alternatives`, and `caveats`, so this orchestration feature requires no schema version change.

## Remote diagnosis over SSH

`--via <ssh-destination>` performs the diagnosis on another machine and presents it here:

```sh
netdoc --via server example.com
netdoc --via server --json --check dns,target_tcp example.com
netdoc --via server --save remote.ndoc example.com
netdoc --two-sided --via server example.com
```

It is remote *execution*, not remote monitoring: one connection and one answer
for an ordinary target run. A profile uses one such connection per component
and aggregates the completed answers. Live two-sided diagnosis pairs one such
remote run with one concurrently started local ordinary run, then reads their
canonical snapshots locally. There is no daemon, no agent, no installation
step, and no persistent state on either machine.

### How it runs

The local netdoc starts the system `ssh` client with a fixed argument list:

```text
ssh -T <destination> netdoc --remote-worker
```

No local shell is involved: `ssh` is executed directly with those arguments as separate `argv` elements, never as a command string. The destination is passed through exactly as typed, so `~/.ssh/config` aliases, `user@host`, `ssh://` URLs, ports, `IdentityFile`, `ProxyJump`, and agent authentication behave the way they do for a direct `ssh` invocation. netdoc reads no SSH configuration itself and reimplements none of it. Password, passphrase, and host-key prompts still reach your terminal, because `ssh` reads those from the terminal rather than from the pipe the protocol uses.

`--remote-worker` puts the far end in worker mode. It is not a flag: it is recognized before any flag parsing, accepts nothing alongside it, and appears in no help output, because it is one netdoc talking to another. That is also what keeps the remote command line a fixed string: the target, the timeout, the probe selection, and every other setting travel as structured data on standard input, so no user text is ever spelled into a command a remote shell will read. The same invocation is therefore correct whether the SSH host's default shell is POSIX `sh`, `cmd.exe`, or PowerShell.

The `-T` is deliberate. The exchange is a byte protocol on a pipe, and a pseudo-terminal would be free to translate line endings inside it.

### The remote protocol

One JSON request in, one JSON response out, over the SSH session's standard input and output.

The request carries the run settings as the user spelled them: target, `--iface`, `--public-dns`, `--timeout`, `--check`, and `--skip`. Nothing is pre-resolved locally, because the machine that will run the probes is the one that has to resolve it. The one exception is `--no-reference-egress`, which is resolved here into the probe IDs it removes and travels inside `skip`. That is deliberate: skip has been honored since protocol 1, whereas a new request field would be ignored by any remote netdoc old enough not to know it, and a safety guarantee that a mismatched pair silently drops is worse than no flag at all. `--iface` is the clearest case for an ordinary remote run: it names an interface on the SSH host, so the local machine has no business resolving it against its own NICs. Live two-sided mode reuses this protocol unchanged for its remote half, but rejects `--iface` because the same spelling cannot also select a corresponding local interface honestly.

The response carries the two artifacts netdoc already publishes, built on the far end by the ordinary code paths:

- the `--json` report, exactly as that machine would print it, and
- the `.ndoc` snapshot, stamped with that machine's build, operating system, and architecture.

Both are versioned external contracts in their own right, which is why the SSH protocol does not define a third schema over the probe structs. The envelope adds only what neither artifact says: which protocol version is being spoken, which build answered, and whether the remote could run the request at all.

The diagnosis is reached on the machine that probed, and never recomputed locally. This matters: the remediation for a finding is chosen by operating system, so a Windows host's advice is not a Linux client's to rewrite. The local side transports, presents, and decides the exit code, which is what a local run does with its own results.

The envelope's `protocol` and `error` fields are fixed for all time, at every version. A netdoc that cannot speak the version it was handed still has to be able to say so in a way the version that asked understands, and that is only true if those two keys never move. The version itself moves for a change an existing peer would misread; adding an optional field is not that, and neither side rejects unknown keys.

### Standard output is the protocol

On the SSH host, worker-mode standard output carries one JSON object and nothing else: no banners, no progress, no logs, no terminal formatting, no human-readable text of any kind. Anything meant for a person goes to standard error, where `ssh` delivers it to the caller.

Locally, the same discipline holds in the other direction. The provenance line naming the SSH host and the remote build goes to standard error, so `netdoc --via server --json host` leaves standard output byte-for-byte the report a local `--json` run leaves in a pipe. Live `--two-sided --json` instead writes only the existing `netdoc.twosided.v1` result assembled after both ordinary artifacts are complete.

### Exit codes

The exit code is netdoc's, not `ssh`'s. A completed protocol exchange is a transport success, whatever the diagnosis concluded, and the worker exits `0` even when every check failed. The local side then applies the ordinary contract:

| Situation | Exit |
|---|---|
| The remote run completed with no failed row | `0` |
| The remote run had a failed row | `1` |
| The local run was interrupted before the answer arrived | `1` |
| `ssh` could not open the connection | `2` |
| No usable `netdoc` ran on the SSH host | `2` |
| The two ends do not speak the same remote protocol | `2` |
| The remote refused the request (a rejected target, an unknown probe ID) | `2` |

The separation is the point. "The network you asked about is broken" and "I could not reach the machine to ask" are opposite conclusions, and a script must never confuse them. Each `2` says which one it was and quotes what the remote itself said.

### The remote executable

The SSH host must already have a `netdoc` on the `PATH` of a non-interactive SSH session, new enough to know worker mode. netdoc does not install it, copy it, or modify anything on the far end.

`NETDOC_VIA_COMMAND` overrides the program to start. It is read on the local machine, never sent anywhere, and is for an installation that is not on that `PATH`, which is common enough on Windows and on macOS under a non-login shell. The value must be a plain path: letters, digits, and `. _ - / \ : + @ ~`, with no whitespace and no shell punctuation. That restriction is what lets one value mean the same thing to every remote shell, and a path containing a space is refused rather than guessed at.

When the remote produces no usable response, the error names the likely causes and quotes the remote's own standard error, which is what distinguishes a missing executable from one too old to know the flag:

```text
netdoc: -via: server: netdoc did not run on the SSH host (ssh exited 2)
  flag provided but not defined: -remote-worker
  run 'netdoc --help' for usage
Install netdoc on the SSH host and make sure it is on the PATH of a
non-interactive SSH session, or set NETDOC_VIA_COMMAND to its full path.
The netdoc there also has to be new enough to know --remote-worker.
```

### Cancellation

Interrupting a `--via` run terminates the local `ssh` process, which drops the channel, which closes the worker's standard input on the far end. The worker treats the end of that stream as the caller having gone away and cancels the running probes, so a cancelled run does not leave a diagnosis finishing on a machine nobody is listening to. The local process exits `1`, the code quitting before the chain finished already spends.

Live two-sided diagnosis gives the local and remote acquisitions one cancellation context. An interrupt stops both. A remote transport or protocol failure also stops the local probe set and exits `2` without producing a localization. A completed remote report containing `FAIL` rows is evidence, not a transport failure, so it remains available to the two-sided engine.

### What crosses the wire, and what does not

The request holds only the run settings, all of which the user typed. The response holds the report and the snapshot, which is the same information a local run would leave on this machine anyway. Nothing else is collected, and no file on either machine is read on the strength of a path the other end supplied.

`--support` sanitization runs locally, on the snapshot that came back. That is deliberate: which artifact is safe to share is a decision about what leaves *your* machine, and it is the same decision, applied the same way, as for a local run. As locally, only the file is sanitized; a combined `--json` run still prints the full-fidelity report.

Both ends bound what they will read from the other, and neither trusts the other's text: a response is one JSON object within a size cap, anything after it is a protocol violation, and every string that reaches a terminal is stripped of escape sequences and control characters first.

### Limits

- One connection per ordinary run and per profile component. Live two-sided
  diagnosis uses one connection for its remote half. `--watch` is not
  combinable with `--via`, because a watch that reconnected on every pass is a
  different feature.
- There is no live progress. The probes run on the far end and the answer arrives when the run is finished, which is why `--via` is headless rather than a remote terminal UI.
- The probe IDs given to `--check` and `--skip` are validated locally as well as remotely, so a probe ID that exists only on a newer remote netdoc is rejected before the connection opens.
- The drill-down tools, the LAN map, and the SSH login form are terminal UI features and are not part of a remote run.
