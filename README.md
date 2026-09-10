# Network Doctor

[![CI](https://github.com/heymaikol/network-doctor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/heymaikol/network-doctor/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/heymaikol/network-doctor)](https://github.com/heymaikol/network-doctor/releases/latest)
[![License: Apache-2.0](https://img.shields.io/github/license/heymaikol/network-doctor)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-heymaikol.github.io-1f6feb)](https://heymaikol.github.io/network-doctor/)

**Find the layer where your connection breaks.** Network Doctor is a
cross-platform network troubleshooting TUI that turns interface, DNS, TCP,
TLS, HTTP, proxy, and path-MTU checks into one plain-English diagnosis.

![Network Doctor diagnosing an office printer hostname that will not resolve: the DNS row fails, every check that depended on it is skipped, and the verdict names the missing DNS record as the fix](assets/hero.gif)

Instead of handing you a wall of `ping`, `dig`, and `curl` output, Network
Doctor answers the useful question: **is the problem on my network, along the
path, or at the service?**

## Why Network Doctor

- **Isolates the failing layer.** Independent probes distinguish local-link,
  DNS, egress, target, TLS, HTTP, proxy, and path-MTU failures, and say so when
  the evidence stops short of naming one.
- **Explains what to do next.** Results include evidence and targeted fix hints,
  with familiar drill-down tools one keypress away.
- **Needs no root access.** Even the path-MTU check and LAN map use unprivileged
  sockets and bounded probes.
- **Works interactively or in automation.** Use the TUI for live investigation,
  `--watch` for intermittent faults, or stable JSON and exit codes in scripts.
- **Runs everywhere.** The same diagnosis engine supports Linux, macOS, and
  Windows, with native packages and prebuilt binaries.

If Network Doctor saves you time, you can [support its development on GitHub Sponsors](https://github.com/sponsors/heymaikol).

## Install

Runs on **Linux, macOS, and Windows**. Project = `network-doctor`; installed binary = `netdoc`.

### Windows

Scoop, from own bucket:

```powershell
scoop bucket add heymaikol https://github.com/heymaikol/scoop-bucket
scoop install network-doctor
```

A release reaches the bucket as soon as it publishes, so `scoop update network-doctor` picks it up like any other app.

### macOS and Linux (Homebrew)

```sh
brew install network-doctor
```

The Homebrew Core formula, bottled for both platforms, so `brew upgrade` picks up releases like any other formula. It installs `netdoc` alone; for `netdoc-sim` too, take a [Linux package](#linux).

### Linux

Every Linux package installs two commands at the same version: `netdoc`, and
`netdoc-sim`, the simulator behind [Challenge Mode](#challenge-mode).

#### Fedora

**Fedora stable uses the prebuilt release RPM**, downloaded from the [latest
release](https://github.com/heymaikol/network-doctor/releases/latest). It is
prebuilt, so the Go-version limitation that prevents COPR source builds on
Fedora 43, 44, and 45 does not apply:

```sh
sudo dnf install ./network-doctor_X.Y.Z_linux_ARCH.rpm    # ARCH is amd64 or arm64
```

**Fedora Rawhide uses the COPR repository**, which builds from source and
publishes for Rawhide on `x86_64` and `aarch64` alone:

```sh
sudo dnf copr enable heymaikol/network-doctor
sudo dnf install network-doctor
```

#### Other distributions

Take a prebuilt `.deb`, `.rpm`, or `.apk` from the
[latest release](https://github.com/heymaikol/network-doctor/releases/latest),
for `amd64` and `arm64`:

```sh
sudo apt install ./network-doctor_X.Y.Z_linux_amd64.deb    # Debian, Ubuntu, Mint
sudo dnf install ./network-doctor_X.Y.Z_linux_amd64.rpm    # RHEL, Rocky, Alma
sudo apk add --allow-untrusted ./network-doctor_X.Y.Z_linux_amd64.apk    # Alpine
```

Downloaded packages are standalone, so `dnf`/`apt` will not pull the next
version for you; the COPR repository upgrades normally. Upgrade paths, trust
roots, and the `netdoc-sim` Linux-only rule are in
**[docs/installation.md](docs/installation.md#linux)**.

### Everywhere else

Grab a prebuilt binary from the [latest release](https://github.com/heymaikol/network-doctor/releases/latest) (Windows ships as a `.zip`, the rest as bare binaries), or install with Go 1.27+:

```sh
go install github.com/heymaikol/network-doctor/cmd/netdoc@latest
```

Check what you are running with `netdoc --version`. Releases carry a signed
attestation binding each artifact to the workflow run that built it; verifying
one is in
**[docs/installation.md](docs/installation.md#verify-your-download)**, along with
building from a clone.

## Quick start

```sh
netdoc                  # local interface, egress, proxy, public DNS, Wi-Fi
netdoc github.com       # DNS, TCP, TLS, HTTP diagnosis of one target
netdoc github.com:22    # the port selects the protocol rows (SSH banner)
netdoc --watch host     # catch intermittent failures
netdoc --json host      # structured report for scripts or bug reports
```

A finished run leads with the answer: the verdict, the fix, the tool worth
reaching for next, and the one line of evidence the verdict rests on, above the
checks that produced them. Select any other row for its own evidence and fix,
press `e` for the causal explanation, and `?` for every shortcut.

The recording above is one worked example: an office printer hostname that no
longer resolves. The DNS row fails, every check that depended on it is skipped
rather than guessed at, and the verdict names the missing DNS record instead of
blaming the printer.

## What it checks

Probes form a **dependency graph with independent branches**, so an unrelated
failure never hides a working one: direct egress, QUIC, proxy egress, public and
encrypted DNS, and the selected target path each run on their own, and the
unprivileged path-MTU check hangs off the connect.

| Branch | Rows |
|---|---|
| Local | Interface, Wi-Fi network |
| Egress | Internet (TCP egress), QUIC / UDP 443, Internet (env proxy) |
| Naming | DNS, DNS (public), DNS (encrypted DoH/DoT) |
| Target path | TCP, Path MTU, TLS, HTTP, HTTPS, SSH/SMTP banner |

Each row lands in one of five states, **✓ Pass**, **! Warn**, **✗ Fail**,
**⊘ Skip**, and **– N/A**; Warn never counts as a failure. The full probe table
with exact pass conditions, JSON causes, and the unprivileged path-MTU method is
in **[docs/reference.md](docs/reference.md#how-it-diagnoses)**.

## Capabilities

Each one gets a sentence here and a complete contract in the reference.

- **Service profiles.** `--profile github` composes ordinary runs into one
  service-specific check with a single aggregate verdict, and every component
  keeps its full report. Built-ins: `github`, `ssh`, `smtp`, `web`.
  [Plans and aggregate rules](docs/reference.md#service-profiles).
- **Watch Mode.** `--watch` re-runs continuously and keeps a bounded incident
  timeline around each intermittent failure, from the last working state to the
  recovery. Press `i` to inspect one, `w` to save it.
  [Incident reconstruction](docs/reference.md#usage-details).
- **Drill-down tools.** When a row is not proof enough, run the real tools as
  cancellable streaming jobs, several at once, sanitized before the output hits
  your terminal: route, socket, ping, DNS, curl, traceroute, mtr, and nmap are
  one keypress each, `v` maps the local private network, and `S` opens an SSH
  login. [Per-OS commands](docs/reference.md#drill-down-tools).
- **Structured output and exit codes.** `--json` prints one document with stable
  field names: `status` per row, and the `verdict` a script actually asks about
  (`ok`, `degraded`, `dns`, `network`, `service`, `incomplete`). Exit `0` passed,
  `1` failed or incomplete, `2` could not run.
  [Fields](docs/reference.md#json-output),
  [exit codes](docs/reference.md#exit-codes).
- **Diagnostic snapshots.** `--save` writes a finished run to a portable `.ndoc`
  for the failure you cannot reproduce on demand, `--support` writes it
  pseudonymized for sharing, and `--compare good.ndoc bad.ndoc` reports what
  changed between two saved runs without opening a socket.
  [Format](docs/reference.md#diagnostic-snapshots),
  [support policy](docs/reference.md#support-snapshots),
  [comparison](docs/reference.md#comparing-two-snapshots).
- **Remote and two-machine diagnosis.** `--via server host` runs the checks on
  another machine through your own `ssh` client, installing nothing on the far
  end. `--two-sided` asks why one target behaves differently from two vantage
  points and places the failure on the side where it is specific.
  `--peer-listen` and `--peer-connect` compare traffic observed at both ends of
  an authenticated, directly connected TLS 1.3 session, with no relay or
  account. [Remote](docs/reference.md#remote-diagnosis-over-ssh),
  [two-sided](docs/reference.md#two-sided-diagnosis),
  [peer](docs/reference.md#peer-diagnosis).
- **Narrowing a run.** `--list-checks` prints the stable probe IDs that `--check`
  and `--skip` accept, `--no-reference-egress` drops every check that would
  contact netdoc's own reference services, and `--iface` binds probe traffic to
  one interface or address. [Flag semantics](docs/reference.md#usage-details).

## Challenge Mode

Challenge Mode drops you into a deliberately broken network without telling you
what is wrong, then lets Network Doctor take a shot at the same problem, with
both graded against the simulator's independently observed ground truth. There
is a daily challenge, and everybody who plays that day gets the same network:

```sh
netdoc-sim challenge -daily          # today's, the same one for everybody
netdoc-sim challenge -id V4-8F42C1   # replay the one a friend sent you
```

Everything is local and reproducible: no account, no server, no leaderboard, and
a challenge id is the whole puzzle. The simulator builds its networks out of
Linux namespaces, so macOS and Windows run one container image instead:

```sh
docker run --rm -it --cap-add SYS_ADMIN ghcr.io/heymaikol/netdoc-sim:latest challenge -daily
```

The walkthrough is in the wiki's
[Challenge Mode](https://github.com/heymaikol/network-doctor/wiki/Challenge-Mode);
the scoring contract is in
**[docs/simulation-challenge.md](docs/simulation-challenge.md)** and the
simulator in **[docs/simulation.md](docs/simulation.md)**.

## Documentation

The **[wiki](https://github.com/heymaikol/network-doctor/wiki)** is the
user-facing hub for how to use `netdoc` and what a diagnosis means;
**[docs/reference.md](docs/reference.md)** is the full technical reference for
exact CLI semantics, keybindings, exit codes, and schemas. Both are published at
**[heymaikol.github.io/network-doctor](https://heymaikol.github.io/network-doctor/)**:

- [Getting Started](https://heymaikol.github.io/network-doctor/wiki/Getting-Started/): install, first run, and what the screen is showing you.
- [Understanding Your Diagnosis](https://heymaikol.github.io/network-doctor/wiki/Understanding-Your-Diagnosis/): turning a verdict into a next action, including telling "my network" and "their service" apart.
- [How Network Doctor Works](https://heymaikol.github.io/network-doctor/wiki/How-Network-Doctor-Works/): why the probe branches are independent, and how path MTU is measured without root.
- [Troubleshooting and FAQ](https://heymaikol.github.io/network-doctor/wiki/Troubleshooting-and-FAQ/): the rows that behave surprisingly, and the questions that come up most.
- [Reference](https://heymaikol.github.io/network-doctor/docs/reference/), [installation details](https://heymaikol.github.io/network-doctor/docs/installation/), and the [simulator guide](https://heymaikol.github.io/network-doctor/docs/simulation/): the same `docs/` files that live beside the code.

The site is built from `docs/` and the wiki, so each page is still edited exactly where it lives; nothing is duplicated to publish it.

## Contributing

Network Doctor actively welcomes external contributors, and many contributions
need no networking expertise. Useful work includes Go and Bubble Tea / TUI
development, Bash, Zsh, and Fish completions, CI / packaging / release tooling,
documentation, Linux / macOS / Windows testing, and real-network field testing.

- [Good first issues](https://github.com/heymaikol/network-doctor/issues?q=is:issue+is:open+label:%22good+first+issue%22)
- [Help wanted issues](https://github.com/heymaikol/network-doctor/issues?q=is:issue+is:open+label:%22help+wanted%22)

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, choosing a task, and opening a
pull request. An ordinary change runs `./scripts/check`; the complete gate and
what each layer of evidence proves are in
**[docs/validation.md](docs/validation.md)**. Please report suspected
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea),
[Bubbles](https://github.com/charmbracelet/bubbles), and
[Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Support

**Personal Network Diagnosis.** Still stuck after running Network Doctor? I
offer [a paid personal diagnosis](https://tally.so/r/KYK7Y7) for one networking
problem. Send a description, relevant context, and a sanitized report created
locally with `netdoc --support support.ndoc example.com`. I investigate the
evidence and send a written diagnosis of the likely cause, concrete steps to try
next, and one follow-up reply. The introductory price is **$25 USD as a one-time
payment, limited to the first 5 cases**. This is diagnostic assistance, not a
guarantee of repair. Network Doctor does not upload the file.

**GitHub Sponsors.** Network Doctor is free software maintained independently.
If it saves you time, you can
[sponsor its development](https://github.com/sponsors/heymaikol). Your support
helps fund the time spent on cross-platform testing, packaging, releases, and
ongoing maintenance. Sponsorship is optional and does not affect access to the
software or how issues are prioritized.

## License

Network Doctor is licensed under the [Apache License, Version 2.0](LICENSE). Package metadata declares this as `Apache-2.0`.

## Star History

<a href="https://www.star-history.com/?repos=heymaikol%2Fnetwork-doctor&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=heymaikol/network-doctor&type=date&theme=dark&legend=top-left&sealed_token=4XgBnUitKav8JRmYTBIst1x9bwnwAJEe_qDlPb20W2iSTPj_FG9cXicHok2d59GSb9QcFWynwWwexSj1vBNPTojS13SGdu0UUhNb9dx930Yaj-93UZ9oVw" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=heymaikol/network-doctor&type=date&legend=top-left&sealed_token=4XgBnUitKav8JRmYTBIst1x9bwnwAJEe_qDlPb20W2iSTPj_FG9cXicHok2d59GSb9QcFWynwWwexSj1vBNPTojS13SGdu0UUhNb9dx930Yaj-93UZ9oVw" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=heymaikol/network-doctor&type=date&legend=top-left&sealed_token=4XgBnUitKav8JRmYTBIst1x9bwnwAJEe_qDlPb20W2iSTPj_FG9cXicHok2d59GSb9QcFWynwWwexSj1vBNPTojS13SGdu0UUhNb9dx930Yaj-93UZ9oVw" />
 </picture>
</a>
