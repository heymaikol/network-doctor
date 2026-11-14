# Network Doctor

[![CI](https://github.com/heymaikol/network-doctor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/heymaikol/network-doctor/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/heymaikol/network-doctor)](https://github.com/heymaikol/network-doctor/releases/latest)
[![License: Apache-2.0](https://img.shields.io/github/license/heymaikol/network-doctor)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-networkdoctor.dev-1f6feb)](https://networkdoctor.dev/)

**Find out what's wrong with your network.**

Network Doctor is a free, open-source terminal app that helps you troubleshoot
network problems. It checks your connection, explains what it finds, and
suggests what to try next.

Whether a website won't load, a server won't connect, or your internet keeps
dropping, Network Doctor helps you figure out where the problem might be.

![Network Doctor showing a failed DNS check and explaining what to fix](assets/hero.gif)

## Install

Network Doctor runs on **Linux, macOS, and Windows**. The command is `netdoc`.

### macOS and Linux (Homebrew)

```sh
brew install network-doctor
```

### Windows (Scoop)

```powershell
scoop bucket add heymaikol https://github.com/heymaikol/scoop-bucket
scoop install network-doctor
```

### Linux packages

Download a `.deb`, `.rpm`, or `.apk` from the
[latest release](https://github.com/heymaikol/network-doctor/releases/latest)
and install it with your package manager.

Linux packages include both `netdoc` and `netdoc-sim`. For commands by
platform, see the [Linux installation guide](docs/installation.md#linux).

### Everywhere else

Download a [prebuilt binary](https://github.com/heymaikol/network-doctor/releases/latest)
or install with Go 1.27+:

```sh
go install github.com/heymaikol/network-doctor/v2/cmd/netdoc@latest
```

Homebrew installs `netdoc` only. See the
[installation guide](docs/installation.md) for updates and download verification.

## Try it

Open a terminal and run:

```sh
netdoc                  # Check your local network and internet connection
netdoc github.com       # Check a website or server
netdoc github.com:22    # Check a specific port
netdoc --watch github.com  # Watch for intermittent problems
```

Network Doctor shows what passed, what failed, and what you can try next.
It also tells you when there isn't enough information to identify the cause.

Select a check to see its results, press `D` for details, `w` to save a report,
or `?` to see the keyboard shortcuts.

**Sharing a report?** Files saved with `w` can include private network details.
Create a privacy-conscious support report instead:

```sh
netdoc --support support.ndoc github.com
```

Network Doctor does not upload the file. Review it before sharing.
See [support reports](docs/reference.md#support-snapshots) for details.

## What can Network Doctor help with?

- **Find where a connection fails.** Check your local network, DNS, internet
  access, and the connection to a website or server.
- **Understand the result.** Get a plain-language explanation and practical
  next steps, not just raw command output.
- **Catch intermittent issues.** Use Watch Mode to see failures and recoveries
  over time.
- **Investigate further.** Open familiar tools such as ping, traceroute, and
  DNS lookup from the terminal interface, or explore devices on your LAN.
- **Save and compare diagnoses.** Keep a report for later, compare a working
  connection with a broken one, or prepare a support report to share.
- **Troubleshoot from another computer.** Run checks remotely or compare what
  two machines experience.
- **Use it in scripts.** Get JSON output and exit codes with
  `netdoc --json github.com`.

For service profiles, two-sided diagnosis, route analysis, imports, and every
available option, see the [technical reference](docs/reference.md).

## Challenge Mode

Want to practice troubleshooting? Challenge Mode gives you a deliberately
broken network to diagnose, then compares your answer with what actually went
wrong. Everyone gets the same daily challenge.

On Linux, install a Linux package that includes `netdoc-sim`, then run:

```sh
netdoc-sim challenge -daily
netdoc-sim challenge -id V4-8F42C1  # Replay a friend's challenge
```

On macOS or Windows, use the simulator's container image:

```sh
docker run --rm -it --cap-add SYS_ADMIN ghcr.io/heymaikol/netdoc-sim:latest challenge -daily
```

Challenges run locally, without an account or leaderboard.
See the [Challenge Mode guide](https://github.com/heymaikol/network-doctor/wiki/Challenge-Mode)
for more ways to play.

## Documentation

- [Getting started](https://networkdoctor.dev/wiki/Getting-Started/): your first diagnosis
- [Understanding your diagnosis](https://networkdoctor.dev/wiki/Understanding-Your-Diagnosis/): what the results mean
- [Troubleshooting and FAQ](https://networkdoctor.dev/wiki/Troubleshooting-and-FAQ/): common questions
- [Installation details](docs/installation.md) and [technical reference](docs/reference.md): platforms, flags, and advanced features
- [Simulator guide](docs/simulation.md): Challenge Mode and network simulation

You can also browse the [documentation site](https://networkdoctor.dev/).

## Contributing

Contributions are welcome, from Go and terminal UI development to
documentation, packaging, and testing on real networks. Start with
[good first issues](https://github.com/heymaikol/network-doctor/issues?q=is:issue+is:open+label:%22good+first+issue%22),
[help wanted](https://github.com/heymaikol/network-doctor/issues?q=is:issue+is:open+label:%22help+wanted%22),
or [CONTRIBUTING.md](CONTRIBUTING.md). Run `./scripts/check.sh` to validate
changes. Report security issues privately using [SECURITY.md](SECURITY.md).

## Support

Need help with a specific network problem? I offer a
[paid personal diagnosis](https://tally.so/r/KYK7Y7): a written assessment,
suggested next steps, and one follow-up reply. The introductory price is
**$25 USD, one time, for the first five cases**. Diagnosis does not guarantee
a repair. Reports remain local unless you choose to share one.

Network Doctor is free and independently maintained. You can
[sponsor development](https://github.com/sponsors/heymaikol) if it has helped you.

## License

[Apache License 2.0](LICENSE).
