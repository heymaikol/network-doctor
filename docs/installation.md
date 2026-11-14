# Installation details

[README.md](../README.md) gives the one command per platform that installs
`netdoc`. This page covers what comes after that: how each install method
upgrades, which trust root signs it, what a Linux package contains, and how to
verify a downloaded artifact. The wiki's
[Getting Started](https://github.com/heymaikol/network-doctor/wiki/Getting-Started)
page walks through the first run instead.

The project is `network-doctor`; the installed binary is `netdoc`. Check what
you are running with `netdoc --version`.

## Windows

Scoop installs from the project's own bucket:

```powershell
scoop bucket add heymaikol https://github.com/heymaikol/scoop-bucket
scoop install network-doctor
```

A release reaches the bucket as soon as it publishes, so
`scoop update network-doctor` picks it up like any other app.

## macOS and Linux (Homebrew)

```sh
brew install network-doctor
```

This is the Homebrew Core formula, bottled for both platforms, so `brew upgrade`
picks up releases like any other formula. It installs `netdoc` alone. For
`netdoc-sim` as well, take a Linux package below, or run the simulator from
[a container](simulation.md#running-it-in-a-container).

## Linux

Every prebuilt Linux package (`.deb`, `.rpm`, `.apk`) installs two commands at the
same version: `netdoc`, and `netdoc-sim`, the simulator behind Challenge Mode.
Confirm both:

```sh
netdoc --version
netdoc-sim help
```

`netdoc-sim` is Linux-only: it builds its networks out of Linux namespaces, so
the macOS and Windows downloads ship `netdoc` alone. Those hosts run the same
simulator from [a container](simulation.md#running-it-in-a-container) instead.

### Fedora (stable and Rawhide): prebuilt release RPM

Download the `.rpm` for your architecture from the
[latest release](https://github.com/heymaikol/network-doctor/releases/latest),
then install it locally:

```sh
sudo dnf install ./network-doctor_X.Y.Z_linux_ARCH.rpm    # amd64 or arm64
```

The release RPM is prebuilt and does not depend on the Go toolchain available
in Fedora repositories. It does not add an update repository, so `dnf` will
not automatically download new Network Doctor releases.

The former COPR repository is not updated by the release workflow. Existing
COPR installations should not be assumed to have the latest version.

### Other Linux distributions

Prebuilt `.deb`, `.rpm`, and `.apk` packages are on the
[latest release](https://github.com/heymaikol/network-doctor/releases/latest),
for `amd64` and `arm64`. Download one and install it locally:

```sh
sudo apt install ./network-doctor_X.Y.Z_linux_amd64.deb    # Debian, Ubuntu, Mint
sudo dnf install ./network-doctor_X.Y.Z_linux_amd64.rpm    # RHEL, Rocky, Alma
sudo apk add --allow-untrusted ./network-doctor_X.Y.Z_linux_amd64.apk    # Alpine
```

These standalone packages do not add an update repository, so `dnf`/`apt` will
not pull the next version for you. After downloading a newer Debian package,
install it over the existing version and confirm the upgrade:

```sh
sudo apt install ./network-doctor_X.Y.Z_linux_amd64.deb
netdoc --version
netdoc-sim version
dpkg-query -W network-doctor
```

## Prebuilt binaries, `go install`, and building from a clone

Prebuilt binaries are on the
[latest release](https://github.com/heymaikol/network-doctor/releases/latest);
Windows ships as a `.zip`, the rest as bare binaries. With Go 1.27 or newer:

```sh
go install github.com/heymaikol/network-doctor/v2/cmd/netdoc@latest
```

That entrypoint exists so the installed command is named `netdoc`. A plain
`go install github.com/heymaikol/network-doctor/v2@latest` would name it
`network-doctor` instead, which is the same program under a different name.

The path without `/v2` only serves v1 releases, so the old
`github.com/heymaikol/network-doctor/cmd/netdoc@latest` command keeps installing
v1.

To build from a clone:

```sh
git clone https://github.com/heymaikol/network-doctor
cd network-doctor
go build -o netdoc .
```

A local build reports its version as `dev` unless the version is injected with
`-ldflags "-X main.version=..."`, which is what release builds do.

## Verify your download

Releases carry a signed attestation binding each artifact to the workflow run
that built it (not available for v1.8.4 and earlier). With the GitHub CLI
installed and `gh auth login` done:

```sh
VERSION=X.Y.Z
gh attestation verify "./netdoc_${VERSION}_linux_amd64" \
  --repo heymaikol/network-doctor \
  --signer-workflow heymaikol/network-doctor/.github/workflows/release.yml
```

This proves the bytes were built from the tagged commit by the release workflow.
The source tarball, the `.deb`/`.rpm`/`.apk` packages, and the Windows `.zip`
are attested too, so pass whichever filename you downloaded. The
vendored-dependency tarball (`*-vendor.tar.gz`) is attested as well. It
supports optional offline source builds using the RPM spec, but is not
needed when installing a prebuilt release RPM.
