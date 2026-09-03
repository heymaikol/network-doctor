# Challenge Mode, and the rest of netdoc-sim, packaged for hosts that are not
# Linux. The image is an execution layer and nothing else: it ships the same
# netdoc-sim the Linux packages do, and that binary builds its networks out of
# the same unprivileged user, network and mount namespaces it uses natively.
# There is no container simulation backend, no reduced-fidelity mode, and no
# second implementation to keep in step: macOS and Windows get a Linux kernel
# from Docker Desktop or Podman Machine, and the real simulator runs on it.
#
# Both binaries are built here from one source tree with one version string, so
# the netdoc the challenge runs is the netdoc the image tag names. The simulator
# finds it as the sibling of netdoc-sim (docs/simulation.md, "Which netdoc gets
# run"), which is why they share a directory and why nothing else named netdoc
# is on PATH.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine3.23@sha256:d9e2f2f07b10cc922da3e80e035c3058810b328d5aef82d2c63680967c5e2ec9 AS build

WORKDIR /src
# Dependencies first: the module graph changes far less often than the code, so
# an ordinary source edit does not re-download it.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# TARGETARCH comes from the builder; the compile is a cross-compile from the
# build host's architecture, so no emulator runs the Go toolchain.
ARG TARGETARCH
# VERSION is what both binaries report. The release workflow passes the tag, so
# `netdoc -version` inside the image and the image tag are the same release.
# A local `docker build` with no --build-arg gets "dev", which is the truth
# about a local build and is what the recorded challenge result should say.
ARG VERSION=dev
# CGO_ENABLED=0 for the same reason the packages use it: a cgo netdoc can
# resolve through the host's glibc resolver instead of the simulated node's
# private /etc/resolv.conf, which would test this container instead of the
# simulation. -s -w matches the release build's flags.
ENV CGO_ENABLED=0 GOOS=linux
RUN GOARCH="$TARGETARCH" go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/netdoc . && \
    GOARCH="$TARGETARCH" go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/netdoc-sim ./cmd/netdoc-sim

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Two sets of tools, both required.
#
# The backend shells out to ip and nsenter always, and to tc and nft for netem
# and firewall faults; iproute2 6.6 or newer is what seeded netem loss needs.
# The rest is the challenge shell: a person is dropped into the broken node and
# told to reach for ping, dig, curl, ss, traceroute and nc, so an image without
# them would set a puzzle it does not let anyone solve. traceroute and the shell
# come from busybox, which is already here.
RUN apk add --no-cache \
        iproute2 \
        iproute2-tc \
        nftables \
        util-linux-misc \
        iputils-ping \
        bind-tools \
        curl \
        netcat-openbsd

COPY --from=build /out/netdoc /usr/bin/netdoc
COPY --from=build /out/netdoc-sim /usr/bin/netdoc-sim

# Unprivileged by default, and it costs nothing: a simulation needs no
# capability at all. It creates a user namespace, and the kernel gives it root
# over the namespaces it just made and nothing else. Running as a normal user
# means the --cap-add SYS_ADMIN that Docker's default seccomp profile requires
# to permit clone(CLONE_NEWUSER) unlocks the syscall filter without arming the
# capability for a process that could use it. See docs/simulation.md.
RUN adduser -D -u 1000 netdoc
USER netdoc
ENV HOME=/home/netdoc

# A result posted from this image has to be runnable by whoever reads it, and
# they may have no netdoc-sim at all. Override it with -e for another runtime.
ENV NETDOC_SIM_CHALLENGE_COMMAND="docker run --rm -it --cap-add SYS_ADMIN ghcr.io/heymaikol/netdoc-sim challenge"

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="netdoc-sim" \
      org.opencontainers.image.description="Network Doctor Challenge Mode and network simulator, on the real Linux namespace backend" \
      org.opencontainers.image.url="https://github.com/heymaikol/network-doctor" \
      org.opencontainers.image.source="https://github.com/heymaikol/network-doctor" \
      org.opencontainers.image.documentation="https://github.com/heymaikol/network-doctor/blob/main/docs/simulation.md#running-it-in-a-container" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# netdoc-sim owns the argument parsing, so everything after the image name is
# its own command line: `challenge`, `challenge -id V4-8F42C1 -json`, `run
# broken-dns`, `capabilities`. Bare `docker run IMAGE` plays a challenge.
ENTRYPOINT ["/usr/bin/netdoc-sim"]
CMD ["challenge"]
