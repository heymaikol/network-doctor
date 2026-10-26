# Static Go binary built with -s -w: nothing left for debuginfo to extract.
%global debug_package %{nil}

Name:           network-doctor
# Placeholder, not a per-release chore. The copr job in the release workflow
# rewrites this from the git tag before building, so published RPMs always
# match the release. Here it only selects which release's Source0/Source1
# tarballs a hand-run rpmbuild/mock/spectool downloads, so bump it (with a
# changelog entry) only when you want a manual build of a newer version.
Version:        1.10.8
Release:        1%{?dist}
Summary:        Terminal UI that diagnoses network connectivity and names the layer where the connection breaks

License:        Apache-2.0
URL:            https://github.com/heymaikol/network-doctor
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{url}/releases/download/v%{version}/%{name}-%{version}-vendor.tar.gz

BuildRequires:  golang >= 1.27.3

%description
Network Doctor diagnoses network connectivity layer by layer and names the
layer where the connection breaks in plain English, instead of a wall of tool
output. Probes run unprivileged and time-bounded, and form a dependency graph
with independent branches so an unrelated failure never hides a working path.

The installed binaries are netdoc, the diagnostic itself, and netdoc-sim, the
Linux-only simulator that builds throwaway virtual networks to test netdoc
against and to play Challenge Mode in.

%prep
# -a1 unpacks the vendor tarball after entering the source directory.
%autosetup -a1

%build
export CGO_ENABLED=0
export GOFLAGS="-mod=vendor -trimpath -modcacherw"
# The builder has no network. Fail loudly here rather than mysteriously later.
export GOPROXY=off
export GOTOOLCHAIN=local
go build -ldflags "-s -w -X main.version=%{version}" -o netdoc .
# Shipped from the same source and version as netdoc, to keep this package's
# installed binaries identical to the nfpm-built deb/rpm/apk on the release
# page. netdoc-sim needs a netdoc beside it, which %{_bindir} gives it.
go build -ldflags "-s -w -X main.version=%{version}" -o netdoc-sim ./cmd/netdoc-sim

%install
install -Dpm0755 netdoc %{buildroot}%{_bindir}/netdoc
install -Dpm0755 netdoc-sim %{buildroot}%{_bindir}/netdoc-sim
install -Dpm0644 packaging/netdoc.1 %{buildroot}%{_mandir}/man1/netdoc.1
install -Dpm0644 packaging/completions/netdoc.bash %{buildroot}%{_datadir}/bash-completion/completions/netdoc
install -Dpm0644 packaging/completions/netdoc.zsh %{buildroot}%{_datadir}/zsh/site-functions/_netdoc
install -Dpm0644 packaging/completions/netdoc.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/netdoc.fish
install -Dpm0644 packaging/netdoc-sim.1 %{buildroot}%{_mandir}/man1/netdoc-sim.1
install -Dpm0644 packaging/completions/netdoc-sim.bash %{buildroot}%{_datadir}/bash-completion/completions/netdoc-sim
install -Dpm0644 packaging/completions/netdoc-sim.zsh %{buildroot}%{_datadir}/zsh/site-functions/_netdoc-sim
install -Dpm0644 packaging/completions/netdoc-sim.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/netdoc-sim.fish

%files
%license LICENSE
%doc README.md
%{_bindir}/netdoc
%{_bindir}/netdoc-sim
# Glob: brp-compress gzips the page after %install, so the name gains a suffix.
%{_mandir}/man1/netdoc.1*
# Not %dir-owned: bash-completion, zsh, and fish are not dependencies, and the
# completion is useless without the shell anyway. Owning the file only.
%{_datadir}/bash-completion/completions/netdoc
%{_datadir}/zsh/site-functions/_netdoc
%{_datadir}/fish/vendor_completions.d/netdoc.fish
%{_mandir}/man1/netdoc-sim.1*
%{_datadir}/bash-completion/completions/netdoc-sim
%{_datadir}/zsh/site-functions/_netdoc-sim
%{_datadir}/fish/vendor_completions.d/netdoc-sim.fish

%changelog
* Sun Aug 09 2026 Michael Placzek <heymaikol@proton.me> - 1.10.8-1
- Update to 1.10.8

* Mon Aug 03 2026 Michael Placzek <heymaikol@proton.me> - 1.10.3-1
- Initial COPR package
