package app

import (
	"runtime"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// snapshotWriteFile is stubbed in tests that need the write itself to fail.
var snapshotWriteFile = snapshot.WriteFile

// writeSnapshot builds the portable artifact for a finished run and saves it.
func writeSnapshot(h headless, probes []diagnostic.Probe, results map[diagnostic.ProbeID]diagnostic.ProbeResult) error {
	return saveSnapshot(h, buildSnapshotArtifact(h, probes, results))
}

// buildSnapshotArtifact is the portable artifact for a finished run.
//
// The conversion from probe results lives in internal/diagnostic, which is the
// only package that can read its own evidence. What is added here is what
// describes the invocation rather than the network: which build ran, when, and
// the settings that decide what the probes did, so a later comparison can tell
// a changed network from a differently configured run.
//
// It stops short of the privacy policy and the write, so the worker behind
// --via can hand the same artifact back over the wire and let the machine that
// asked for it decide what to keep.
func buildSnapshotArtifact(h headless, probes []diagnostic.Probe, results map[diagnostic.ProbeID]diagnostic.ProbeResult) snapshot.Snapshot {
	s := diagnostic.BuildSnapshot(h.target, probes, results)
	s.Tool = snapshot.Tool{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	s.CreatedAt = timeNow().UTC().Format(time.RFC3339)
	s.Options = snapshot.Options{
		ProbeTimeoutMs: h.timeout.Milliseconds(),
		PublicDNS:      h.publicDNS,
		PublicDNSAuto:  h.publicDNSAuto,
	}
	s.Options.Check = h.check.strings()
	s.Options.Skip = h.skip.strings()
	// Only the binding netdoc was told to use. Nothing here enumerates the
	// machine's other interfaces or addresses.
	if h.sources != nil {
		source := snapshot.Source{Interface: h.sources.Iface}
		if h.sources.IPv4 != nil {
			source.IPv4 = h.sources.IPv4.String()
		}
		if h.sources.IPv6 != nil {
			source.IPv6 = h.sources.IPv6.String()
		}
		s.Options.Source = &source
	}
	return s
}

// saveSnapshot applies the run's privacy policy and writes the artifact. It is
// the last step for a local run and for a remote one alike: a --via snapshot is
// built and stamped by the machine that probed, and sanitizing it is a decision
// about what leaves this machine, so it is made here either way.
func saveSnapshot(h headless, s snapshot.Snapshot) error {
	if h.support {
		s = snapshot.SanitizeForSupport(s)
	}
	return snapshotWriteFile(h.save, s)
}
