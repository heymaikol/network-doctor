package snapshot

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func profileFixture() ProfileSnapshot {
	component := func(id, fallback, status string, ok bool) ProfileComponent {
		failedStage := ""
		if status == StatusFail {
			failedStage = "target_tcp"
		}
		return ProfileComponent{
			ID: id, Label: id, Focus: "target_tcp", Status: status, Fallback: fallback,
			Snapshot: Snapshot{
				Schema: Schema, CreatedAt: "2026-08-26T12:00:00Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Target:    &Target{Raw: "server.internal:22", Host: "server.internal", Port: 22, Protocol: "ssh", PortExplicit: true},
				Checks:    []Check{{ID: "target_tcp", Name: "TCP server.internal:22", Status: status, Ran: true, DurationMs: 1}},
				Diagnosis: Diagnosis{Verdict: "service", Summary: "server.internal result", FailedStage: failedStage}, OK: ok,
			},
		}
	}
	return ProfileSnapshot{
		Schema: ProfileSchema, CreatedAt: "2026-08-26T12:00:01Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Profile:    ProfileIdentity{Name: "ssh", Version: 1, Title: "SSH"},
		Components: []ProfileComponent{component("ssh", "", StatusFail, false), component("ssh-alt", "ssh", StatusPass, true)},
		Aggregate: ProfileAggregate{Status: StatusWarn, Summary: "SSH fallback works.", Finding: &ProfileFinding{
			ID: "ssh_fallback_available", AffectedComponents: []string{"ssh"}, WorkingComponents: []string{"ssh-alt"},
		}},
		OK: true,
	}
}

func TestProfileSnapshotRoundTrip(t *testing.T) {
	want := profileFixture()
	data, err := EncodeProfile(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != want.Profile || len(got.Components) != 2 || got.Aggregate.Finding.ID != "ssh_fallback_available" || !got.OK {
		t.Fatalf("round trip = %+v", got)
	}
	path := filepath.Join(t.TempDir(), "profile.ndoc")
	if err := WriteProfileFile(path, want); err != nil {
		t.Fatal(err)
	}
}

func TestProfileAndSingleSnapshotSchemasStayDistinct(t *testing.T) {
	profileData, err := EncodeProfile(profileFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(profileData); err == nil {
		t.Fatal("single-run decoder accepted a profile artifact")
	} else {
		var unsupported UnsupportedSchemaError
		if !errors.As(err, &unsupported) || unsupported.Found != ProfileSchema {
			t.Fatalf("single-run decode error = %v", err)
		}
	}
	singleData, err := Encode(Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"}, Checks: []Check{}, OK: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProfile(singleData); err == nil {
		t.Fatal("profile decoder accepted a single-run snapshot")
	}
}

func TestProfileSupportRedactionUsesOneMapping(t *testing.T) {
	sanitized := SanitizeProfileForSupport(profileFixture())
	if sanitized.Redaction == nil || !sanitized.Redaction.Sanitized {
		t.Fatal("profile lacks redaction metadata")
	}
	first := sanitized.Components[0].Snapshot
	second := sanitized.Components[1].Snapshot
	if first.Redaction == nil || second.Redaction == nil {
		t.Fatal("component lacks redaction metadata")
	}
	if first.Target.Host == "server.internal" || first.Target.Host != second.Target.Host {
		t.Fatalf("redacted hosts = %q, %q", first.Target.Host, second.Target.Host)
	}
	if _, err := EncodeProfile(sanitized); err != nil {
		t.Fatal(err)
	}
}

// profileRejectsBothWays holds a profile artifact to the same rules in both
// directions. The decode half marshals the struct directly rather than going
// through EncodeProfile, which stamps schemas on the way past and would repair
// part of what is under test.
func profileRejectsBothWays(t *testing.T, profile ProfileSnapshot, want string) {
	t.Helper()
	if _, err := EncodeProfile(profile); err == nil {
		t.Errorf("EncodeProfile published %s", want)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProfile(data); err == nil {
		t.Errorf("DecodeProfile accepted %s", want)
	}
}

// A profile states its conclusions twice: as the envelope a script reads and
// as the complete runs nested inside it. These are the shapes where the two
// disagree, each one otherwise a valid artifact.
func TestProfileEnvelopeCannotContradictItsRuns(t *testing.T) {
	for name, mutate := range map[string]func(*ProfileSnapshot){
		"a component that passes over a failed run": func(p *ProfileSnapshot) {
			p.Components[0].Status = StatusPass
		},
		"a component that fails over a passing run": func(p *ProfileSnapshot) {
			p.Components[1].Status = StatusFail
		},
		"a component that passes with no focus row at all": func(p *ProfileSnapshot) {
			p.Components[1].Focus = "target_tls"
		},
		"a component that passes over a run reported not ok": func(p *ProfileSnapshot) {
			p.Components[1].Snapshot.Checks[0].Status = StatusIncomplete
			p.Components[1].Snapshot.OK = false
			p.Components[1].Snapshot.Diagnosis.FailedStage = ""
		},
		"a component that passes over a degraded run": func(p *ProfileSnapshot) {
			p.Components[1].Snapshot.Diagnosis.Verdict = VerdictDegraded
		},
		"an aggregate that passes over an affected component": func(p *ProfileSnapshot) {
			p.Aggregate.Status, p.Aggregate.Finding = StatusPass, nil
		},
		"an aggregate that fails while a component works": func(p *ProfileSnapshot) {
			p.Aggregate.Status, p.OK = StatusFail, false
		},
		"a finding naming a conclusion the components do not reach": func(p *ProfileSnapshot) {
			p.Aggregate.Finding.ID = "ssh_unreachable"
		},
		"a finding for a profile whose components all passed": func(p *ProfileSnapshot) {
			p.Components[0].Status = StatusPass
			p.Components[0].Snapshot.Checks[0].Status = StatusPass
			p.Components[0].Snapshot.OK = true
			p.Components[0].Snapshot.Diagnosis.FailedStage = ""
		},
		"no finding for a profile with an affected component": func(p *ProfileSnapshot) {
			p.Aggregate.Finding = nil
		},
		"affected components that are not the ones that are down": func(p *ProfileSnapshot) {
			p.Aggregate.Finding.AffectedComponents = []string{"ssh-alt"}
		},
		"working components that are not the ones that work": func(p *ProfileSnapshot) {
			p.Aggregate.Finding.WorkingComponents = []string{"ssh"}
		},
		"a working component listed twice": func(p *ProfileSnapshot) {
			p.Aggregate.Finding.WorkingComponents = []string{"ssh-alt", "ssh-alt"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := profileFixture()
			mutate(&profile)
			profileRejectsBothWays(t, profile, name)
		})
	}
}

// The other direction, which is the one a passing test suite is worst at: the
// ordinary artifacts a profile actually produces have to stay readable.
func TestOrdinaryProfileArtifactsStayValid(t *testing.T) {
	for name, build := range map[string]func() ProfileSnapshot{
		"a fallback covering the component that is down": profileFixture,
		"every component reachable": func() ProfileSnapshot {
			p := profileFixture()
			p.Components[0].Status = StatusPass
			p.Components[0].Snapshot.Checks[0].Status = StatusPass
			p.Components[0].Snapshot.OK = true
			p.Components[0].Snapshot.Diagnosis.FailedStage = ""
			p.Aggregate = ProfileAggregate{Status: StatusPass, Summary: "All SSH components are reachable."}
			return p
		},
		"no component reachable": func() ProfileSnapshot {
			p := profileFixture()
			p.Components[1].Status = StatusFail
			p.Components[1].Snapshot.Checks[0].Status = StatusFail
			p.Components[1].Snapshot.OK = false
			p.Components[1].Snapshot.Diagnosis.FailedStage = "target_tcp"
			p.Aggregate = ProfileAggregate{Status: StatusFail, Summary: "No SSH component completed its service check.",
				Finding: &ProfileFinding{ID: "ssh_unreachable", AffectedComponents: []string{"ssh", "ssh-alt"}}}
			p.OK = false
			return p
		},
		"a degraded component counted as both affected and working": func() ProfileSnapshot {
			p := profileFixture()
			p.Components[0].Status = StatusWarn
			p.Components[0].Snapshot.Checks[0].Status = StatusPass
			p.Components[0].Snapshot.OK = true
			p.Components[0].Snapshot.Diagnosis.Verdict = VerdictDegraded
			p.Components[0].Snapshot.Diagnosis.FailedStage = ""
			p.Aggregate = ProfileAggregate{Status: StatusWarn, Summary: "ssh is unavailable, but ssh-alt works.",
				Finding: &ProfileFinding{ID: "ssh_fallback_available",
					AffectedComponents: []string{"ssh"}, WorkingComponents: []string{"ssh", "ssh-alt"}}}
			return p
		},
		"a fallback that is down while the service it stands in for works": func() ProfileSnapshot {
			p := profileFixture()
			p.Components[0].Status = StatusPass
			p.Components[0].Snapshot.Checks[0].Status = StatusPass
			p.Components[0].Snapshot.OK = true
			p.Components[0].Snapshot.Diagnosis.FailedStage = ""
			p.Components[1].Status = StatusFail
			p.Components[1].Snapshot.Checks[0].Status = StatusFail
			p.Components[1].Snapshot.OK = false
			p.Components[1].Snapshot.Diagnosis.FailedStage = "target_tcp"
			p.Aggregate = ProfileAggregate{Status: StatusWarn, Summary: "ssh works, but ssh-alt is unavailable.",
				Finding: &ProfileFinding{ID: "ssh_fallback_unavailable",
					AffectedComponents: []string{"ssh-alt"}, WorkingComponents: []string{"ssh"}}}
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := EncodeProfile(build())
			if err != nil {
				t.Fatalf("an ordinary profile artifact was refused: %v", err)
			}
			if _, err := DecodeProfile(data); err != nil {
				t.Fatalf("an ordinary profile artifact would not read back: %v", err)
			}
		})
	}
}
