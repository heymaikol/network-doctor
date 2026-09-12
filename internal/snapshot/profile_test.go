package snapshot

import (
	"errors"
	"path/filepath"
	"testing"
)

func profileFixture() ProfileSnapshot {
	component := func(id, status string, ok bool) ProfileComponent {
		return ProfileComponent{
			ID: id, Label: id, Focus: "target_tcp", Status: status,
			Snapshot: Snapshot{
				Schema: Schema, CreatedAt: "2026-08-26T12:00:00Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Target:    &Target{Raw: "server.internal:22", Host: "server.internal", Port: 22, Protocol: "ssh", PortExplicit: true},
				Checks:    []Check{{ID: "target_tcp", Name: "TCP server.internal:22", Status: status, Ran: true, DurationMs: 1}},
				Diagnosis: Diagnosis{Verdict: "service", Summary: "server.internal result"}, OK: ok,
			},
		}
	}
	return ProfileSnapshot{
		Schema: ProfileSchema, CreatedAt: "2026-08-26T12:00:01Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Profile:    ProfileIdentity{Name: "ssh", Version: 1, Title: "SSH"},
		Components: []ProfileComponent{component("ssh", StatusFail, false), component("ssh-alt", StatusPass, true)},
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
	singleData, err := Encode(Snapshot{Checks: []Check{}, OK: true})
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
