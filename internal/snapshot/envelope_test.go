package snapshot

import (
	"encoding/json"
	"testing"
)

// Each mutation starts from the production builder's golden artifact. Decode
// receives raw JSON, never Encode's output, so no boundary can repair another.
func TestEnvelopeBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Snapshot)
		valid  bool
	}{
		{"created_at empty", func(s *Snapshot) { s.CreatedAt = "" }, false},
		{"created_at malformed", func(s *Snapshot) { s.CreatedAt = "yesterday" }, false},
		{"created_at offset", func(s *Snapshot) { s.CreatedAt = "2026-01-02T03:04:05+01:00" }, false},
		{"created_at UTC offset", func(s *Snapshot) { s.CreatedAt = "2026-01-02T03:04:05+00:00" }, true},
		{"version empty", func(s *Snapshot) { s.Tool.Version = "" }, false},
		{"baseline", func(s *Snapshot) {}, true},
		{"version blank", func(s *Snapshot) { s.Tool.Version = " " }, false},
		{"os blank", func(s *Snapshot) { s.Tool.OS = "" }, false},
		{"arch blank", func(s *Snapshot) { s.Tool.Arch = "" }, false},
		{"future tool", func(s *Snapshot) { s.Tool = Tool{"next build", "future-os", "future-arch"} }, true},
		{"empty target", func(s *Snapshot) { s.Target = &Target{} }, false},
		{"raw blank", func(s *Snapshot) { s.Target.Raw = " " }, false},
		{"host blank", func(s *Snapshot) { s.Target.Host = " " }, false},
		{"protocol blank", func(s *Snapshot) { s.Target.Protocol = "" }, false},
		{"future protocol", func(s *Snapshot) { s.Target.Protocol = "future" }, true},
		{"raw independent", func(s *Snapshot) { s.Target.Raw = "future://example.com/path" }, true},
		{"port zero", func(s *Snapshot) { s.Target.Port = 0 }, false},
		{"port negative", func(s *Snapshot) { s.Target.Port = -1 }, false},
		{"port overflow", func(s *Snapshot) { s.Target.Port = 65536 }, false},
		{"port maximum", func(s *Snapshot) { s.Target.Port = 65535 }, true},
		{"ip malformed", func(s *Snapshot) { s.Target.IP = "invalid" }, false},
		{"ip on hostname", func(s *Snapshot) { s.Target.IP = "192.0.2.1" }, false},
		{"literal missing ip", func(s *Snapshot) { s.Target.Host = "192.0.2.1" }, false},
		{"literal different ip", func(s *Snapshot) {
			s.Target = &Target{Raw: "192.0.2.1", Host: "192.0.2.1", IP: "192.0.2.2", Port: 443, Protocol: "tls+http"}
		}, false},
		{"mapped literal", func(s *Snapshot) {
			s.Target = &Target{Raw: "::ffff:192.0.2.1", Host: "::ffff:192.0.2.1", IP: "192.0.2.1", Port: 443, Protocol: "tls+http"}
		}, true},
		{"generic", func(s *Snapshot) { s.Target = nil }, true},
		{"timeout negative", func(s *Snapshot) { s.Options.ProbeTimeoutMs = -1 }, false},
		{"timeout rounded zero", func(s *Snapshot) { s.Options.ProbeTimeoutMs = 0 }, true},
		{"resolver malformed", func(s *Snapshot) { s.Options.PublicDNS = "auto" }, false},
		{"auto without resolver", func(s *Snapshot) { s.Options.PublicDNS = ""; s.Options.PublicDNSAuto = true }, true},
		{"check blank", func(s *Snapshot) { s.Options.Check = []string{""} }, false},
		{"skip blank", func(s *Snapshot) { s.Options.Skip = []string{" "} }, false},
		{"future selection", func(s *Snapshot) { s.Options.Check = []string{"future"}; s.Options.Skip = []string{"future"} }, true},
		{"source empty", func(s *Snapshot) { s.Options.Source = &Source{} }, false},
		{"source interface only", func(s *Snapshot) { s.Options.Source = &Source{Interface: "eth0"} }, false},
		{"source invalid v4", func(s *Snapshot) { s.Options.Source = &Source{IPv4: "bad"} }, false},
		{"source wrong v4 family", func(s *Snapshot) { s.Options.Source = &Source{IPv4: "2001:db8::1"} }, false},
		{"source wrong v6 family", func(s *Snapshot) { s.Options.Source = &Source{IPv6: "192.0.2.1"} }, false},
		{"source exact IPv4", func(s *Snapshot) { s.Options.Source = &Source{IPv4: "192.0.2.1"} }, true},
		{"source exact IPv6", func(s *Snapshot) { s.Options.Source = &Source{IPv6: "2001:db8::1"} }, true},
		{"source mapped IPv6", func(s *Snapshot) { s.Options.Source = &Source{IPv6: "::ffff:192.0.2.1"} }, false},
		{"source malformed IPv6", func(s *Snapshot) { s.Options.Source = &Source{IPv6: "bad"} }, false},
		{"source unspecified", func(s *Snapshot) { s.Options.Source = &Source{IPv4: "0.0.0.0"} }, false},
		{"source multicast", func(s *Snapshot) { s.Options.Source = &Source{IPv6: "ff02::1"} }, false},
		{"source exact dual family", func(s *Snapshot) { s.Options.Source = &Source{IPv4: "192.0.2.1", IPv6: "2001:db8::1"} }, false},
		{"source interface dual family", func(s *Snapshot) {
			s.Options.Source = &Source{Interface: "future interface", IPv4: "192.0.2.1", IPv6: "fe80::1"}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s Snapshot
			if err := json.Unmarshal(golden(t), &s); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&s)
			if tc.valid {
				if _, err := Encode(SanitizeForSupport(s)); err != nil {
					t.Fatalf("support artifact: %v", err)
				}
			}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			p := profileFixture()
			p.Components[0].Snapshot = s
			profileData, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			for name, call := range map[string]func() error{
				"EncodeProfile component": func() error { _, err := EncodeProfile(p); return err },
				"DecodeProfile component": func() error { _, err := DecodeProfile(profileData); return err },
				"Validate":                func() error { return Validate(s) },
				"Encode":                  func() error { _, err := Encode(s); return err },
				"Decode":                  func() error { _, err := Decode(data); return err },
			} {
				t.Run(name, func(t *testing.T) {
					err := call()
					if (err == nil) != tc.valid {
						t.Errorf("accepted=%v, want %v; error=%v", err == nil, tc.valid, err)
					}
				})
			}
		})
	}
}

func TestProfileEnvelopeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ProfileSnapshot)
		valid  bool
	}{
		{"empty time", func(p *ProfileSnapshot) { p.CreatedAt = "" }, false},
		{"malformed time", func(p *ProfileSnapshot) { p.CreatedAt = "bad" }, false},
		{"non UTC time", func(p *ProfileSnapshot) { p.CreatedAt = "2026-01-02T03:04:05-01:00" }, false},
		{"blank version", func(p *ProfileSnapshot) { p.Tool.Version = "" }, false},
		{"blank os", func(p *ProfileSnapshot) { p.Tool.OS = " " }, false},
		{"blank arch", func(p *ProfileSnapshot) { p.Tool.Arch = "" }, false},
		{"different remote tool", func(p *ProfileSnapshot) { p.Tool = Tool{"future", "future-os", "future-arch"} }, true},
		{"fractional UTC", func(p *ProfileSnapshot) { p.CreatedAt = "2026-01-02T03:04:05.123+00:00" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileFixture()
			tc.mutate(&p)
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			for name, call := range map[string]func() error{
				"EncodeProfile": func() error { _, err := EncodeProfile(p); return err },
				"DecodeProfile": func() error { _, err := DecodeProfile(data); return err },
			} {
				t.Run(name, func(t *testing.T) {
					if err := call(); (err == nil) != tc.valid {
						t.Errorf("accepted=%v, want %v; error=%v", err == nil, tc.valid, err)
					}
				})
			}
		})
	}
}

func TestEnvelopeMissingAndAdditiveFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		valid bool
	}{
		{"created_at", false}, {"tool", false}, {"target", true}, {"options", true},
	} {
		t.Run(tc.field, func(t *testing.T) {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(golden(t), &object); err != nil {
				t.Fatal(err)
			}
			delete(object, tc.field)
			data, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			// Missing target/options retain their established zero-value reading.
			// Presence cannot be inferred from an already decoded Snapshot either.
			if _, err := Decode(data); (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, tc.valid, err)
			}
		})
	}
	var s Snapshot
	if err := json.Unmarshal(golden(t), &s); err != nil {
		t.Fatal(err)
	}
	s.Options.Source = &Source{IPv4: "192.0.2.1"}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	for _, fields := range []map[string]any{object, object["tool"].(map[string]any), object["target"].(map[string]any), object["options"].(map[string]any), object["options"].(map[string]any)["source"].(map[string]any)} {
		fields["future_optional"] = map[string]any{"meaning": "unknown to this reader"}
	}
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
}
