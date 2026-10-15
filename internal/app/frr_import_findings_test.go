package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/ospf"
)

// stageFRRLab stages the broadcast manifest, then replaces each of its four
// captures with the same capture from another recorded lab, unframed the same
// way. The declared collection times stay the broadcast lab's.
func stageFRRLab(t *testing.T, lab string) (dir, manifest string) {
	t.Helper()
	dir, manifest = stageFRRBcast(t)
	for _, s := range []struct{ stem, file, command string }{
		{"r1-show_ip_ospf_interface_json", "r1-interface.json", "show ip ospf interface json"},
		{"r1-show_ip_ospf_neighbor_detail_json", "r1-neighbor.json", "show ip ospf neighbor detail json"},
		{"r2-show_ip_ospf_interface_json", "r2-interface.json", "show ip ospf interface json"},
		{"r2-show_ip_ospf_neighbor_detail_json", "r2-neighbor.json", "show ip ospf neighbor detail json"},
	} {
		// #nosec G304 -- the path is a committed lab fixture named from this table.
		raw, err := os.ReadFile(filepath.Join(frrBcastDir, "..", lab, s.stem+".raw"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"), "\n")
		if len(lines) < 3 || lines[0] != s.command {
			t.Fatalf("%s %s: echoed command is not %q", lab, s.stem, s.command)
		}
		// #nosec G703 -- s.file is a literal name from this test's own table.
		if err := os.WriteFile(filepath.Join(dir, s.file), []byte(strings.Join(lines[1:len(lines)-1], "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, manifest
}

// importOSPFFindings runs a JSON import and returns its exit code and the
// findings under its ospf key, or nil when the key is absent.
func importOSPFFindings(t *testing.T, manifest string) (int, []ospf.Finding) {
	t.Helper()
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	raw, ok := frrReportFields(t, stdout)["ospf"]
	if !ok {
		return code, nil
	}
	var rep ospf.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("ospf key does not decode: %v\nstderr: %s", err, stderr)
	}
	return code, rep.Findings
}

// The MTU lab holds Exchange and ExStart neighbors. The import reports each as
// a state before FULL, with the limit that it names no cause and does not show
// the far side down.
func TestFRRImportReportsOSPFFindingsForTheMTULab(t *testing.T) {
	_, manifest := stageFRRLab(t, "mtu")
	code, findings := importOSPFFindings(t, manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	got := map[string]string{}
	for _, f := range findings {
		if f.Kind != ospf.KindNeighborState || f.Strength != ospf.Reported {
			t.Errorf("unexpected finding %s [%s] %s", f.Kind, f.Strength, f.Detail)
			continue
		}
		got[f.Node+" "+f.Interface] = f.Detail
		if !strings.Contains(f.Limit, "names no root cause and does not prove the far side is down") {
			t.Errorf("%s %s limit = %q, want the before-FULL limit", f.Node, f.Interface, f.Limit)
		}
	}
	if !strings.Contains(got["r1 e1"], "exchange") || !strings.Contains(got["r2 e2"], "exstart") {
		t.Errorf("findings = %v, want r1 e1 exchange and r2 e2 exstart", got)
	}

	_, text, _ := runNetdoc(t, "--import-frr-ospf", manifest)
	block := strings.Index(text, "\nOSPF (from recorded evidence")
	if block < 0 || block < strings.Index(text, "\nNeighbor records") || block > strings.Index(text, "\nNot imported:") {
		t.Errorf("text has no OSPF block between the neighbor records and the not-imported list:\n%s", text)
	}
	if strings.Contains(text, "not analyzed:") {
		t.Errorf("a complete import says something was not analyzed:\n%s", text)
	}
}

// A refused capture makes the import incomplete. The findings the accepted
// captures support are still reported, the exit code stays 1, and the text says
// what was not analyzed.
func TestFRRImportIncompleteStillReportsOSPFFindings(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	editFRRJSON(t, manifest, func(m map[string]any) {
		frrManifestCapture(m, 3)["frr_version"] = "10.6.0" // r2 neighbor detail
	})
	code, findings := importOSPFFindings(t, manifest)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if len(findings) != 1 || findings[0].Node != "r1" || findings[0].Kind != ospf.KindNeighborState {
		t.Errorf("findings = %+v, want one neighbor_state for r1", findings)
	}
	code, text, _ := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 1 {
		t.Fatalf("text exit %d, want 1", code)
	}
	for _, want := range []string{"Result: incomplete.", "neighbor_state [reported] r1 e1 to r2 e2", "not analyzed: unmapped neighbor records 0, refused captures 1. They wrote no evidence"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

// Interface captures alone give no OSPF finding, so the report has no ospf key
// and no OSPF block, as before.
func TestFRRImportWithoutNeighborCapturesHasNoOSPFSection(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	editFRRJSON(t, manifest, func(m map[string]any) {
		all := m["captures"].([]any)
		m["captures"] = []any{all[0], all[2]}
	})
	code, findings := importOSPFFindings(t, manifest)
	if code != 0 || findings != nil {
		t.Errorf("exit %d, findings %+v; want 0 and no ospf key", code, findings)
	}
	if _, text, _ := runNetdoc(t, "--import-frr-ospf", manifest); strings.Contains(text, "OSPF (from") {
		t.Errorf("interface-only import printed an OSPF block:\n%s", text)
	}
}

// An unmapped record leaves its capture accepted, and the other side's mapped
// record still writes evidence. Only that side's own report is a finding: the
// unmapped side is never read as missing, one-sided, or in conflict.
func TestFRRImportUnmappedRecordGivesNoFindingForItsSide(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	editFRRJSON(t, filepath.Join(dir, "r2-interface.json"), func(m map[string]any) {
		delete(m["interfaces"].(map[string]any)["e2"].(map[string]any), "routerId")
	})
	code, findings := importOSPFFindings(t, manifest)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want only r2's own report", findings)
	}
	if f := findings[0]; f.Kind != ospf.KindNeighborState || f.Node != "r2" || f.Interface != "e2" || f.Detail != "reports state full" {
		t.Errorf("finding = %+v, want r2 e2 reporting state full", f)
	}
	_, text, _ := runNetdoc(t, "--import-frr-ospf", manifest)
	if !strings.Contains(text, "not analyzed: unmapped neighbor records 1, refused captures 0.") {
		t.Errorf("text does not count the unmapped record as not analyzed:\n%s", text)
	}
}

// An incomplete import whose accepted captures give no finding still says what
// was not analyzed. The text keeps the OSPF block with that line, so the gap is
// not read as nothing found, and the JSON still leaves out the ospf key.
func TestFRRImportIncompleteWithNoFindingSaysWhatWasNotAnalyzed(t *testing.T) {
	cases := []struct {
		name        string
		edit        func(t *testing.T, dir, manifest string)
		notAnalyzed string
	}{
		{"refused neighbor captures", func(t *testing.T, _, manifest string) {
			editFRRJSON(t, manifest, func(m map[string]any) {
				frrManifestCapture(m, 1)["frr_version"] = "10.6.0" // r1 neighbor detail
				frrManifestCapture(m, 3)["frr_version"] = "10.6.0" // r2 neighbor detail
			})
		}, "not analyzed: unmapped neighbor records 0, refused captures 2."},
		{"unmapped neighbor records", func(t *testing.T, dir, _ string) {
			for _, s := range []struct{ file, iface string }{{"r1-interface.json", "e1"}, {"r2-interface.json", "e2"}} {
				editFRRJSON(t, filepath.Join(dir, s.file), func(m map[string]any) {
					delete(m["interfaces"].(map[string]any)[s.iface].(map[string]any), "routerId")
				})
			}
		}, "not analyzed: unmapped neighbor records 2, refused captures 0."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, manifest := stageFRRBcast(t)
			c.edit(t, dir, manifest)
			code, findings := importOSPFFindings(t, manifest)
			if code != 1 || findings != nil {
				t.Fatalf("exit %d, findings %+v; want 1 and no ospf key", code, findings)
			}
			code, text, _ := runNetdoc(t, "--import-frr-ospf", manifest)
			if code != 1 {
				t.Fatalf("text exit %d, want 1", code)
			}
			want := "\nOSPF (from recorded evidence for every node in the file; nothing was probed):\n  no finding from the accepted captures\n  " + c.notAnalyzed + " They wrote no evidence, so what they report is unknown here, not absent.\n"
			block := strings.Index(text, want)
			if block < 0 || block < strings.Index(text, "\nNeighbor records") || block > strings.Index(text, "\nNot imported:") {
				t.Errorf("text lacks %q between the neighbor records and the not-imported list:\n%s", want, text)
			}
			if !strings.Contains(text, "Result: incomplete.") {
				t.Errorf("text does not say the import is incomplete:\n%s", text)
			}
		})
	}
}
