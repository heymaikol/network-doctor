package diagnostic

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// declaredConstants reads the declarations because Go has no runtime enum
// inventory. This keeps the regression check independent of another hand-kept
// list of protocols, statuses, or probe IDs.
func declaredConstants(t *testing.T, filename, typeName string) []*ast.ValueSpec {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declared []*ast.ValueSpec
	for _, decl := range f.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		active := false
		for _, raw := range group.Specs {
			spec := raw.(*ast.ValueSpec)
			if name, ok := spec.Type.(*ast.Ident); ok {
				active = name.Name == typeName
			} else if len(spec.Values) > 0 {
				active = false
			}
			if active {
				declared = append(declared, spec)
			}
		}
	}
	if len(declared) == 0 {
		t.Fatalf("no %s constants found", typeName)
	}
	return declared
}

func declaredIotaLen(t *testing.T, filename, typeName string) int {
	t.Helper()
	specs := declaredConstants(t, filename, typeName)
	if len(specs[0].Names) != 1 || len(specs[0].Values) != 1 {
		t.Fatalf("first %s constant is not iota", typeName)
	}
	iotaExpr, ok := specs[0].Values[0].(*ast.Ident)
	if !ok || iotaExpr.Name != "iota" {
		t.Fatalf("first %s constant is not iota", typeName)
	}
	for _, spec := range specs[1:] {
		if len(spec.Names) != 1 || len(spec.Values) != 0 {
			t.Fatalf("%s must remain a contiguous iota enum", typeName)
		}
	}
	return len(specs)
}

func declaredProbeIDs(t *testing.T) map[ProbeID]struct{} {
	t.Helper()
	ids := map[ProbeID]struct{}{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}
			typeName, ok := spec.Type.(*ast.Ident)
			if !ok || typeName.Name != "ProbeID" {
				return true
			}
			for i, name := range spec.Names {
				if i >= len(spec.Values) {
					t.Fatalf("%s has no explicit stable probe ID", name.Name)
				}
				literal, ok := spec.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				id := ProbeID(value)
				if _, duplicate := ids[id]; duplicate {
					t.Fatalf("duplicate declared probe ID %q", id)
				}
				ids[id] = struct{}{}
			}
			return true
		})
	}
	return ids
}

func TestEnumNameTablesCoverDeclarations(t *testing.T) {
	if got := declaredIotaLen(t, "target.go", "Proto"); got != len(protoNames) {
		t.Errorf("%d Proto constants, but %d names", got, len(protoNames))
	}
	if got := declaredIotaLen(t, "checks.go", "Status"); got != len(statusNames) {
		t.Errorf("%d Status constants, but %d names", got, len(statusNames))
	}
}

func TestSelectableProbeIDsCoverDeclaredProbeIDs(t *testing.T) {
	declared := declaredProbeIDs(t)
	selected := map[ProbeID]struct{}{}
	for _, id := range selectableProbeIDs() {
		if _, duplicate := selected[id]; duplicate {
			t.Errorf("selectable probe ID %q is duplicated", id)
		}
		selected[id] = struct{}{}
		if _, ok := declared[id]; !ok {
			t.Errorf("selectable probe ID %q has no ProbeID constant", id)
		}
	}
	for id := range declared {
		if _, ok := selected[id]; !ok {
			t.Errorf("declared probe ID %q is not selectable", id)
		}
	}
}

// probeRowNameHost stands in for the target in a row name. It never resolves,
// and building the DAG names rows without probing anything.
const probeRowNameHost = "example.invalid"

// The row names are a published contract: docs/reference.md tabulates them, the
// wiki repeats them, and people write them into runbooks and bug reports.
// Renaming one is a documentation change, so it has to be a deliberate edit
// here rather than a side effect of touching the probe beside it. Only the
// names are pinned; what each probe reports is its own tests' business.
func TestStableProbeRowNames(t *testing.T) {
	// The rows a generic run shows, whose names carry no target at all.
	generic := map[ProbeID]string{
		ProbeIface:        "Interface",
		ProbeInternet:     "Internet (TCP egress)",
		ProbeQUIC:         "QUIC / UDP 443",
		ProbeProxy:        "Internet (env proxy)",
		ProbeDNS:          "DNS",
		ProbeDNSPublic:    "DNS (public)",
		ProbeDNSEncrypted: "DNS (encrypted DoH/DoT)",
		ProbeSSID:         "Wi-Fi network",
	}
	// The rows a target adds, plus the DNS row a target renames. Everything
	// else keeps the generic name.
	targeted := map[ProbeID]string{
		ProbeDNS:       "DNS " + probeRowNameHost,
		ProbeTargetTCP: "TCP " + probeRowNameHost + ":443",
		ProbePMTU:      "Path MTU " + probeRowNameHost + ":443",
		ProbeTLS:       "TLS " + probeRowNameHost,
		ProbeHTTP:      "HTTP " + probeRowNameHost,
		ProbeHTTPS:     "HTTPS " + probeRowNameHost,
		ProbeSSH:       "SSH banner " + probeRowNameHost + ":443",
		ProbeSMTP:      "SMTP banner " + probeRowNameHost + ":443",
	}
	withTarget := map[ProbeID]string{}
	for id, name := range generic {
		withTarget[id] = name
	}
	for id, name := range targeted {
		withTarget[id] = name
	}

	seen := map[ProbeID]struct{}{}
	check := func(probes []Probe, want map[ProbeID]string) {
		for _, p := range probes {
			name, ok := want[p.ID]
			if !ok {
				t.Errorf("probe %q shows row name %q that no documented name is pinned to", p.ID, p.Name)
				continue
			}
			seen[p.ID] = struct{}{}
			if p.Name != name {
				t.Errorf("probe %q row name = %q, want %q; the documentation names this row", p.ID, p.Name, name)
			}
		}
	}
	// Naming rows runs no probe, so an empty seam is all the DAG needs here.
	o := &netops{}
	check(o.buildProbes(nil, DefaultPublicDNS, true), generic)
	for proto := range protoNames {
		check(o.buildProbes(&Target{Host: probeRowNameHost, Port: 443, Proto: Proto(proto)}, DefaultPublicDNS, true), withTarget)
	}

	// A pinned name no DAG produces any more is a name that moved without this
	// test noticing.
	for id := range withTarget {
		if _, ok := seen[id]; !ok {
			t.Errorf("no probe shows the pinned row name for %q any more", id)
		}
	}
	for _, id := range selectableProbeIDs() {
		if _, ok := seen[id]; !ok {
			t.Errorf("selectable probe %q has no pinned row name", id)
		}
	}
}

func probeSet(ids ...ProbeID) map[ProbeID]struct{} {
	set := make(map[ProbeID]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func selectedIDs(probes []Probe) []ProbeID {
	ids := make([]ProbeID, len(probes))
	for i, p := range probes {
		ids[i] = p.ID
	}
	return ids
}

func TestProbeSelection(t *testing.T) {
	target, err := ParseTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	probes := BuildProbesFromSources(target, nil, DefaultPublicDNS, true)
	tests := []struct {
		name       string
		selection  ProbeSelection
		want       []ProbeID
		wantAbsent []ProbeID
	}{
		{
			name:      "one check includes prerequisites",
			selection: ProbeSelection{Check: probeSet(ProbeTLS)},
			want:      []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP, ProbeTLS},
		},
		{
			name:      "multiple checks use canonical order",
			selection: ProbeSelection{Check: probeSet(ProbeTLS, ProbeDNS, ProbeTargetTCP)},
			want:      []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP, ProbeTLS},
		},
		{
			name:       "one skip",
			selection:  ProbeSelection{Skip: probeSet(ProbeQUIC)},
			wantAbsent: []ProbeID{ProbeQUIC},
		},
		{
			name:       "multiple skips",
			selection:  ProbeSelection{Skip: probeSet(ProbeInternet, ProbeQUIC)},
			wantAbsent: []ProbeID{ProbeInternet, ProbeQUIC},
		},
		{
			name:      "skipped prerequisite removes dependent branch only",
			selection: ProbeSelection{Check: probeSet(ProbeTLS, ProbeQUIC), Skip: probeSet(ProbeDNS)},
			want:      []ProbeID{ProbeIface, ProbeQUIC},
		},
		{
			name:      "all requested branches blocked",
			selection: ProbeSelection{Check: probeSet(ProbeDNS, ProbeTargetTCP, ProbeTLS), Skip: probeSet(ProbeDNS)},
			want:      []ProbeID{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.selection.Apply(probes)
			if tt.want != nil && !reflect.DeepEqual(selectedIDs(got), tt.want) {
				t.Errorf("IDs = %v, want %v", selectedIDs(got), tt.want)
			}
			for _, absent := range tt.wantAbsent {
				for _, id := range selectedIDs(got) {
					if id == absent {
						t.Errorf("selected probes contain skipped %q", absent)
					}
				}
			}
		})
	}

	a := ProbeSelection{Check: probeSet(ProbeTLS, ProbeDNS, ProbeTargetTCP)}.Apply(probes)
	b := ProbeSelection{Check: probeSet(ProbeDNS, ProbeTargetTCP, ProbeTLS)}.Apply(probes)
	if !reflect.DeepEqual(selectedIDs(a), selectedIDs(b)) {
		t.Errorf("check order changed probe order: %v != %v", selectedIDs(a), selectedIDs(b))
	}
}

func TestProbeSelectionGraphClosureAndPruning(t *testing.T) {
	const (
		root    ProbeID = "root"
		a       ProbeID = "a"
		x       ProbeID = "x"
		b       ProbeID = "b"
		left    ProbeID = "left"
		right   ProbeID = "right"
		diamond ProbeID = "diamond"
	)
	probes := []Probe{
		{ID: root},
		{ID: a, Deps: []ProbeID{root}},
		{ID: x, Deps: []ProbeID{a}},
		{ID: b, Deps: []ProbeID{root}},
		{ID: left, Deps: []ProbeID{root}},
		{ID: right, Deps: []ProbeID{root}},
		{ID: diamond, Deps: []ProbeID{left, right}},
	}
	tests := []struct {
		name string
		sel  ProbeSelection
		want []ProbeID
	}{
		{"deep dependency closure", ProbeSelection{Check: probeSet(x)}, []ProbeID{root, a, x}},
		{"diamond closure", ProbeSelection{Check: probeSet(diamond)}, []ProbeID{root, left, right, diamond}},
		{"blocked branch keeps shared root for viable branch", ProbeSelection{Check: probeSet(x, b), Skip: probeSet(a)}, []ProbeID{root, b}},
		{"skipped root blocks descendants", ProbeSelection{Check: probeSet(x, b), Skip: probeSet(root)}, []ProbeID{}},
		{"skip root without check", ProbeSelection{Skip: probeSet(root)}, []ProbeID{}},
		{"requested prerequisite", ProbeSelection{Check: probeSet(a)}, []ProbeID{root, a}},
		{"all requested branches blocked", ProbeSelection{Check: probeSet(x), Skip: probeSet(a)}, []ProbeID{}},
		{"dependency and descendant requested", ProbeSelection{Check: probeSet(a, x)}, []ProbeID{root, a, x}},
		{"broken diamond prunes unused sibling", ProbeSelection{Check: probeSet(diamond), Skip: probeSet(left)}, []ProbeID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectedIDs(tt.sel.Apply(probes)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IDs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmptyProbeSelectionPreservesBuiltDAG(t *testing.T) {
	probes := BuildProbesFromSources(mustTarget(t, "example.com"), nil, DefaultPublicDNS, true)
	got := (ProbeSelection{}).Apply(probes)
	if len(got) != len(probes) {
		t.Fatalf("probe count = %d, want %d", len(got), len(probes))
	}
	if &got[0] != &probes[0] {
		t.Fatal("empty policy copied the probe DAG")
	}
	for i := range probes {
		if got[i].ID != probes[i].ID || got[i].Name != probes[i].Name || !reflect.DeepEqual(got[i].Deps, probes[i].Deps) || reflect.ValueOf(got[i].Run).Pointer() != reflect.ValueOf(probes[i].Run).Pointer() {
			t.Fatalf("probe %d changed under empty policy: got %+v, want %+v", i, got[i], probes[i])
		}
	}
}

// ProbeInternet owns the direct-egress and captive-portal traffic. Keeping it
// out of the selected slice proves a narrow CI run cannot invoke either one.
func TestProbeSelectionDoesNotInvokeExcludedEgressOrPortalProbes(t *testing.T) {
	var mu sync.Mutex
	runs := map[ProbeID]int{}
	probe := func(id ProbeID, deps ...ProbeID) Probe {
		return Probe{ID: id, Deps: deps, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			mu.Lock()
			runs[id]++
			mu.Unlock()
			return ProbeResult{Status: StatusPass}
		}}
	}
	probes := []Probe{
		probe(ProbeIface),
		probe(ProbeInternet, ProbeIface),
		probe(ProbeQUIC, ProbeIface),
		probe(ProbeProxy, ProbeIface),
		probe(ProbeDNS, ProbeIface),
		probe(ProbeDNSPublic, ProbeIface),
		probe(ProbeDNSEncrypted, ProbeIface),
		probe(ProbeTargetTCP, ProbeDNS),
		probe(ProbePMTU, ProbeTargetTCP),
		probe(ProbeSSID, ProbeIface),
		probe(ProbeTLS, ProbeTargetTCP),
		probe(ProbeHTTP, ProbeDNS),
		probe(ProbeHTTPS, ProbeTLS),
	}
	selected := ProbeSelection{Check: probeSet(ProbeDNS, ProbeTargetTCP, ProbeTLS)}.Apply(probes)
	RunAll(context.Background(), selected, DefaultProbeTimeout)

	if got, want := selectedIDs(selected), []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP, ProbeTLS}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected IDs = %v, want %v", got, want)
	}
	for _, id := range []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP, ProbeTLS} {
		if runs[id] != 1 {
			t.Errorf("%s ran %d times, want 1", id, runs[id])
		}
	}
	for _, id := range []ProbeID{ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNSPublic, ProbeDNSEncrypted, ProbePMTU, ProbeSSID, ProbeHTTP, ProbeHTTPS} {
		if runs[id] != 0 {
			t.Errorf("excluded probe %s ran %d times", id, runs[id])
		}
	}

	runs = map[ProbeID]int{}
	selected = ProbeSelection{Check: probeSet(ProbeTLS, ProbeQUIC), Skip: probeSet(ProbeDNS)}.Apply(probes)
	RunAll(context.Background(), selected, DefaultProbeTimeout)
	if got, want := selectedIDs(selected), []ProbeID{ProbeIface, ProbeQUIC}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selection with skipped prerequisite = %v, want %v", got, want)
	}
	if runs[ProbeIface] != 1 || runs[ProbeQUIC] != 1 || runs[ProbeDNS] != 0 || runs[ProbeTargetTCP] != 0 || runs[ProbeTLS] != 0 {
		t.Errorf("runs after skipped prerequisite = %v", runs)
	}
}

func TestProbeSelectionValidation(t *testing.T) {
	for _, selection := range []ProbeSelection{
		{Check: probeSet("bogus")},
		{Skip: probeSet("bogus")},
	} {
		if err := selection.Validate(); err == nil {
			t.Fatal("unknown probe ID accepted")
		}
	}
	for _, selection := range []ProbeSelection{
		{Check: probeSet(ProbeTLS, ProbeSSH, ProbeSMTP)},
		{Skip: probeSet(ProbeDNSPublic)},
	} {
		if err := selection.Validate(); err != nil {
			t.Fatalf("known conditional probe rejected: %v", err)
		}
	}
	err1 := (ProbeSelection{Check: probeSet("zzz", "aaa")}).Validate()
	err2 := (ProbeSelection{Check: probeSet("aaa", "zzz")}).Validate()
	if err1 == nil || err2 == nil || err1.Error() != err2.Error() || !strings.Contains(err1.Error(), `unknown probe ID "aaa"`) {
		t.Fatalf("validation errors are not deterministic: %v / %v", err1, err2)
	}
}

func TestDiagnoseUnfilteredCompatibility(t *testing.T) {
	target := mustTarget(t, "example.com")
	targetProbes := BuildProbesFromSources(target, nil, DefaultPublicDNS, true)
	targetOrder := selectedIDs(targetProbes)
	targetResults := make(map[ProbeID]ProbeResult, len(targetOrder))
	for _, id := range targetOrder {
		targetResults[id] = ProbeResult{Status: StatusPass}
	}
	if d := Interpret(target, targetOrder, targetResults); d.Summary != "All checks passed. example.com:443 looks healthy." || d.Verdict != VerdictOK {
		t.Fatalf("full target all-clear = %q/%q", d.Summary, d.Verdict)
	}
	targetResults[ProbeQUIC] = ProbeResult{Status: StatusFail}
	targetResults[ProbeDNSPublic] = ProbeResult{Status: StatusWarn}
	if d := Interpret(target, targetOrder, targetResults); d.Summary != "The target and direct TCP/443 work, but the QUIC handshake over UDP/443 failed. Applications can fall back to TCP, which may feel slower." || d.Verdict != VerdictDegraded {
		t.Fatalf("full target precedence = %q/%q", d.Summary, d.Verdict)
	}

	genericProbes := BuildProbesFromSources(nil, nil, DefaultPublicDNS, true)
	genericOrder := selectedIDs(genericProbes)
	genericResults := make(map[ProbeID]ProbeResult, len(genericOrder))
	for _, id := range genericOrder {
		genericResults[id] = ProbeResult{Status: StatusPass}
	}
	if d := Interpret(nil, genericOrder, genericResults); d.Summary != "Online: direct TCP egress and DNS both work." || d.Verdict != VerdictOK {
		t.Fatalf("full generic all-clear = %q/%q", d.Summary, d.Verdict)
	}
}

func TestPMTUSelectionByProtocol(t *testing.T) {
	for _, raw := range []string{"host:9999", "host:443", "host:8443", "host:80", "host:22", "host:25", "host:587", "https://host:9999", "http://host:9999", "ssh://host:9999", "smtp://host:9999"} {
		for _, tc := range []struct {
			name        string
			check, skip []ProbeID
			want        bool
		}{
			{name: "default", want: raw != "host:9999"},
			{name: "explicit", check: []ProbeID{ProbePMTU}, want: true},
			{name: "combined", check: []ProbeID{ProbePMTU, ProbeTargetTCP}, want: true},
			{name: "tcp only", check: []ProbeID{ProbeTargetTCP}},
			{name: "skip", check: []ProbeID{ProbePMTU}, skip: []ProbeID{ProbePMTU}},
			{name: "skip prerequisite", check: []ProbeID{ProbePMTU}, skip: []ProbeID{ProbeTargetTCP}},
		} {
			t.Run(raw+"/"+tc.name, func(t *testing.T) {
				selection := ProbeSelection{Check: map[ProbeID]struct{}{}, Skip: map[ProbeID]struct{}{}, NoReferenceEgress: true}
				for _, id := range tc.check {
					selection.Check[id] = struct{}{}
				}
				for _, id := range tc.skip {
					selection.Skip[id] = struct{}{}
				}
				probes := selection.BuildProbesFromSources(mustTarget(t, raw), nil, DefaultPublicDNS, true)
				if got := slices.ContainsFunc(probes, func(p Probe) bool { return p.ID == ProbePMTU }); got != tc.want {
					t.Fatalf("PMTU selected = %t, want %t", got, tc.want)
				}
			})
		}
	}
}
