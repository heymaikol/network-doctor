// The remediation table: that advice follows the diagnosis rather than the
// first failed row, that a stable cause narrows it, that the commands stay
// safe and read-only on every OS, and that the ambiguous conclusions keep
// saying what to investigate instead of naming a culprit.

package diagnostic

import (
	"go/ast"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestRemediationFollowsTheDiagnosisFocus is the property that makes this a
// view of the diagnosis rather than a second opinion: every arm that reaches a
// finding gets advice, every arm that reaches none gets silence, and the
// advice chosen is the one keyed by that finding's own identity and the cause
// on the row it focuses. An arm that blamed the first failed row instead would
// fail here on the outage cases, where QUIC and the encrypted resolver fail
// early in probe order while the prose blames something else.
func TestRemediationFollowsTheDiagnosisFocus(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			rem, ok := Remediate(d, c.res, "linux")
			if len(d.Findings) == 0 {
				if ok {
					t.Fatalf("a run with no finding was given advice %q", rem.ID)
				}
				return
			}
			if !ok {
				t.Fatalf("finding %q reached no remediation", d.Findings[0].ID)
			}
			focus := d.Findings[0].Focus
			want, found := remedies[remedyKey{id: d.Findings[0].ID, cause: c.res[focus].Cause}]
			if !found {
				want = remedies[remedyKey{id: d.Findings[0].ID}]
			}
			if rem.ID != want.id {
				t.Errorf("finding %q (focus %q, cause %q) got %q, want %q",
					d.Findings[0].ID, focus, c.res[focus].Cause, rem.ID, want.id)
			}
			if rem.Action == "" {
				t.Errorf("remediation %q has no action", rem.ID)
			}
		})
	}
}

// TestEveryDiagnosisIDHasRemediation keeps the two vocabularies in step. A
// conclusion netdoc is willing to publish is one it should be able to say
// something about, and the alternative is a user reading a specific diagnosis
// with a blank space where the next step belongs.
func TestEveryDiagnosisIDHasRemediation(t *testing.T) {
	for _, spec := range declaredConstants(t, "finding.go", "DiagnosisID") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := remedies[remedyKey{id: DiagnosisID(value)}]; !ok {
				t.Errorf("%s (%q) has no remediation", name.Name, value)
			}
		}
	}
}

// TestDistinctCausesGetDistinctRemediation is the reason the table is keyed by
// cause as well as conclusion: one dead direct path is four different things
// to go and do, and the routing tables already said which. An unrecognized
// cause must keep the conclusion's general answer rather than losing the
// advice entirely.
func TestDistinctCausesGetDistinctRemediation(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	tests := []struct {
		cause string
		want  RemediationID
	}{
		{RouteCauseNoDefaultRoute, RemedyRestoreDefaultRoute},
		{RouteCauseGatewayUnreachable, RemedyReachGateway},
		{RouteCauseSelectedPathFailed, RemedyCheckUpstream},
		{RouteCausePreferredPathFailed, RemedyFixPreferredRoute},
		{"", RemedyCheckLocalPath},
		{"a_cause_from_a_later_release", RemedyCheckLocalPath},
	}
	for _, tt := range tests {
		res := map[ProbeID]ProbeResult{
			ProbeIface:    {Status: StatusPass},
			ProbeInternet: {Status: StatusFail, Cause: tt.cause},
			ProbeDNS:      {Status: StatusFail},
		}
		d := Interpret(nil, order, res)
		if d.Findings[0].ID != DiagnosisOffline {
			t.Fatalf("cause %q changed the diagnosis to %q", tt.cause, d.Findings[0].ID)
		}
		rem, ok := Remediate(d, res, "linux")
		if !ok || rem.ID != tt.want {
			t.Errorf("offline with cause %q = %q (ok=%v), want %q", tt.cause, rem.ID, ok, tt.want)
		}
	}

	// A degraded family is a cause on the same row under a different
	// conclusion, and each family names its own missing half.
	for _, tt := range []struct {
		cause string
		want  RemediationID
	}{
		{FamilyCauseIPv4Unreachable, RemedyRestoreIPv4},
		{FamilyCauseIPv6Unreachable, RemedyRestoreIPv6},
		{"", RemedyReadEgressWarning},
	} {
		res := map[ProbeID]ProbeResult{
			ProbeIface:    {Status: StatusPass},
			ProbeInternet: {Status: StatusWarn, Cause: tt.cause},
			ProbeDNS:      {Status: StatusPass},
		}
		d := Interpret(nil, order, res)
		if d.Findings[0].ID != DiagnosisDirectEgressDegraded {
			t.Fatalf("cause %q changed the diagnosis to %q", tt.cause, d.Findings[0].ID)
		}
		if rem, ok := Remediate(d, res, "linux"); !ok || rem.ID != tt.want {
			t.Errorf("degraded egress with cause %q = %q (ok=%v), want %q", tt.cause, rem.ID, ok, tt.want)
		}
	}
}

// TestRemediationPicksThePlatformCommand walks the per-OS table from one OS,
// which is why goos is a parameter rather than runtime.GOOS. An OS with no
// entry of its own falls back to the default branch, exactly as the fix hints
// do.
func TestRemediationPicksThePlatformCommand(t *testing.T) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute},
		ProbeDNS:      {Status: StatusFail},
	}
	d := Interpret(nil, []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}, res)
	tests := []struct {
		goos string
		want []string
	}{
		{"linux", []string{"ip", "route"}},
		{"darwin", []string{"netstat", "-rn"}},
		{"windows", []string{"route", "print", "-4"}},
		{"openbsd", []string{"ip", "route"}}, // no entry: the default branch
	}
	for _, tt := range tests {
		rem, ok := Remediate(d, res, tt.goos)
		if !ok || !slices.Equal(rem.Command, tt.want) {
			t.Errorf("%s command = %q, want %q", tt.goos, rem.Command, tt.want)
		}
		if got := rem.CommandLine(); got != strings.Join(tt.want, " ") {
			t.Errorf("%s command line = %q", tt.goos, got)
		}
	}
}

// TestRemediationWithoutACommand pins the other half of the contract: prose
// alone where nothing local is worth inspecting. A command invented to fill
// the field would be one more thing for a reader to run for no reason.
func TestRemediationWithoutACommand(t *testing.T) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusPass, Portal: &Portal{RedirectURL: "http://portal.example/login"}},
		ProbeDNS:      {Status: StatusPass},
	}
	d := Interpret(nil, []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}, res)
	rem, ok := Remediate(d, res, "linux")
	if !ok || rem.ID != RemedySignInToPortal {
		t.Fatalf("captive portal remediation = %q (ok=%v)", rem.ID, ok)
	}
	if len(rem.Command) != 0 || rem.CommandLine() != "" {
		t.Errorf("signing in to a portal needs no command, got %q", rem.Command)
	}
	if len(rem.Steps) == 0 || rem.Action == "" {
		t.Error("a remediation with no command still has to say what to do")
	}
}

// TestRemediationCommandsAreSafe holds the whole table to what a diagnostic
// tool may suggest: an argv rather than a shell string, no privilege
// escalation, and nothing that writes. netdoc never runs these, but it puts
// them in front of a person who might, so a destructive one would be a
// destructive one shipped.
func TestRemediationCommandsAreSafe(t *testing.T) {
	// Read-only inspection commands only. Adding a binary here is a decision
	// to be made deliberately, which is the point of the list.
	readOnly := []string{"ip", "ifconfig", "netstat", "arp", "route", "netsh", "cat", "scutil", "ipconfig", "timedatectl", "date", "w32tm"}
	escalation := []string{"sudo", "doas", "su", "runas", "pkexec", "gsudo"}
	// The subcommands that turn a read-only binary into a writing one. "ip
	// route" reads; "ip route add" does not.
	writes := []string{"add", "del", "delete", "set", "flush", "replace", "change"}
	for key, r := range remedies {
		for goos, args := range r.command {
			what := string(r.id) + " on " + goos + " (" + string(key.id) + "/" + key.cause + ")"
			if len(args) == 0 {
				t.Errorf("%s: empty command", what)
				continue
			}
			if !slices.Contains(readOnly, args[0]) {
				t.Errorf("%s: %q is not a known read-only command", what, args[0])
			}
			if slices.Contains(escalation, args[0]) {
				t.Errorf("%s: escalates privilege", what)
			}
			for _, arg := range args[1:] {
				if slices.Contains(writes, arg) {
					t.Errorf("%s: %q modifies configuration", what, arg)
				}
			}
			for _, arg := range args {
				if arg == "" {
					t.Errorf("%s: empty argument", what)
				}
				// A shell metacharacter would mean the argv was really a shell
				// string in disguise, and a space would make CommandLine's
				// rendering ambiguous.
				if strings.ContainsAny(arg, " \t;|&$><`\n\"'\\") {
					t.Errorf("%s: argument %q is not a plain argv element", what, arg)
				}
			}
		}
	}
}

// TestAmbiguousDiagnosesStayCautious pins the conclusions netdoc cannot narrow
// down to advice that investigates rather than advice that accuses. Getting
// this wrong is worse than saying nothing: it sends someone to replace a
// certificate over a clock, or to blame a resolver the run never tested.
func TestAmbiguousDiagnosesStayCautious(t *testing.T) {
	tests := []struct {
		id   DiagnosisID
		want RemediationID
	}{
		// No second opinion separated a broken resolver from a missing name,
		// so this must not become "fix your resolver".
		{DiagnosisDNSFailure, RemedyCheckResolution},
		// The handshake produced no cause the client could classify.
		{DiagnosisTLSHandshakeFailure, RemedyNarrowTLSFailure},
		// The selection left out the checks that would blame one end.
		{DiagnosisReachabilityUntested, RemedyRerunWithEgress},
		// Split DNS is usually deliberate, so this is a question, not a fix.
		{DiagnosisDNSDisagreement, RemedyConfirmSplitDNS},
	}
	for _, tt := range tests {
		r, ok := remedies[remedyKey{id: tt.id}]
		if !ok || r.id != tt.want {
			t.Fatalf("%q = %q (ok=%v), want %q", tt.id, r.id, ok, tt.want)
		}
		// The cautious ones have to leave the alternatives standing in prose.
		// A rewrite that names one cause takes the hedge out with it.
		hedges := []string{"still possible", "cannot", "may", "both", "usually", "or "}
		if !slices.ContainsFunc(hedges, func(h string) bool { return strings.Contains(r.why, h) }) {
			t.Errorf("%q states a single cause as fact: %q", tt.id, r.why)
		}
		if len(r.steps) == 0 {
			t.Errorf("%q says nothing about what to investigate", tt.id)
		}
	}
}

// TestRemediationDoesNotHandOutTheTable: a caller mutating what it was given
// must not rewrite the advice every later run gets.
func TestRemediationDoesNotHandOutTheTable(t *testing.T) {
	res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusFail}}
	d := Interpret(nil, []ProbeID{ProbeIface}, res)
	first, ok := Remediate(d, res, "linux")
	if !ok || len(first.Steps) == 0 || len(first.Command) == 0 {
		t.Fatal("the link-down remediation should carry steps and a command")
	}
	first.Steps[0] = "mutated"
	first.Command[0] = "mutated"
	second, _ := Remediate(d, res, "linux")
	if second.Steps[0] == "mutated" || second.Command[0] == "mutated" {
		t.Error("Remediate returned the table's own slices")
	}
}

// TestRemediationIDsAreStableAndDocumented mirrors the guard on the diagnosis
// vocabulary: the values are a JSON contract, they have to be unique, and a
// contract nobody wrote down is one users discover by reading source.
func TestRemediationIDsAreStableAndDocumented(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	for _, spec := range declaredConstants(t, "remediation.go", "RemediationID") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			if held, dup := declared[value]; dup {
				t.Errorf("%s and %s share the value %q", held, name.Name, value)
			}
			declared[value] = name.Name
			if !stableIDRe.MatchString(value) {
				t.Errorf("%s (%q) is not a stable lower_snake_case id", name.Name, value)
			}
			if !strings.Contains(string(docs), "`"+value+"`") {
				t.Errorf("%s (%q) is not documented in docs/reference.md", name.Name, value)
			}
		}
	}
	// Every declared id has to be reachable, and every id the table uses has to
	// be declared: an unreachable constant is advice nobody can get, and an
	// undeclared one is a value the docs guard above never sees.
	used := map[string]bool{}
	for _, r := range remedies {
		used[string(r.id)] = true
		if _, ok := declared[string(r.id)]; !ok {
			t.Errorf("the table uses %q, which is not a declared RemediationID", r.id)
		}
	}
	for value, name := range declared {
		if !used[value] {
			t.Errorf("%s (%q) is declared but no table entry produces it", name, value)
		}
	}
}

func TestGatewayRemediationKeepsConfiguredAlternateContext(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, competing := range []bool{false, true} {
			t.Run(family+strconv.FormatBool(competing), func(t *testing.T) {
				route := RouteDecision{Destination: net.ParseIP("1.1.1.1"), Family: family}
				if competing {
					route.Competing = []CompetingRoute{{Iface: "eth1", Metric: 200}}
				}
				res := map[ProbeID]ProbeResult{
					ProbeIface:    {Status: StatusPass, Routes: []RouteDecision{route}},
					ProbeInternet: {Status: StatusFail, Cause: RouteCauseGatewayUnreachable, causeFamily: "ipv4"},
				}
				d := Diagnosis{Findings: []DiagnosisFinding{{ID: DiagnosisLocalEgressFailure, Focus: ProbeInternet}}}
				rem, ok := Remediate(d, res, "linux")
				if !ok {
					t.Fatal("missing remediation")
				}
				text := strings.Join(rem.Steps, " ")
				want := competing && family == "ipv4"
				if strings.Contains(text, "Another default route is configured") != want {
					t.Fatalf("alternate context = %q, want present=%v", text, want)
				}
				if want && !strings.Contains(text, "does not prove it works") {
					t.Fatal("alternate route advice lost its uncertainty")
				}
				stored := BuildSnapshot(nil, []Probe{{ID: ProbeIface}}, res)
				restored, err := replayResult(ProbeIface, StatusPass, stored.Checks[0])
				if err != nil {
					t.Fatal(err)
				}
				res[ProbeIface] = restored
				replayRem, ok := Remediate(d, res, "linux")
				if !ok || !reflect.DeepEqual(rem, replayRem) {
					t.Fatalf("replayed route context changed remediation: %+v", replayRem)
				}
			})
		}
	}
	for _, cause := range []string{RouteCauseSelectedPathFailed, RouteCausePreferredPathFailed} {
		if _, ok := remedies[remedyKey{id: DiagnosisLocalEgressFailure, cause: cause}]; ok {
			t.Fatalf("dead remediation key for %s", cause)
		}
		if _, ok := remedies[remedyKey{id: DiagnosisOffline, cause: cause}]; !ok {
			t.Fatalf("lost reachable offline remediation for %s", cause)
		}
	}
}
