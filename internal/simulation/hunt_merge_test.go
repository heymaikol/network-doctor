package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestRunHuntShardsPartitionTheExistingGlobalStream(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
		for _, cases := range []int{1, 2, 7, 13, 60} {
			for _, shardCount := range []int{1, 2, 3, 4, 8} {
				t.Run(string(lane)+"_"+strconv.Itoa(cases)+"_cases_"+strconv.Itoa(shardCount)+"_shards", func(t *testing.T) {
					full := RunHunt(context.Background(), "healthy-routed-network", base, func() Backend {
						return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
					},
						HuntOptions{Cases: cases, Seed: 12345, MaxFaults: 2, Lane: lane, DryRun: false})
					want := make(map[int]GeneratedCaseManifest, len(full.Cases))
					for _, item := range full.Cases {
						want[item.Manifest.Case] = item.Manifest
					}
					got := make(map[int]GeneratedCaseManifest, len(full.Cases))
					shards := make([]*HuntResult, 0, shardCount)
					for index := 0; index < shardCount; index++ {
						shard := HuntShard{Index: index, Count: shardCount}
						result := RunHunt(context.Background(), "healthy-routed-network", base, func() Backend {
							return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
						},
							HuntOptions{Cases: cases, Seed: 12345, MaxFaults: 2, Lane: lane, DryRun: false, Shard: &shard})
						shards = append(shards, result)
						for _, item := range result.Cases {
							caseNumber := item.Manifest.Case
							if !shard.Includes(caseNumber) {
								t.Errorf("shard %d/%d executed global case %d", index, shardCount, caseNumber)
							}
							if _, exists := got[caseNumber]; exists {
								t.Errorf("global case %d appeared in more than one shard", caseNumber)
							}
							got[caseNumber] = item.Manifest
						}
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("shard union differs from unsharded stream:\ngot  %+v\nwant %+v", got, want)
					}
					merged, err := MergeHuntResults(shards...)
					if err != nil {
						t.Fatal(err)
					}
					if merged.Shard != nil || !reflect.DeepEqual(caseManifests(merged), caseManifests(full)) {
						t.Fatalf("merged cases differ:\ngot  %+v\nwant %+v", caseManifests(merged), caseManifests(full))
					}
				})
			}
		}
	}
}

func TestShardPreservesGlobalCaseReproductionIdentity(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	const caseNumber = 18
	const wantFingerprint = "03d8cb299ae4f698"
	// The same case under the generator before the promotion. Held next to the
	// current one because a generator version is part of case identity: v7
	// exists precisely so that adding an operator to a lane cannot move a v6
	// case, and this is the pair that says so on the smallest possible example.
	const wantVersion6Fingerprint = "306edad66d6aff47"
	direct := RunHunt(context.Background(), "healthy", base, nil,
		HuntOptions{Seed: 20260101, Case: intPointer(caseNumber), MaxFaults: 2, DryRun: true})
	shard := HuntShard{Index: caseNumber % 4, Count: 4}
	partition := RunHunt(context.Background(), "healthy", base, nil,
		HuntOptions{Cases: 24, Seed: 20260101, MaxFaults: 2, DryRun: true, Shard: &shard})
	i := slices.IndexFunc(partition.Cases, func(item HuntCaseResult) bool { return item.Manifest.Case == caseNumber })
	if i < 0 {
		t.Fatalf("global case %d was omitted from shard %d/%d", caseNumber, shard.Index, shard.Count)
	}
	if !reflect.DeepEqual(partition.Cases[i].Manifest, direct.Cases[0].Manifest) {
		t.Fatalf("sharding changed global case %d:\n%+v\n%+v", caseNumber,
			partition.Cases[i].Manifest, direct.Cases[0].Manifest)
	}
	if got := direct.Cases[0].Manifest.CaseFingerprint; got != wantFingerprint {
		t.Fatalf("global case %d fingerprint = %s, want %s", caseNumber, got, wantFingerprint)
	}
	previous := RunHunt(context.Background(), "healthy", base, nil,
		HuntOptions{Seed: 20260101, Case: intPointer(caseNumber), MaxFaults: 2, DryRun: true, GeneratorVersion: "v6"})
	if got := previous.Cases[0].Manifest.CaseFingerprint; got != wantVersion6Fingerprint {
		t.Fatalf("global case %d under v6 fingerprint = %s, want %s", caseNumber, got, wantVersion6Fingerprint)
	}
	if !reflect.DeepEqual(mutationIDs(previous.Cases[0].Manifest), mutationIDs(direct.Cases[0].Manifest)) {
		t.Fatalf("v6 and v7 disagree on a case neither promotion touches:\n%+v\n%+v",
			previous.Cases[0].Manifest, direct.Cases[0].Manifest)
	}
}

// mutationIDs is the operator vocabulary of one manifest, which is the part of
// case identity a lane change could move.
func mutationIDs(manifest GeneratedCaseManifest) []string {
	out := make([]string, 0, len(manifest.Mutations))
	for _, mutation := range manifest.Mutations {
		out = append(out, mutation.ID)
	}
	return out
}

func TestHistoricalGeneratorVersionSurvivesShardsAndMerge(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	var shards []*HuntResult
	for index := 0; index < 2; index++ {
		shard := HuntShard{Index: index, Count: 2}
		result := RunHunt(context.Background(), "healthy-routed-network", base, nil,
			HuntOptions{Cases: 7, Seed: 12345, MaxFaults: 2, GeneratorVersion: "v3", DryRun: true, Shard: &shard})
		if result.GeneratorVersion != "v3" {
			t.Fatalf("shard %d generator = %q", index, result.GeneratorVersion)
		}
		for _, item := range result.Cases {
			if item.Manifest.GeneratorVersion != "v3" {
				t.Fatalf("shard %d case %d generator = %q", index, item.Manifest.Case, item.Manifest.GeneratorVersion)
			}
		}
		shards = append(shards, result)
	}
	merged, err := MergeHuntResults(shards...)
	if err != nil {
		t.Fatal(err)
	}
	if merged.GeneratorVersion != "v3" {
		t.Fatalf("merged generator = %q", merged.GeneratorVersion)
	}
	historical := cloneHuntResult(t, merged)
	historical.Lane = ""
	if err := ValidateMergedHuntResult(historical); err != nil {
		t.Fatalf("historical result with missing lane metadata no longer validates: %v", err)
	}
	if got := reproductionFor(historical.Cases[0].Manifest).Command(); !strings.Contains(got, "--lane all") {
		t.Errorf("historical reproduction = %q, want explicit all-operator lane", got)
	}
}

func TestMergedShardsAreSemanticallyEquivalentToARealUnshardedHunt(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	backend := func() Backend {
		return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
	}
	opts := HuntOptions{Cases: 24, Seed: 20260101, MaxFaults: 2, Run: Options{Netdoc: "netdoc"}}
	full := RunHunt(context.Background(), "healthy", base, backend, opts)
	if len(full.Findings) == 0 {
		t.Fatal("unsharded hunt produced no findings, so finding equivalence was not exercised")
	}
	var shards []*HuntResult
	for index := 0; index < 3; index++ {
		shard := HuntShard{Index: index, Count: 3}
		shardOpts := opts
		shardOpts.Shard = &shard
		shards = append(shards, RunHunt(context.Background(), "healthy", base, backend, shardOpts))
	}
	merged, err := MergeHuntResults(shards...)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(huntSemanticResult(merged), huntSemanticResult(full)) {
		got, _ := json.MarshalIndent(huntSemanticResult(merged), "", "  ")
		want, _ := json.MarshalIndent(huntSemanticResult(full), "", "  ")
		t.Fatalf("merged hunt differs from unsharded hunt:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestMergeHuntResultsRejectsIncompleteAndIncompatibleInputs(t *testing.T) {
	shards := dryHuntShards(t, 7, 3)
	nonempty := slices.IndexFunc(shards, func(result *HuntResult) bool { return len(result.Cases) > 0 })
	other := (nonempty + 1) % len(shards)
	if len(shards[other].Cases) == 0 {
		other = (other + 1) % len(shards)
	}
	if nonempty < 0 || len(shards[other].Cases) == 0 {
		t.Fatal("test setup needs two nonempty shards")
	}

	tests := []struct {
		name string
		edit func([]*HuntResult) []*HuntResult
		want string
	}{
		{"duplicate shard", func(in []*HuntResult) []*HuntResult {
			return append(in, cloneHuntResult(t, in[0]))
		}, "duplicate shard"},
		{"missing shard", func(in []*HuntResult) []*HuntResult { return in[1:] }, "missing shard"},
		{"duplicate global case", func(in []*HuntResult) []*HuntResult {
			in[nonempty].Cases = append(in[nonempty].Cases, in[other].Cases[0])
			in[nonempty].GeneratedCases++
			in[nonempty].UniqueCases++
			return in
		}, "duplicate global case"},
		{"missing expected case", func(in []*HuntResult) []*HuntResult {
			last := len(in[nonempty].Cases) - 1
			in[nonempty].Cases = in[nonempty].Cases[:last]
			in[nonempty].GeneratedCases--
			in[nonempty].UniqueCases--
			return in
		}, "missing expected cases"},
		{"seed", func(in []*HuntResult) []*HuntResult { in[1].HuntSeed++; return in }, "hunt seed"},
		{"case total", func(in []*HuntResult) []*HuntResult { in[1].RequestedCases++; return in }, "requested cases"},
		{"shard count", func(in []*HuntResult) []*HuntResult { in[1].Shard.Count++; return in }, "shard count"},
		{"generator", func(in []*HuntResult) []*HuntResult {
			in[1].GeneratorVersion, in[1].Lane = "v4", HuntLaneAllOperators
			return in
		}, "generator version"},
		{"lane", func(in []*HuntResult) []*HuntResult { in[1].Lane = HuntLaneStress; return in }, "hunt lane"},
		{"missing current lane", func(in []*HuntResult) []*HuntResult { in[0].Lane = ""; return in }, "no lane metadata"},
		{"missing generator", func(in []*HuntResult) []*HuntResult { in[0].GeneratorVersion = ""; return in }, "unknown hunt generator version"},
		{"baseline", func(in []*HuntResult) []*HuntResult { in[1].BaseScenario = "healthy"; return in }, "base scenario"},
		{"fault ceiling", func(in []*HuntResult) []*HuntResult { in[1].MaxFaults = 1; return in }, "max faults"},
		{"dry run", func(in []*HuntResult) []*HuntResult { in[1].DryRun = false; return in }, "dry-run setting"},
		{"fail fast", func(in []*HuntResult) []*HuntResult { in[1].FailFast = true; return in }, "fail-fast setting"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := cloneHuntResults(t, shards)
			if _, err := MergeHuntResults(test.edit(inputs)...); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("MergeHuntResults error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMergeHuntResultsPropagatesShardRuntimeFailure(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	var shards []*HuntResult
	for index := 0; index < 2; index++ {
		shard := HuntShard{Index: index, Count: 2}
		shards = append(shards, RunHunt(context.Background(), "healthy-routed-network", base, func() Backend {
			return &fakeBackend{caps: Capabilities{Backend: "fake", Reason: "cannot build topology"}}
		}, HuntOptions{Cases: 4, Seed: 7, MaxFaults: 1, Shard: &shard, Run: Options{Netdoc: "netdoc"}}))
	}
	merged, err := MergeHuntResults(shards...)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Result != HuntResultError || !merged.RuntimeFailure ||
		!strings.Contains(merged.Error, "shard 0/2") || !strings.Contains(merged.Error, "shard 1/2") {
		t.Fatalf("merged failure = %+v", merged)
	}
}

func TestMergeHuntResultsDoesNotHideAnErrorBehindCancellation(t *testing.T) {
	shards := dryHuntShards(t, 4, 2)
	shards[0].Result, shards[0].Cancelled = HuntResultCancelled, true
	shards[1].Result, shards[1].RuntimeFailure = HuntResultError, true
	shards[1].ErrorKind, shards[1].Error = "runtime", "netdoc failed"
	merged, err := MergeHuntResults(shards...)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Result != HuntResultError || !merged.Cancelled || !merged.RuntimeFailure {
		t.Fatalf("merged failure = %+v", merged)
	}
}

func TestMergeHuntResultsIsDeterministicAcrossInputOrder(t *testing.T) {
	shards := dryHuntShards(t, 11, 4)
	forward, err := MergeHuntResults(shards...)
	if err != nil {
		t.Fatal(err)
	}
	reversed := slices.Clone(shards)
	slices.Reverse(reversed)
	backward, err := MergeHuntResults(reversed...)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(forward)
	b, _ := json.Marshal(backward)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("merge depends on input order:\n%s\n%s", a, b)
	}
}

func TestMergeHuntResultsAcceptsEmptyAndSingleShards(t *testing.T) {
	for _, test := range []struct {
		cases, shards int
	}{
		{1, 3},
		{5, 1},
	} {
		inputs := dryHuntShards(t, test.cases, test.shards)
		if test.shards > test.cases && !slices.ContainsFunc(inputs, func(result *HuntResult) bool { return len(result.Cases) == 0 }) {
			t.Fatal("test setup did not produce an empty valid shard")
		}
		merged, err := MergeHuntResults(inputs...)
		if err != nil {
			t.Fatalf("merge %d cases over %d shards: %v", test.cases, test.shards, err)
		}
		if len(merged.Cases) != test.cases {
			t.Fatalf("merged %d cases, want %d", len(merged.Cases), test.cases)
		}
	}
}

func dryHuntShards(t *testing.T, cases, count int) []*HuntResult {
	t.Helper()
	base := loadHuntBase(t, "healthy-routed-network")
	results := make([]*HuntResult, 0, count)
	for index := 0; index < count; index++ {
		shard := HuntShard{Index: index, Count: count}
		results = append(results, RunHunt(context.Background(), "healthy-routed-network", base, nil,
			HuntOptions{Cases: cases, Seed: 12345, MaxFaults: 2, DryRun: true, Shard: &shard}))
	}
	return results
}

func cloneHuntResults(t *testing.T, inputs []*HuntResult) []*HuntResult {
	t.Helper()
	out := make([]*HuntResult, len(inputs))
	for i, input := range inputs {
		out[i] = cloneHuntResult(t, input)
	}
	return out
}

func cloneHuntResult(t *testing.T, input *HuntResult) *HuntResult {
	t.Helper()
	blob, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var out HuntResult
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func caseManifests(result *HuntResult) []GeneratedCaseManifest {
	out := make([]GeneratedCaseManifest, len(result.Cases))
	for i, item := range result.Cases {
		out[i] = item.Manifest
	}
	return out
}

func huntSemanticResult(result *HuntResult) HuntResult {
	out := *result
	out.Cases = append([]HuntCaseResult(nil), result.Cases...)
	for i := range out.Cases {
		out.Cases[i].Report = nil
	}
	out.Shard = nil
	return out
}

func intPointer(value int) *int { return &value }

// TestLargestGeneratedHuntShardFitsTheIngestionBudget is a regression check on
// headroom, not the reason the budget is safe: the ceilings are enforced where
// each section is built, and this measures how much of them a real hunt spends.
// Every base and both released lanes run at HuntMaxCases and HuntMaxFaults with
// a shard count of one, which is the widest legal shard, one shard owning every
// requested case. A generator change that starts crowding a ceiling shows up
// here as a number rather than as a truncated report in production.
func TestLargestGeneratedHuntShardFitsTheIngestionBudget(t *testing.T) {
	shard := HuntShard{Index: 0, Count: 1}
	worstResult, worstCase := 0, 0
	for _, name := range HuntBaseNames() {
		base := loadHuntBase(t, name)
		for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
			result := RunHunt(context.Background(), name, base, func() Backend {
				return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
			}, HuntOptions{Cases: HuntMaxCases, Seed: 12345, MaxFaults: HuntMaxFaults, Lane: lane, Shard: &shard})
			if len(result.Cases) == 0 {
				t.Fatalf("%s %s generated no cases", name, lane)
			}
			var buf bytes.Buffer
			if err := result.WriteJSON(&buf); err != nil {
				t.Fatal(err)
			}
			for i := range result.Cases {
				size := huntEncodedElementSize(result.Cases[i])
				if size > worstCase {
					worstCase = size
				}
				if size > HuntMaxCaseResultBytes {
					t.Errorf("%s %s global case %d writes %d bytes, over HuntMaxCaseResultBytes %d",
						name, lane, result.Cases[i].Manifest.Case, size, HuntMaxCaseResultBytes)
				}
			}
			if buf.Len() > worstResult {
				worstResult = buf.Len()
			}
			if buf.Len() > HuntMaxResultBytes {
				t.Errorf("%s %s writes %d bytes, over HuntMaxResultBytes %d", name, lane, buf.Len(), HuntMaxResultBytes)
			}
		}
	}
	t.Logf("largest generated shard: result %d/%d bytes, case %d/%d bytes",
		worstResult, HuntMaxResultBytes, worstCase, HuntMaxCaseResultBytes)
}
