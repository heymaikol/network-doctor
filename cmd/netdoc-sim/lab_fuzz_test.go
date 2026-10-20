package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

func TestLabFuzzCLI(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unresolvable.invalid:1")
	t.Setenv("ALL_PROXY", "socks5://unresolvable.invalid:1")
	for _, args := range [][]string{{"--cases", "4", "--json"}, {"--case", "7", "--seed", "847293", "--json"}, {"--cases", "4", "--property", "two-sided-symmetry", "--workers", "2"}, {"-h"}} {
		var out, errs bytes.Buffer
		if code := runLabFuzz(context.Background(), args, &out, &errs); code != exitOK {
			t.Fatalf("%v: %d %s", args, code, errs.String())
		}
	}
	for _, args := range [][]string{{"--cases", "0"}, {"--case", "-2"}, {"--workers", "0"}, {"--max-faults", "13"}, {"--property", "invented"}, {"replay"}, {"unexpected"}} {
		var out, errs bytes.Buffer
		if code := runLabFuzz(context.Background(), args, &out, &errs); code == exitOK {
			t.Fatal("invalid args passed", args)
		}
	}
	c, err := simulation.GenerateLabFuzz(1, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	a := simulation.LabFuzzArtifact{Format: "lab-fuzz-artifact-v1", Original: c, Minimized: c, Failure: simulation.LabFuzzViolation{Property: "determinism", Code: "fabricated"}}
	data, _ := json.Marshal(a)
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := runLabFuzz(context.Background(), []string{"replay", path}, &out, &errs); code != exitOK || !bytes.Contains(out.Bytes(), []byte("reproduced=false")) {
		t.Fatalf("replay: %d %s %s", code, out.String(), errs.String())
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runLabFuzz(context.Background(), []string{"replay", path}, &out, &errs); code != exitUsage {
		t.Fatal("malformed artifact accepted")
	}
}
