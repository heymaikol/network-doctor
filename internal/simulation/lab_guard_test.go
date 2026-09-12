package simulation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The lab's network model is data-only. Pin the imports and dangerous seams
// instead of relying on the CI host happening to have no usable Internet.
func TestLabHasNoLiveNetworkOrClockFallback(t *testing.T) {
	paths, err := filepath.Glob("lab*.go")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		count++
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			name, _ := strconv.Unquote(imp.Path.Value)
			if !slices.Contains([]string{"crypto/sha256", "io", "encoding/json", "maps", "context", "errors", "fmt", "reflect", "slices", "strings", "sync", "time", "net", "net/netip", "strconv", "hash/fnv", "github.com/heymaikol/network-doctor/internal/compare", "github.com/heymaikol/network-doctor/internal/diagnostic", "github.com/heymaikol/network-doctor/internal/snapshot"}, name) {
				t.Errorf("%s imports %s; audit offline boundary", path, name)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && slices.Contains([]string{"Run", "DefaultBackend", "LaunchDirector", "Load", "LoadScenario", "RunNode", "NewID"}, id.Name) {
				t.Errorf("%s calls live simulator seam %s", path, id.Name)
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name {
			case "net":
				if !slices.Contains([]string{"ParseIP", "JoinHostPort"}, sel.Sel.Name) {
					t.Errorf("%s calls net.%s", path, sel.Sel.Name)
				}
			case "time":
				t.Errorf("%s calls time.%s; model must not read or wait on the clock", path, sel.Sel.Name)
			case "diagnostic", "d":
				if !slices.Contains([]string{"ParseTarget", "ProbePlan", "RunAll", "BuildSnapshot", "ReplaySnapshot", "Interpret", "InternetProbeEndpoints", "ProbeTimeoutMs"}, sel.Sel.Name) {
					t.Errorf("%s calls diagnostic.%s; audit offline boundary", path, sel.Sel.Name)
				}
			}
			return true
		})
	}
	if count < 4 {
		t.Fatal("offline guard missed lab sources")
	}
}
