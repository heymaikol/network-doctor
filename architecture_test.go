package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPackageLayering(t *testing.T) {
	// Internal dependencies must descend this order. Incident reconstruction
	// reads comparisons but no probes, and UI may present it. Peer transport and
	// simulation remain peers. Live diagnosis and snapshot comparison are peers:
	// comparison reads artifacts, never probes. Remote execution joins them
	// there: it moves the two published artifacts over SSH and runs no probe of
	// its own, so it depends on the schemas and never on the probe engine. Field
	// cases sit beside comparison: they validate stored artifacts and metadata,
	// never live probe state.
	// Checking every direct edge also rules out a transitive path to the same or
	// a higher layer.
	layers := map[string]int{
		"internal/app":        4,
		"internal/textsafe":   0,
		"internal/report":     0,
		"internal/snapshot":   0,
		"internal/compare":    1,
		"internal/diagnostic": 1,
		"internal/fieldcase":  1,
		"internal/remote":     1,
		"internal/incident":   2,
		"internal/peer":       2,
		"internal/profile":    2,
		"internal/simulation": 2,
		"internal/ui":         3,
	}
	const internalPrefix = "github.com/heymaikol/network-doctor/internal/"

	files := make(map[string]int)
	edges := make(map[string]bool)
	scanned := 0
	err := filepath.WalkDir("internal", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "internal" && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		pkg := filepath.ToSlash(filepath.Dir(path))
		files[pkg]++
		scanned++
		sourceLayer, sourceKnown := layers[pkg]
		if !sourceKnown {
			t.Errorf("%s: package layering violation: %s has no architecture layer", path, pkg)
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range f.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(importPath, internalPrefix) {
				continue
			}
			dependency := "internal/" + strings.TrimPrefix(importPath, internalPrefix)
			edges[pkg+" -> "+dependency] = true
			dependencyLayer, dependencyKnown := layers[dependency]
			if !dependencyKnown {
				t.Errorf("%s: package layering violation: %s depends on unclassified %s", fset.Position(spec.Pos()), pkg, dependency)
				continue
			}
			if sourceKnown && dependencyLayer >= sourceLayer {
				t.Errorf("%s: package layering violation: %s depends on %s; rule: dependencies must point down ui -> incident/peer/simulation -> diagnostic/compare/fieldcase -> report/snapshot/textsafe", fset.Position(spec.Pos()), pkg, dependency)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan internal packages: %v", err)
	}
	for pkg := range layers {
		if files[pkg] == 0 {
			t.Errorf("scanned no production Go files in expected package %s", pkg)
		}
	}
	if scanned < 20 || len(edges) < 3 {
		t.Errorf("scan reached only %d production Go files and %d internal package edges; the guard is not reaching the repository", scanned, len(edges))
	}
}

// The probe timeout has one canonical representation and one place that decides
// it, and that is an invariant a reviewer cannot hold in their head: the setting
// is written into two published integer-millisecond fields from three
// producers, sent by one, and rebuilt by one. A second normalization added
// later would not fail any existing test, it would just drift.
//
// So the two shapes that went wrong are pinned here. Writing a millisecond
// field from anything but the canonical projection is how precision used to
// disappear after the invocation was already accepted. Multiplying a millisecond
// field back into nanoseconds inline is how an out-of-range wire value used to
// overflow into a small positive duration that a sign check accepted.
func TestProbeTimeoutHasOneCanonicalConversion(t *testing.T) {
	const canonical = "internal/diagnostic/timeout.go"
	msFields := map[string]bool{"ProbeTimeoutMs": true, "TimeoutMs": true}

	writes, rebuilds := 0, 0
	roots := []string{"internal", "cmd"}
	walk := func(root string, path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		slash := filepath.ToSlash(path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				// A millisecond field being written. Either the canonical
				// projection produced the number, or it is a field that already
				// held a canonical one being carried across unchanged.
				key, ok := node.Key.(*ast.Ident)
				if !ok || !msFields[key.Name] {
					return true
				}
				writes++
				switch value := node.Value.(type) {
				case *ast.CallExpr:
					if canonicalProjection(value.Fun) {
						return true
					}
				case *ast.SelectorExpr:
					if msFields[value.Sel.Name] {
						return true
					}
				case *ast.BasicLit:
					// A literal in a fixed scenario, not a conversion.
					return true
				}
				t.Errorf("%s: %s is written from something other than diagnostic.ProbeTimeoutMs; a second projection can drift from the rule that makes it lossless", slash, key.Name)
			case *ast.BinaryExpr:
				// A millisecond field being rebuilt into a Duration. Only the
				// canonical converter may, because only it bounds the number
				// before the multiplication can overflow.
				if node.Op != token.MUL || slash == canonical {
					return true
				}
				for _, side := range []ast.Expr{node.X, node.Y} {
					if namesAMillisecondField(side, msFields) {
						rebuilds++
						t.Errorf("%s: a millisecond timeout is multiplied into nanoseconds outside %s; an out-of-range value overflows before any check sees it", slash, canonical)
					}
				}
			}
			return true
		})
		return nil
	}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			return walk(root, path, d, err)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The producers this is meant to cover: the two snapshot builders, the
	// simulated lab's artifact, the redaction pass-through, and the request.
	if writes < 5 {
		t.Errorf("swept %d millisecond-field writes, want at least 5: the guard is not reaching the producers", writes)
	}
	if rebuilds != 0 {
		t.Errorf("found %d inline rebuilds, want 0", rebuilds)
	}
}

// canonicalProjection reports whether fun is the one function allowed to turn a
// probe timeout into milliseconds, named from inside internal/diagnostic or from
// another package.
func canonicalProjection(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name == "ProbeTimeoutMs"
	case *ast.SelectorExpr:
		return f.Sel.Name == "ProbeTimeoutMs"
	}
	return false
}

// namesAMillisecondField reports whether e reads one of the millisecond fields,
// through any number of conversions such as time.Duration(req.TimeoutMs).
func namesAMillisecondField(e ast.Expr, fields map[string]bool) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return fields[v.Sel.Name]
	case *ast.CallExpr:
		for _, arg := range v.Args {
			if namesAMillisecondField(arg, fields) {
				return true
			}
		}
	case *ast.ParenExpr:
		return namesAMillisecondField(v.X, fields)
	}
	return false
}
