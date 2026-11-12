package capture

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/heymaikol/network-doctor/v2/contrib/frr-correlation/"

func imports(t *testing.T, dir, goos string) []string {
	t.Helper()
	ctx := build.Default
	ctx.GOOS, ctx.CgoEnabled = goos, false
	pkg, err := ctx.ImportDir(dir, 0)
	if err != nil {
		t.Fatalf("%s on %s: %v", dir, goos, err)
	}
	return pkg.Imports
}

// This package never promotes anything: it does not import the collector, whose
// Lifecycle is the only place a TrustedResult comes from, and it does not read
// producer content, so no producer claim can steer it. Nothing in the collector
// or the supervisor reaches it either, so no existing path consumes a Snapshot.
func TestCaptureHasNoPathToTrustPromotion(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, imp := range imports(t, ".", goos) {
			if strings.HasPrefix(imp, module) || strings.HasPrefix(imp, "encoding/") || strings.Contains(imp, "json") {
				t.Errorf("%s build imports %s", goos, imp)
			}
		}
	}
	for _, dir := range []string{"../collector", "../supervisor"} {
		for _, imp := range imports(t, dir, "linux") {
			if imp == module+"capture" {
				t.Errorf("%s imports the capture package before a reviewed slice wires it in", dir)
			}
		}
	}
}

// The exported surface is pinned. A new exported name, above all one that
// returns a collector type, must be a deliberate edit of this list in review.
func TestExportedSurfaceIsPinned(t *testing.T) {
	want := []string{
		"BGPD", "Cancelled", "CleanupIncomplete", "Closed", "CloseFailure", "Code", "AlreadyUsed", "FilesystemRefused",
		"Inbox", "Inbox.Close", "Inbox.Path", "Inbox.Seal", "InvalidRole", "LinkRefused", "MaxDiagnosticBytes",
		"MaxStreamBytes", "MixedEpochs", "Modified", "NewInbox", "NotRegular", "OwnerRefused", "ReadFailure",
		"Refusal", "Refusal.Code", "Refusal.Error", "ResourceLimit", "Role", "SealFailure", "Snapshot",
		"Snapshot.Close", "Snapshot.ReadAt", "Snapshot.SHA256", "Snapshot.Size", "UnexpectedEntry", "Unsupported",
		"WriterPresent", "Zebra",
	}
	slices.Sort(want)
	got, codes := surface(t)
	if !slices.Equal(got, want) {
		t.Fatalf("exported surface changed:\n got  %v\n want %v", got, want)
	}
	if len(codes) != len(messages) {
		t.Fatalf("%d refusal codes but %d fixed messages", len(codes), len(messages))
	}
	for _, c := range codes {
		if _, ok := messages[Code(c)]; !ok {
			t.Errorf("code %q has no fixed message", c)
		}
	}
}

// surface lists the exported names across every platform file, and the values of
// the refusal codes.
func surface(t *testing.T) (names, codes []string) {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				name := d.Name.Name
				if d.Recv != nil {
					recv := d.Recv.List[0].Type
					if star, ok := recv.(*ast.StarExpr); ok {
						recv = star.X
					}
					id, ok := recv.(*ast.Ident)
					if !ok || !id.IsExported() {
						continue
					}
					name = id.Name + "." + name
				}
				seen[name] = true
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							seen[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for i, n := range s.Names {
							if !n.IsExported() {
								continue
							}
							seen[n.Name] = true
							if id, ok := s.Type.(*ast.Ident); ok && id.Name == "Code" {
								codes = append(codes, strings.Trim(s.Values[i].(*ast.BasicLit).Value, `"`))
							}
						}
					}
				}
			}
		}
	}
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, codes
}
