package frrospf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The steady zebra RIB capture is described in testdata/frr/10.7.0/zebra-rib/README.md.
// These tests are untagged and portable, and they read only the capture's bytes. The
// validators are pure, so the negative cases run whether or not the capture is installed.
// The tests that read the installed capture fail, rather than skip, while it is missing,
// so an incomplete transfer cannot pass quietly.

// zebraRIBDir is the installed steady capture.
var zebraRIBDir = filepath.Join(fixtureRoot, "zebra-rib", "steady")

// zebraRIBSums is the manifest the operator stages. It is not one of the captures.
const zebraRIBSums = "SHA256SUMS"

// zebraRIBEmptySHA256 is the SHA-256 of empty input. The in-memory manifest vectors
// use empty files, so no test hashes bytes it made up.
const zebraRIBEmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// zebraRIBRole is one query of the steady bracket. The command is the echo that the
// first line of the role's .raw must hold. It is written here rather than read from a
// file name, so a renamed file cannot change what is checked.
type zebraRIBRole struct {
	name    string
	command string
}

// zebraRIBRoles is the bracket in capture order. R is zebra's RIB, and the other roles
// are ospfd.
var zebraRIBRoles = []zebraRIBRole{
	{"A", "show ip ospf json"},
	{"B", "show ip ospf database detail json"},
	{"E", "show ip ospf route json"},
	{"R", "show ip route json"},
	{"D", "show ip ospf json"},
}

// zebraRIBNodes are the two routers, r1 first.
var zebraRIBNodes = []string{"r1", "r2"}

// zebraRIBPin pins one R capture by its exact length and the SHA-256 of the whole .raw
// file, in hex. The check reads the bytes, not SHA256SUMS, so a rewritten manifest
// cannot move the pin.
type zebraRIBPin struct {
	size int
	hash string
}

// zebraRIBPins are the R pins, keyed by node.
var zebraRIBPins = map[string]zebraRIBPin{
	"r1": {3313, "f1dfe82b6c10b36853edf3ac24c93c2e27e33c80a0ae2c8a06945e3deffe4bcf"},
	"r2": {3857, "9e4dc0621bce7464a89b597095eafbf19a70a1b00ef49033dcf5c5526e41c525"},
}

// zebraRIBStamps are the R stamps, exact to the byte with the LF included.
var zebraRIBStamps = map[string]string{
	"r1": "2026-10-12T14:16:20.821906515Z\n",
	"r2": "2026-10-12T14:16:36.536488001Z\n",
}

// zebraRIBPrefixes is the number of top-level prefixes each R capture holds.
var zebraRIBPrefixes = map[string]int{"r1": 6, "r2": 7}

// zebraRIBStampRE is one RFC 3339 UTC stamp with exactly nine fraction digits, a Z, and
// LF. time.Parse alone accepts any number of fraction digits.
var zebraRIBStampRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z\n$`)

// zebraRIBSumLine is one line of a GNU sha256sum --binary manifest: 64 lowercase hex
// digits, a space, an asterisk, and the file name.
var zebraRIBSumLine = regexp.MustCompile(`^([0-9a-f]{64}) \*(\S+)$`)

// zebraRIBStem is the name of one capture without its extension, built the way lsdb/
// builds its names: node, role, and the command with spaces as underscores.
func zebraRIBStem(node string, role zebraRIBRole) string {
	return node + "-" + role.name + "-" + strings.ReplaceAll(role.command, " ", "_")
}

// zebraRIBNames returns the 21 capture files in byte order: a .raw and a .collected_at
// for each node and role, and zebra-version.txt.
func zebraRIBNames() []string {
	names := []string{"zebra-version.txt"}
	for _, node := range zebraRIBNodes {
		for _, role := range zebraRIBRoles {
			stem := zebraRIBStem(node, role)
			names = append(names, stem+".raw", stem+".collected_at")
		}
	}
	slices.Sort(names)
	return names
}

// zebraRIBReadModes uses Lstat to identify each entry without following
// symlinks or depending on filesystem directory-entry type support.
func zebraRIBReadModes(dir string) (map[string]fs.FileMode, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	modes := make(map[string]fs.FileMode, len(entries))
	for _, e := range entries {
		info, err := os.Lstat(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("lstat %s: %w", e.Name(), err)
		}
		modes[e.Name()] = info.Mode().Type()
	}
	return modes, nil
}

// zebraRIBReadFiles reads the 21 captures by name.
func zebraRIBReadFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, name := range zebraRIBNames() {
		files[name] = readFile(t, filepath.Join(zebraRIBDir, name))
	}
	return files
}

// zebraRIBCheckLayout requires exactly the 21 captures and SHA256SUMS, each a regular
// file. Any other entry, a subdirectory, or a symlink fails.
func zebraRIBCheckLayout(modes map[string]fs.FileMode) error {
	want := append(zebraRIBNames(), zebraRIBSums)
	var problems []string
	for _, name := range want {
		mode, ok := modes[name]
		switch {
		case !ok:
			problems = append(problems, "missing "+name)
		case !mode.IsRegular():
			problems = append(problems, fmt.Sprintf("%s is not a regular file (%v)", name, mode))
		}
	}
	for name := range modes {
		if !slices.Contains(want, name) {
			problems = append(problems, "extra entry "+name)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	return errors.New(strings.Join(problems, "; "))
}

// zebraRIBCheckSums checks SHA256SUMS against the bytes of the captures. Each line is
// "<64 lowercase hex> *<name>", LF only, with one line per capture, sorted by name in
// byte order, and each digest equal to its file's SHA-256.
func zebraRIBCheckSums(sums []byte, files map[string][]byte) error {
	if len(sums) == 0 || sums[len(sums)-1] != '\n' {
		return errors.New("SHA256SUMS does not end with LF")
	}
	if bytes.ContainsRune(sums, '\r') {
		return errors.New("SHA256SUMS has a CR")
	}
	lines := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n")
	if len(lines) != len(files) {
		return fmt.Errorf("SHA256SUMS has %d entries, want %d", len(lines), len(files))
	}
	prev := ""
	for i, line := range lines {
		m := zebraRIBSumLine.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("SHA256SUMS line %d is not <64 lowercase hex> *<name>", i+1)
		}
		digest, name := m[1], m[2]
		data, ok := files[name]
		if !ok {
			return fmt.Errorf("SHA256SUMS names %s, which is not one of the captures", name)
		}
		if i > 0 && name <= prev {
			return fmt.Errorf("SHA256SUMS line %d (%s) is a duplicate or out of byte order", i+1, name)
		}
		prev = name
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return fmt.Errorf("%s: SHA256SUMS digest %s does not match the file", name, digest)
		}
	}
	return nil
}

// zebraRIBCheckFrame checks the vty framing of one .raw and returns its body. The bytes
// must be the echoed command and CRLF, the output, CRLF, and the node's prompt with its
// trailing space, and nothing after the prompt. Line endings are not normalized. The
// output may hold CRLF inside, but it may not start or end with a blank line.
func zebraRIBCheckFrame(raw []byte, command, node string) ([]byte, error) {
	head := []byte(command + "\r\n")
	tail := []byte("\r\n" + node + "> ")
	if !bytes.HasPrefix(raw, head) {
		return nil, fmt.Errorf("first line is not the echo %q", command+"\r\n")
	}
	if !bytes.HasSuffix(raw, tail) {
		return nil, fmt.Errorf("does not end with CRLF and the prompt %q, with nothing after it", node+"> ")
	}
	if len(raw) <= len(head)+len(tail) {
		return nil, errors.New("no output between the echo and the prompt")
	}
	body := raw[len(head) : len(raw)-len(tail)]
	if bytes.ContainsAny(body[:1], "\r\n") || bytes.ContainsAny(body[len(body)-1:], "\r\n") {
		return nil, errors.New("output has a blank line at its edge")
	}
	return body, nil
}

// zebraRIBCheckRIB checks that an R body is exactly one JSON object whose top-level keys
// are distinct prefixes that netip.ParsePrefix accepts, and that there are as many as
// node holds. Values are not read, and nothing here says whether a route is selected,
// installed, or in the kernel FIB.
func zebraRIBCheckRIB(body []byte, node string) error {
	if !utf8.Valid(body) {
		return errors.New("R body is not valid UTF-8")
	}
	if len(body) == 0 || body[0] != '{' || body[len(body)-1] != '}' {
		return errors.New("R body is not one JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("R body is not one JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("R key %v is not a string", tok)
		}
		if seen[key] {
			return fmt.Errorf("R repeats top-level key %q", key)
		}
		seen[key] = true
		if _, err := netip.ParsePrefix(key); err != nil {
			return fmt.Errorf("R top-level key %q is not a prefix: %w", key, err)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("R value of %q: %w", key, err)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("R body is not one JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("R body has junk after the JSON object")
	}
	if want := zebraRIBPrefixes[node]; len(seen) != want {
		return fmt.Errorf("%s R has %d top-level prefixes, want %d", node, len(seen), want)
	}
	return nil
}

// zebraRIBCheckPin checks one R capture's bytes against its pin: the exact length, then
// the SHA-256 of the whole file. A malformed pin fails here, so a typo cannot pass.
func zebraRIBCheckPin(node string, pin zebraRIBPin, raw []byte) error {
	want, err := hex.DecodeString(pin.hash)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("%s pin is not %d hex bytes", node, sha256.Size)
	}
	if len(raw) != pin.size {
		return fmt.Errorf("%s R is %d bytes, want %d", node, len(raw), pin.size)
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(sum[:], want) {
		return fmt.Errorf("%s R sha256 is %x, want %s", node, sum, pin.hash)
	}
	return nil
}

// zebraRIBParseStamp parses one .collected_at. It must be an RFC 3339 UTC stamp with
// nine fraction digits, a Z, and LF, and nothing else.
func zebraRIBParseStamp(b []byte) (time.Time, error) {
	if !zebraRIBStampRE.Match(b) {
		return time.Time{}, fmt.Errorf("stamp %q is not RFC 3339 with nine fraction digits, Z, and LF", b)
	}
	return time.Parse(time.RFC3339Nano, string(b[:len(b)-1]))
}

// zebraRIBCheckOrder requires each node's stamps in bracket order, A before B before E
// before R before D, and r1's D before r2's A. Keys are "node role", such as "r1 A".
func zebraRIBCheckOrder(stamps map[string]time.Time) error {
	for _, node := range zebraRIBNodes {
		for i := 1; i < len(zebraRIBRoles); i++ {
			prev, cur := zebraRIBRoles[i-1].name, zebraRIBRoles[i].name
			before, okB := stamps[node+" "+prev]
			after, okA := stamps[node+" "+cur]
			if !okB || !okA {
				return fmt.Errorf("no stamp for %s %s or %s", node, prev, cur)
			}
			if !before.Before(after) {
				return fmt.Errorf("%s %s is not before %s", node, prev, cur)
			}
		}
	}
	d1, okD := stamps["r1 D"]
	a2, okA := stamps["r2 A"]
	if !okD || !okA {
		return errors.New("no stamp for r1 D or r2 A")
	}
	if !d1.Before(a2) {
		return errors.New("r1 D is not before r2 A")
	}
	return nil
}

// zebraRIBFirstKey returns the first top-level key of a JSON object body.
func zebraRIBFirstKey(t *testing.T, body []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	tok, err := dec.Token()
	if err != nil {
		t.Fatal(err)
	}
	key, ok := tok.(string)
	if !ok {
		t.Fatalf("first member of the R body is %v, not a key", tok)
	}
	return key
}

// zebraRIBWithKey returns body with key, and the value 0, placed ahead of its members.
// A key the body already holds makes a duplicate, and a key that is not a prefix makes
// an invalid one. body must be a non-empty JSON object.
func zebraRIBWithKey(body []byte, key string) []byte {
	return []byte(fmt.Sprintf("{%q:0,%s", key, body[1:]))
}

// zebraRIBExpectErr fails t unless err is nil when want is empty, or an error whose text
// contains want.
func zebraRIBExpectErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Errorf("unexpected error: %v", err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Errorf("error %v, want one containing %q", err, want)
	}
}

// zebraRIBSumsText writes a manifest for names in the form sha256sum --binary uses: the
// digest, a space, an asterisk, and the name, with LF after each line.
func zebraRIBSumsText(names []string, digest string) []byte {
	var b strings.Builder
	for _, name := range names {
		b.WriteString(digest + " *" + name + "\n")
	}
	return []byte(b.String())
}

// zebraRIBOrderedStamps returns one stamp per node and role, one second apart, in the
// bracket order that zebraRIBCheckOrder accepts.
func zebraRIBOrderedStamps() map[string]time.Time {
	stamps := map[string]time.Time{}
	sec := 0
	for _, node := range zebraRIBNodes {
		for _, role := range zebraRIBRoles {
			stamps[node+" "+role.name] = time.Date(2026, 10, 12, 14, 16, sec, 0, time.UTC)
			sec++
		}
	}
	return stamps
}

// TestZebraRIBSteadyCapturesAreComplete applies every check to the installed steady
// capture. It fails while the operator has not yet copied the files in.
func TestZebraRIBSteadyCapturesAreComplete(t *testing.T) {
	if _, err := os.Stat(zebraRIBDir); err != nil {
		t.Fatalf("zebra-rib/steady is not installed, so the operator must copy the 21 captures and SHA256SUMS in before validation: %v", err)
	}
	modes, err := zebraRIBReadModes(zebraRIBDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := zebraRIBCheckLayout(modes); err != nil {
		t.Fatalf("layout: %v", err)
	}
	files := zebraRIBReadFiles(t)
	if err := zebraRIBCheckSums(readFile(t, filepath.Join(zebraRIBDir, zebraRIBSums)), files); err != nil {
		t.Errorf("SHA256SUMS: %v", err)
	}
	stamps := map[string]time.Time{}
	for _, node := range zebraRIBNodes {
		for _, role := range zebraRIBRoles {
			stem := zebraRIBStem(node, role)
			raw := files[stem+".raw"]
			body, err := zebraRIBCheckFrame(raw, role.command, node)
			if err != nil {
				t.Errorf("%s.raw: %v", stem, err)
			}
			if role.name == "R" {
				if err := zebraRIBCheckRIB(body, node); err != nil {
					t.Errorf("%s.raw: %v", stem, err)
				}
				if err := zebraRIBCheckPin(node, zebraRIBPins[node], raw); err != nil {
					t.Errorf("%s.raw: %v", stem, err)
				}
				if got := string(files[stem+".collected_at"]); got != zebraRIBStamps[node] {
					t.Errorf("%s.collected_at is %q, want %q", stem, got, zebraRIBStamps[node])
				}
			}
			at, err := zebraRIBParseStamp(files[stem+".collected_at"])
			if err != nil {
				t.Errorf("%s.collected_at: %v", stem, err)
			}
			stamps[node+" "+role.name] = at
		}
	}
	if err := zebraRIBCheckOrder(stamps); err != nil {
		t.Errorf("stamp order: %v", err)
	}
}

// TestZebraRIBGenuineMutationsAreRejected edits copies of the installed r1 R capture in
// memory, and each edit must fail the check that targets it. It needs the installed
// capture, so it fails until the operator copies the files in.
func TestZebraRIBGenuineMutationsAreRejected(t *testing.T) {
	const name = "r1-R-show_ip_route_json.raw"
	files := zebraRIBReadFiles(t)
	sums := readFile(t, filepath.Join(zebraRIBDir, zebraRIBSums))
	if err := zebraRIBCheckSums(sums, files); err != nil {
		t.Fatalf("installed capture: %v", err)
	}
	raw := files[name]
	body, err := zebraRIBCheckFrame(raw, "show ip route json", "r1")
	if err != nil {
		t.Fatalf("installed capture: %v", err)
	}
	if err := zebraRIBCheckRIB(body, "r1"); err != nil {
		t.Fatalf("installed capture: %v", err)
	}
	if err := zebraRIBCheckPin("r1", zebraRIBPins["r1"], raw); err != nil {
		t.Fatalf("installed capture: %v", err)
	}

	t.Run("one byte changed", func(t *testing.T) {
		changed := bytes.Clone(raw)
		changed[len(changed)/2] ^= 0x01
		altered := maps.Clone(files)
		altered[name] = changed
		zebraRIBExpectErr(t, zebraRIBCheckPin("r1", zebraRIBPins["r1"], changed), "sha256 is")
		zebraRIBExpectErr(t, zebraRIBCheckSums(sums, altered), "does not match the file")
	})
	t.Run("CRLF after the echo changed to LF", func(t *testing.T) {
		lf := bytes.Replace(raw, []byte("\r\n"), []byte("\n"), 1)
		_, err := zebraRIBCheckFrame(lf, "show ip route json", "r1")
		zebraRIBExpectErr(t, err, "first line is not the echo")
	})
	first := zebraRIBFirstKey(t, body)
	t.Run("first prefix repeated", func(t *testing.T) {
		zebraRIBExpectErr(t, zebraRIBCheckRIB(zebraRIBWithKey(body, first), "r1"), "repeats top-level key")
	})
	t.Run("first key replaced by a non-prefix", func(t *testing.T) {
		zebraRIBExpectErr(t, zebraRIBCheckRIB(zebraRIBWithKey(body, "not-a-prefix"), "r1"), "is not a prefix")
	})
}

// TestZebraRIBFrameVectors checks the framing on literal bytes. The first two rows are
// accepted. Each other row breaks one edge of the framing.
func TestZebraRIBFrameVectors(t *testing.T) {
	cases := []struct {
		name, raw, command, node, wantBody, wantErr string
	}{
		{"exact framing", "show ip ospf json\r\n{\"a\":1}\r\nr1> ", "show ip ospf json", "r1", "{\"a\":1}", ""},
		{"CRLF inside the output", "show ip route json\r\n{\r\n}\r\nr1> ", "show ip route json", "r1", "{\r\n}", ""},
		{"LF after the echo", "show ip ospf json\n{}\r\nr1> ", "show ip ospf json", "r1", "", "first line is not the echo"},
		{"LF before the prompt", "show ip ospf json\r\n{}\nr1> ", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"prompt without its trailing space", "show ip ospf json\r\n{}\r\nr1>", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"LF after the prompt", "show ip ospf json\r\n{}\r\nr1> \n", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"CRLF after the prompt", "show ip ospf json\r\n{}\r\nr1> \r\n", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"another node's prompt", "show ip ospf json\r\n{}\r\nr2> ", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"enable prompt", "show ip ospf json\r\n{}\r\nr1# ", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"junk after the prompt", "show ip ospf json\r\n{}\r\nr1> junk", "show ip ospf json", "r1", "", "does not end with CRLF and the prompt"},
		{"another command's echo", "show ip ospf route json\r\n{}\r\nr1> ", "show ip ospf json", "r1", "", "first line is not the echo"},
		{"junk before the echo", "junk\r\nshow ip ospf json\r\n{}\r\nr1> ", "show ip ospf json", "r1", "", "first line is not the echo"},
		{"no echo", "{}\r\nr1> ", "show ip ospf json", "r1", "", "first line is not the echo"},
		{"no output", "show ip ospf json\r\n\r\nr1> ", "show ip ospf json", "r1", "", "no output between the echo and the prompt"},
		{"blank line before the prompt", "show ip ospf json\r\n{}\r\n\r\nr1> ", "show ip ospf json", "r1", "", "blank line at its edge"},
		{"blank line after the echo", "show ip ospf json\r\n\r\n{}\r\nr1> ", "show ip ospf json", "r1", "", "blank line at its edge"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := zebraRIBCheckFrame([]byte(c.raw), c.command, c.node)
			zebraRIBExpectErr(t, err, c.wantErr)
			if c.wantErr == "" && string(body) != c.wantBody {
				t.Errorf("body %q, want %q", body, c.wantBody)
			}
		})
	}
}

// TestZebraRIBRIBVectors checks the R body rules on literal bodies. The accepted rows
// show that nested repeats are not top-level repeats, and that six prefixes (r1) and
// seven (r2) are accepted.
func TestZebraRIBRIBVectors(t *testing.T) {
	cases := []struct {
		name, body, node, wantErr string
	}{
		{"six prefixes for r1, nested repeat", `{"10.10.1.0/24":[{"a":1,"a":2}],"10.10.2.0/24":[],"10.0.1.0/24":[],"10.0.3.0/24":[],"10.0.5.0/24":[],"10.20.0.0/24":null}`, "r1", ""},
		{"seven prefixes for r2", `{"10.10.1.0/24":[],"10.10.2.0/24":[],"10.0.1.0/24":[],"10.0.3.0/24":[],"10.0.5.0/24":[],"10.20.0.0/24":[],"10.0.2.0/24":[]}`, "r2", ""},
		{"five prefixes for r1", `{"10.10.1.0/24":[],"10.10.2.0/24":[],"10.0.1.0/24":[],"10.0.3.0/24":[],"10.0.5.0/24":[]}`, "r1", "has 5 top-level prefixes, want 6"},
		{"six prefixes for r2", `{"10.10.1.0/24":[],"10.10.2.0/24":[],"10.0.1.0/24":[],"10.0.3.0/24":[],"10.0.5.0/24":[],"10.20.0.0/24":[]}`, "r2", "has 6 top-level prefixes, want 7"},
		{"no members", `{}`, "r1", "has 0 top-level prefixes"},
		{"repeated top-level key", `{"10.0.1.0/24":[],"10.0.1.0/24":[]}`, "r1", "repeats top-level key"},
		{"repeated key spelled with an escape", `{"10.0.1.0/24":[],"10.0.1.` + string(rune(92)) + `u0030/24":[]}`, "r1", "repeats top-level key"},
		{"invalid prefix length", `{"10.0.1.0/33":[]}`, "r1", "is not a prefix"},
		{"address with no length", `{"10.0.1.0":[]}`, "r1", "is not a prefix"},
		{"named route", `{"default":[]}`, "r1", "is not a prefix"},
		{"leading space in a key", `{" 10.0.1.0/24":[]}`, "r1", "is not a prefix"},
		{"a JSON array", `[]`, "r1", "is not one JSON object"},
		{"a truncated object", `{"10.0.1.0/24":[`, "r1", "is not one JSON object"},
		{"a blank line after the object", "{\"10.0.1.0/24\":[]}\r\n", "r1", "is not one JSON object"},
		{"junk after the object", `{"10.0.1.0/24":[]}}`, "r1", "has junk after the JSON object"},
		{"invalid UTF-8", "{\"10.0.1.0/24\":\"\xff\"}", "r1", "is not valid UTF-8"},
		{"non-string key", `{1:[]}`, "r1", "string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zebraRIBExpectErr(t, zebraRIBCheckRIB([]byte(c.body), c.node), c.wantErr)
		})
	}
}

// TestZebraRIBPinVectors checks the R pin on literal bytes. The pin itself is checked
// against the installed capture in TestZebraRIBSteadyCapturesAreComplete.
func TestZebraRIBPinVectors(t *testing.T) {
	zebraRIBExpectErr(t, zebraRIBCheckPin("r1", zebraRIBPin{1, "abc"}, nil), "pin is not 32 hex bytes")
	zebraRIBExpectErr(t, zebraRIBCheckPin("r1", zebraRIBPins["r1"], nil), "R is 0 bytes, want 3313")
	same := bytes.Repeat([]byte("x"), zebraRIBPins["r1"].size)
	zebraRIBExpectErr(t, zebraRIBCheckPin("r1", zebraRIBPins["r1"], same), "R sha256 is")
}

// TestZebraRIBStampVectors checks the stamp format. Each bad stamp breaks one rule: nine
// fraction digits, the Z, the LF, RFC 3339 separators, or a valid date.
func TestZebraRIBStampVectors(t *testing.T) {
	at, err := zebraRIBParseStamp([]byte("2026-10-12T14:16:20.821906515Z\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 12, 14, 16, 20, 821906515, time.UTC); !at.Equal(want) {
		t.Errorf("stamp parsed as %v, want %v", at, want)
	}
	bad := []string{
		"2026-10-12T14:16:20.82190651Z\n",
		"2026-10-12T14:16:20.8219065150Z\n",
		"2026-10-12T14:16:20.821906515Z",
		"2026-10-12T14:16:20.821906515Z\r\n",
		"2026-10-12T14:16:20Z\n",
		"2026-10-12T14:16:20.821906515+00:00\n",
		"2026-10-12T14:16:20.821906515Z\n\n",
		"2026-10-12 14:16:20.821906515Z\n",
		"2026-13-12T14:16:20.821906515Z\n",
	}
	for _, s := range bad {
		if _, err := zebraRIBParseStamp([]byte(s)); err == nil {
			t.Errorf("stamp %q accepted", s)
		}
	}
}

// TestZebraRIBOrderVectors checks the bracket order. The first row is accepted. Each
// other row breaks one ordering rule or leaves one stamp out.
func TestZebraRIBOrderVectors(t *testing.T) {
	cases := []struct {
		name    string
		change  func(map[string]time.Time)
		wantErr string
	}{
		{"the bracket in order", func(map[string]time.Time) {}, ""},
		{"E and R swapped", func(s map[string]time.Time) { s["r1 E"], s["r1 R"] = s["r1 R"], s["r1 E"] }, "r1 E is not before R"},
		{"B equal to A", func(s map[string]time.Time) { s["r2 B"] = s["r2 A"] }, "r2 A is not before B"},
		{"r2 A before r1 D", func(s map[string]time.Time) { s["r2 A"] = s["r1 D"].Add(-time.Second) }, "r1 D is not before r2 A"},
		{"r2 D missing", func(s map[string]time.Time) { delete(s, "r2 D") }, "no stamp for r2 R or D"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stamps := zebraRIBOrderedStamps()
			c.change(stamps)
			zebraRIBExpectErr(t, zebraRIBCheckOrder(stamps), c.wantErr)
		})
	}
}

// TestZebraRIBLayoutVectors checks the file set on in-memory listings. Nothing is written
// to disk, so no file named like a capture is created.
func TestZebraRIBLayoutVectors(t *testing.T) {
	names := zebraRIBNames()
	full := func() map[string]fs.FileMode {
		modes := map[string]fs.FileMode{zebraRIBSums: 0}
		for _, name := range names {
			modes[name] = 0
		}
		return modes
	}
	if err := zebraRIBCheckLayout(full()); err != nil {
		t.Fatalf("exact layout: %v", err)
	}
	cases := []struct {
		name    string
		change  func(map[string]fs.FileMode)
		wantErr string
	}{
		{"a capture missing", func(m map[string]fs.FileMode) { delete(m, names[0]) }, "missing " + names[0]},
		{"SHA256SUMS missing", func(m map[string]fs.FileMode) { delete(m, zebraRIBSums) }, "missing SHA256SUMS"},
		{"an extra file", func(m map[string]fs.FileMode) { m["notes.txt"] = 0 }, "extra entry notes.txt"},
		{"a symlink in place of a capture", func(m map[string]fs.FileMode) { m[names[0]] = fs.ModeSymlink }, names[0] + " is not a regular file"},
		{"a subdirectory in place of a capture", func(m map[string]fs.FileMode) { m[names[0]] = fs.ModeDir }, names[0] + " is not a regular file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			modes := full()
			c.change(modes)
			zebraRIBExpectErr(t, zebraRIBCheckLayout(modes), c.wantErr)
		})
	}
}

// TestZebraRIBReadModesOnDisk checks that the directory reader reports a symlink and a
// subdirectory as what they are. The names are not capture names, and the entries are
// removed with the temporary directory.
func TestZebraRIBReadModesOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	modes, err := zebraRIBReadModes(dir)
	if err != nil {
		t.Fatal(err)
	}
	if modes["link"]&fs.ModeSymlink == 0 {
		t.Errorf("link reads as %v, want a symlink", modes["link"])
	}
	if !modes["sub"].IsDir() {
		t.Errorf("sub reads as %v, want a directory", modes["sub"])
	}
	zebraRIBExpectErr(t, zebraRIBCheckLayout(modes), "extra entry link")
}

// TestZebraRIBSumsVectors checks SHA256SUMS on a manifest over empty files. The digest of
// empty input is the one constant above, so the well-formed row also checks that
// constant. Each other row breaks one rule of the format or the match.
func TestZebraRIBSumsVectors(t *testing.T) {
	names := zebraRIBNames()
	files := map[string][]byte{}
	for _, name := range names {
		files[name] = nil
	}
	good := zebraRIBSumsText(names, zebraRIBEmptySHA256)
	if err := zebraRIBCheckSums(good, files); err != nil {
		t.Fatalf("well-formed manifest over empty files: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	replaced := func(i int, line string) string {
		l := slices.Clone(lines)
		l[i] = line
		return join(l)
	}
	last := len(lines) - 1
	swapped := slices.Clone(lines)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	cases := []struct {
		name, text, wantErr string
	}{
		{"one line missing", join(lines[1:]), "has 20 entries"},
		{"a name outside the set", replaced(last, zebraRIBEmptySHA256+" *extra.txt"), "not one of the captures"},
		{"SHA256SUMS lists itself", replaced(last, zebraRIBEmptySHA256+" *"+zebraRIBSums), "not one of the captures"},
		{"digest does not match", replaced(0, strings.Repeat("0", 64)+" *"+names[0]), "does not match the file"},
		{"uppercase digest", replaced(0, strings.ToUpper(lines[0][:64])+lines[0][64:]), "is not <64 lowercase hex>"},
		{"two spaces, text mode", replaced(0, lines[0][:64]+"  "+names[0]), "is not <64 lowercase hex>"},
		{"out of byte order", join(swapped), "out of byte order"},
		{"a line repeated", replaced(1, lines[0]), "out of byte order"},
		{"CRLF line endings", strings.ReplaceAll(string(good), "\n", "\r\n"), "has a CR"},
		{"no final LF", strings.TrimSuffix(string(good), "\n"), "does not end with LF"},
		{"empty manifest", "", "does not end with LF"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zebraRIBExpectErr(t, zebraRIBCheckSums([]byte(c.text), files), c.wantErr)
		})
	}
	altered := maps.Clone(files)
	altered[names[0]] = []byte("x")
	zebraRIBExpectErr(t, zebraRIBCheckSums(good, altered), "does not match the file")
}
