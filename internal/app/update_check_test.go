package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/heymaikol/network-doctor/v2/internal/update"
)

const updateSchemaPath = "../../schema/netdoc-update-check-v1.schema.json"

// updateTest isolates one run of -update-check: a fixed installed version, a
// config directory of its own, and a stub transport that counts requests.
type updateTest struct {
	calls atomic.Int32
	tag   string
	code  int
	err   error
}

func (u *updateTest) RoundTrip(*http.Request) (*http.Response, error) {
	u.calls.Add(1)
	if u.err != nil {
		return nil, u.err
	}
	body := `{"tag_name":"` + u.tag + `","draft":false,"prerelease":false}`
	return &http.Response{StatusCode: u.code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

// setUpdateTest installs u and restores the package state afterwards.
func setUpdateTest(t *testing.T, u *updateTest, installed string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home) // os.UserConfigDir reads this on Windows
	savedVersion, savedClient := version, updateClient
	t.Cleanup(func() { version, updateClient = savedVersion, savedClient })
	version = installed
	updateClient = func() *http.Client {
		return &http.Client{Transport: u, CheckRedirect: update.NewClient().CheckRedirect}
	}
}

// runUpdate runs netdoc with args and returns its exit code and both streams.
func runUpdate(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func compileUpdateSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(updateSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s is not valid JSON: %v", updateSchemaPath, err)
	}
	c := jsonschema.NewCompiler()
	const id = "https://raw.githubusercontent.com/heymaikol/network-doctor/main/schema/netdoc-update-check-v1.schema.json"
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(id)
	if err != nil {
		t.Fatalf("compile %s: %v", updateSchemaPath, err)
	}
	return sch
}

func validateUpdate(sch *jsonschema.Schema, blob string) error {
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(blob))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

// An explicit -update-check asks again after an unsuccessful attempt, here the
// record an interrupted attempt leaves behind, and reports the fresh answer.
func TestExplicitCheckRefreshesAnUnsuccessfulCache(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: 200}
	setUpdateTest(t, u, "2.2.1")
	path := updateCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := `{"checked_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","outcome":"offline","latest":""}`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runUpdate("-update-check", "-json")
	if code != 0 || u.calls.Load() != 1 {
		t.Fatalf("exit %d with %d requests, want exit 0 and one request; stderr %q", code, u.calls.Load(), errOut)
	}
	if err := validateUpdate(compileUpdateSchema(t), out); err != nil {
		t.Fatalf("answer does not match the schema: %v\n%s", err, out)
	}
	var got updateReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "update_available" || got.Cached {
		t.Fatalf("status %q cached=%v, want a fresh update_available", got.Status, got.Cached)
	}
}

func TestUpdateCheckHumanNoticeNamesTheNewerRelease(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, out, errOut := runUpdate("-update-check")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "A newer Network Doctor release is available on GitHub: v2.3.0 (you have 2.2.1).") {
		t.Fatalf("stdout = %q", out)
	}
	if errOut != "" {
		t.Fatalf("stderr = %q, want nothing", errOut)
	}
}

// The machine-readable answer is one JSON object on stdout, and it validates
// against the published schema.
func TestUpdateCheckJSONIsTheContract(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, out, errOut := runUpdate("-update-check", "-json")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout is not one JSON line: %q", out)
	}
	if err := validateUpdate(compileUpdateSchema(t), out); err != nil {
		t.Fatalf("the output does not validate: %v\n%s", err, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] != update.UpdateAvailable || got["latest"] != "v2.3.0" || got["installed"] != "2.2.1" {
		t.Fatalf("answer = %v", got)
	}
}

// Negative control for the schema: an update_available answer without its
// release is refused, so the contract check above has teeth.
func TestUpdateCheckSchemaRefusesAnIncompleteAnswer(t *testing.T) {
	sch := compileUpdateSchema(t)
	bad := `{"schema":"netdoc.update-check.v1","status":"update_available","installed":"2.2.1","cached":false}`
	if err := validateUpdate(sch, bad); err == nil {
		t.Fatal("an update_available answer without latest, release_url and checked_at was accepted")
	}
	wrongSchema := `{"schema":"netdoc.update-check.v2","status":"up_to_date","installed":"2.3.0","cached":true}`
	if err := validateUpdate(sch, wrongSchema); err == nil {
		t.Fatal("an answer with another schema name was accepted")
	}
}

// The schema's status enumeration must match the statuses the code produces.
func TestUpdateCheckStatusesMatchTheSchema(t *testing.T) {
	data, err := os.ReadFile(updateSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties struct {
			Status struct {
				Enum []string `json:"enum"`
			} `json:"status"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{update.UpdateAvailable, update.UpToDate, update.UnknownVersion, update.Disabled, update.Offline, update.RateLimited, update.BadResponse}
	got := append([]string(nil), doc.Properties.Status.Enum...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("schema statuses %v, code statuses %v", got, want)
	}
}

// Negative control: --no-reference-egress overrides the explicit request's
// permission to check, so nothing is sent.
func TestUpdateCheckObeysNoReferenceEgress(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, out, _ := runUpdate("-update-check", "-json", "-no-reference-egress")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if n := u.calls.Load(); n != 0 {
		t.Fatalf("--no-reference-egress still made %d requests", n)
	}
	if !strings.Contains(out, `"status":"disabled"`) {
		t.Fatalf("stdout = %q, want a disabled answer", out)
	}
}

// Negative control: a development or unstable build is never compared, so the
// check makes no request for it.
func TestUpdateCheckMakesNoRequestForUnknownBuilds(t *testing.T) {
	for _, installed := range []string{"dev", "v2.2.2-0.20261120012900-e88e9b22d6f3", "2.3.0-rc.1"} {
		u := &updateTest{tag: "v9.9.9", code: http.StatusOK}
		setUpdateTest(t, u, installed)
		code, out, _ := runUpdate("-update-check", "-json")
		if code != 0 || !strings.Contains(out, `"status":"unknown_version"`) {
			t.Fatalf("%s: exit %d, stdout %q", installed, code, out)
		}
		if n := u.calls.Load(); n != 0 {
			t.Fatalf("%s: made %d requests", installed, n)
		}
	}
}

// -update-check combines only with -json and -no-reference-egress. Any other
// target or flag is refused before a request is made.
func TestUpdateCheckRefusesCombinations(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, _, errOut := runUpdate("-update-check", "example.com")
	if code != 2 || !strings.Contains(errOut, "-update-check cannot be combined") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if n := u.calls.Load(); n != 0 {
		t.Fatalf("a refused combination made %d requests", n)
	}
}

// Offline use is a normal answer: exit 0, no notice, nothing on stderr.
func TestUpdateCheckOfflineIsAnAnswer(t *testing.T) {
	u := &updateTest{err: errors.New("no route to host")}
	setUpdateTest(t, u, "2.2.1")
	code, out, errOut := runUpdate("-update-check")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "Could not reach GitHub to check for updates.") {
		t.Fatalf("stdout = %q", out)
	}
}

// -version makes no request, and its answer is unchanged.
func TestVersionMakesNoRequest(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, out, _ := runUpdate("-version")
	if code != 0 || out != "netdoc 2.2.1\n" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	if n := u.calls.Load(); n != 0 {
		t.Fatalf("-version made %d requests", n)
	}
}

// The automatic check is off by flag, by the environment, and by
// --no-reference-egress, and on otherwise.
func TestUpdateNoticeGates(t *testing.T) {
	t.Setenv(updateOptOutEnv, "")
	if updateNotice(false, false) == nil {
		t.Fatal("the automatic check is off by default")
	}
	if updateNotice(true, false) != nil {
		t.Fatal("-no-update-check did not turn the automatic check off")
	}
	if updateNotice(false, true) != nil {
		t.Fatal("--no-reference-egress did not turn the automatic check off")
	}
	t.Setenv(updateOptOutEnv, "1")
	if updateNotice(false, false) != nil {
		t.Fatal("NETDOC_NO_UPDATE_CHECK=1 did not turn the automatic check off")
	}
}

// The explicit command answers even when the environment opt-out is set: the
// user asked for it directly.
func TestExplicitCheckIgnoresTheEnvironmentOptOut(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	t.Setenv(updateOptOutEnv, "1")
	code, out, _ := runUpdate("-update-check", "-json")
	if code != 0 || !strings.Contains(out, `"status":"update_available"`) {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	if n := u.calls.Load(); n != 1 {
		t.Fatalf("the explicit check made %d requests, want 1", n)
	}
}

// -no-update-check may accompany the explicit command: it has no effect on
// the answer, so the combination is accepted.
func TestNoUpdateCheckFlagAcceptedWithTheExplicitCheck(t *testing.T) {
	u := &updateTest{tag: "v2.3.0", code: http.StatusOK}
	setUpdateTest(t, u, "2.2.1")
	code, _, errOut := runUpdate("-update-check", "-json", "-no-update-check")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}
