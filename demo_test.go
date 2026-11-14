package main

import (
	"cmp"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The README's hero GIF is recorded by .github/workflows/demo.yml from
// hero.tape. These tests hold the parts of that arrangement that break
// silently: a recording is still produced when the tape has drifted off the
// program, and only a manual run from main can publish the tracked media.

// Release tags still record and upload; only successful manual main runs can
// start the job with write access.
const demoPublishCondition = "success() && needs.hero.result == 'success' && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"

type demoWorkflowStep struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	If              string            `yaml:"if"`
	Run             string            `yaml:"run"`
	With            map[string]string `yaml:"with"`
	Env             map[string]string `yaml:"env"`
	ContinueOnError bool              `yaml:"continue-on-error"`
}

type demoWorkflowJob struct {
	If              string             `yaml:"if"`
	Needs           []string           `yaml:"needs"`
	Permissions     map[string]string  `yaml:"permissions"`
	Outputs         map[string]string  `yaml:"outputs"`
	Steps           []demoWorkflowStep `yaml:"steps"`
	ContinueOnError bool               `yaml:"continue-on-error"`
}

type demoWorkflowConfig struct {
	On          map[string]yaml.Node `yaml:"on"`
	Permissions map[string]string    `yaml:"permissions"`
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress *bool  `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]demoWorkflowJob `yaml:"jobs"`
}

func parseDemoWorkflow(t *testing.T) demoWorkflowConfig {
	t.Helper()
	var workflow demoWorkflowConfig
	if err := yaml.Unmarshal([]byte(demoWorkflow(t)), &workflow); err != nil {
		t.Fatalf("demo.yml is not valid YAML: %v", err)
	}
	return workflow
}

func demoNamedStep(t *testing.T, job demoWorkflowJob, name string) demoWorkflowStep {
	t.Helper()
	for _, step := range job.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("demo.yml lacks step %q", name)
	return demoWorkflowStep{}
}

func demoWorkflow(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(".github/workflows/demo.yml")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// demoSteps is the workflow with its commentary removed, for the checks that
// ask what the workflow does rather than what it says.
func demoSteps(t *testing.T) string {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(demoWorkflow(t), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.TrimSpace(code) != "" {
			kept = append(kept, code)
		}
	}
	return strings.Join(kept, "\n")
}

func heroSteps(t *testing.T) string {
	t.Helper()
	tape, err := os.ReadFile("hero.tape")
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	for _, line := range strings.Split(string(tape), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.TrimSpace(code) != "" {
			steps = append(steps, code)
		}
	}
	return strings.Join(steps, "\n")
}

func demoTempRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// VHS, ttyd and ffmpeg are the action's job. Installing any of them here would
// mean a second, unpinned toolchain deciding what the recording looks like.
func TestDemoWorkflowRecordsThroughTheOfficialVHSAction(t *testing.T) {
	workflow := demoWorkflow(t)

	if !strings.Contains(workflow, "uses: charmbracelet/vhs-action@") {
		t.Error("demo.yml does not use charmbracelet/vhs-action; nothing records the tape through the official action")
	}
	if !strings.Contains(workflow, "path: hero.tape") {
		t.Error("demo.yml does not hand hero.tape to the action")
	}
	if !strings.Contains(workflow, "uses: actions/upload-artifact@") {
		t.Error("demo.yml does not upload the generated hero GIF")
	}
	// The tape names its own output, and the workflow checks that file. If
	// the tape's Output line moves, the check is watching a stale path.
	tape, err := os.ReadFile("hero.tape")
	if err != nil {
		t.Fatal(err)
	}
	output := regexp.MustCompile(`(?m)^Output\s+(\S+)`).FindSubmatch(tape)
	if output == nil {
		t.Fatal("hero.tape has no Output line")
	}
	if !strings.Contains(workflow, string(output[1])) {
		t.Errorf("hero.tape records to %q, which demo.yml never verifies or uploads", output[1])
	}

	// The dimensions the workflow asserts are copied out of the tape, so a
	// tape resize has to be made deliberately in both places rather than
	// turning the check red on the next unrelated commit.
	for _, set := range []string{"Width", "Height"} {
		m := regexp.MustCompile(`(?m)^Set\s+` + set + `\s+(\d+)`).FindSubmatch(tape)
		if m == nil {
			t.Fatalf("hero.tape does not Set %s", set)
		}
		if !strings.Contains(workflow, `"`+string(m[1])+`"`) {
			t.Errorf("hero.tape sets %s %s, which demo.yml does not check for", set, m[1])
		}
	}
}

// demoAptPackages is every package the workflow installs with apt, in the order
// the workflow names them. Flags are not packages.
func demoAptPackages(t *testing.T) []string {
	t.Helper()
	var pkgs []string
	for _, line := range strings.Split(demoSteps(t), "\n") {
		_, args, ok := strings.Cut(line, "apt-get install")
		if !ok {
			continue
		}
		for _, field := range strings.Fields(args) {
			if !strings.HasPrefix(field, "-") {
				pkgs = append(pkgs, field)
			}
		}
	}
	return pkgs
}

func TestHeroRecordingRunsNetworkDoctorDirectly(t *testing.T) {
	recording := heroSteps(t)
	if !strings.Contains(recording, `Type "netdoc printer.invalid"`) {
		t.Error("hero.tape does not visibly invoke netdoc printer.invalid")
	}
	for _, forbidden := range []string{"netdoc-sim", "nsenter", "netdoc()", `$PWD/netdoc`, "has no A/AAAA", "Fix:", "Next:"} {
		if strings.Contains(recording, forbidden) {
			t.Errorf("hero.tape executable steps contain %q; the recording must run netdoc directly without injected results", forbidden)
		}
	}
}

// VHS gives the recorded command a real xterm-256color pseudo-terminal, but
// inherits NO_COLOR locally and CI on GitHub-hosted runners. termenv treats
// either as an instruction to return its uncolored profile before inspecting
// the TTY, so the tape clears only those inherited policy flags.
func TestHeroRecordingUsesItsColorCapableTerminal(t *testing.T) {
	recording := heroSteps(t)
	for _, env := range []string{`Env NO_COLOR ""`, `Env CI ""`} {
		if !strings.Contains(recording, env) {
			t.Errorf("hero.tape lacks %q; termenv will disable color in a supported recording environment", env)
		}
	}
	for _, forced := range []string{"CLICOLOR_FORCE", "FORCE_COLOR"} {
		if strings.Contains(recording, forced) {
			t.Errorf("hero.tape contains %q; advertise the pseudo-terminal's real capability instead of forcing color", forced)
		}
	}
}

// The recorder belongs to the action, which installs the pinned VHS binary
// along with ttyd, ffmpeg and the fonts it renders with. A second copy
// installed here would be unpinned, and whichever one won the PATH would decide
// what the recording looks like.
func TestDemoWorkflowLeavesTheRecorderToTheAction(t *testing.T) {
	for _, pkg := range demoAptPackages(t) {
		if slices.Contains([]string{"vhs", "ttyd", "ffmpeg", "fontconfig"}, pkg) {
			t.Errorf("demo.yml apt-installs %q, which charmbracelet/vhs-action already provides", pkg)
		}
		if strings.HasPrefix(pkg, "fonts-") {
			t.Errorf("demo.yml apt-installs the font package %q; the action installs the fonts VHS renders with", pkg)
		}
	}
	// Not every install is an apt install: what this workflow replaced fetched
	// a release archive and piped an installer into a shell.
	steps := demoSteps(t)
	for _, vector := range []string{"curl -", "wget ", "install-fonts"} {
		if strings.Contains(steps, vector) {
			t.Errorf("demo.yml uses %q; VHS, ttyd, ffmpeg and the fonts are the action's to install", vector)
		}
	}
}

// Same supply-chain rule the other workflows follow, plus one of its own: the
// VHS binary is a version too, and `latest` would let an upstream release
// change the recording with nothing in this repository to point at.
func TestDemoWorkflowPinsItsActionsAndItsVHS(t *testing.T) {
	workflow := demoWorkflow(t)

	uses := regexp.MustCompile(`uses: (\S+)@(\S+)`).FindAllStringSubmatch(workflow, -1)
	if len(uses) < 3 {
		t.Fatalf("found %d action uses in demo.yml; the test is not reaching the workflow", len(uses))
	}
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, m := range uses {
		if !sha.MatchString(m[2]) {
			t.Errorf("demo.yml uses %q, which is not pinned to a commit SHA", m[0])
		}
	}

	version := regexp.MustCompile(`(?m)^\s+version: (\S+)`).FindStringSubmatch(workflow)
	if version == nil {
		t.Fatal("demo.yml never pins a VHS version, so the action installs `latest`")
	}
	if version[1] == "latest" {
		t.Error("demo.yml pins VHS to `latest`; an upstream release would change the recording on its own")
	}
}

func TestDemoWorkflowPublishesOnlyFromManualMainRuns(t *testing.T) {
	workflow := parseDemoWorkflow(t)

	if len(workflow.On) != 2 {
		t.Errorf("demo.yml triggers on %v, want only push and workflow_dispatch", workflow.On)
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok {
		t.Error("demo.yml cannot be triggered by hand")
	}
	push, ok := workflow.On["push"]
	if !ok {
		t.Fatal("demo.yml does not run on pushes")
	}
	var pushFilter struct {
		Tags        []string `yaml:"tags"`
		Branches    []string `yaml:"branches"`
		Paths       []string `yaml:"paths"`
		PathsIgnore []string `yaml:"paths-ignore"`
	}
	if err := push.Decode(&pushFilter); err != nil {
		t.Fatalf("decode push trigger: %v", err)
	}
	if !slices.Equal(pushFilter.Tags, []string{"v[0-9]+.[0-9]+.[0-9]+"}) || len(pushFilter.Branches) != 0 || len(pushFilter.Paths) != 0 || len(pushFilter.PathsIgnore) != 0 {
		t.Errorf("demo.yml push filter = tags %q, branches %q, paths %q, paths-ignore %q; want every release tag", pushFilter.Tags, pushFilter.Branches, pushFilter.Paths, pushFilter.PathsIgnore)
	}
	if !maps.Equal(workflow.Permissions, map[string]string{"contents": "read"}) {
		t.Errorf("demo.yml permissions = %v, want only contents: read", workflow.Permissions)
	}
	if !strings.Contains(workflow.Concurrency.Group, "${{ github.ref }}") || workflow.Concurrency.CancelInProgress == nil || !*workflow.Concurrency.CancelInProgress {
		t.Errorf("demo.yml concurrency = group %q, cancel-in-progress %v; newer main runs must cancel obsolete ones", workflow.Concurrency.Group, workflow.Concurrency.CancelInProgress)
	}

	record, recordOK := workflow.Jobs["hero"]
	publish, publishOK := workflow.Jobs["publish"]
	if len(workflow.Jobs) != 2 || !recordOK || !publishOK {
		t.Fatal("demo.yml must separate recording and publishing into exactly two jobs")
	}
	if record.If != "" || len(record.Needs) != 0 {
		t.Error("recording must run unconditionally on release tags and manual dispatches")
	}
	if len(record.Permissions) != 0 && !maps.Equal(record.Permissions, map[string]string{"contents": "read"}) {
		t.Errorf("recording permissions = %v, want inherited or explicit contents: read", record.Permissions)
	}
	if !maps.Equal(publish.Permissions, map[string]string{"contents": "write"}) {
		t.Errorf("publishing permissions = %v, want only contents: write", publish.Permissions)
	}
	if !slices.Equal(publish.Needs, []string{"hero"}) || publish.If != demoPublishCondition {
		t.Errorf("publishing needs = %v, if = %q; require successful recording and a manual main run", publish.Needs, publish.If)
	}
	for name, job := range workflow.Jobs {
		if job.ContinueOnError {
			t.Errorf("job %s must fail when recording or validation fails", name)
		}
		checkouts, commits := 0, 0
		for _, s := range job.Steps {
			label := cmp.Or(s.Name, s.Uses)
			if s.If != "" || s.ContinueOnError {
				t.Errorf("job %s step %q must require all previous steps to succeed", name, label)
			}
			if strings.Contains(s.Run, "git commit") || strings.Contains(s.Run, "git push") {
				commits++
				if name != "publish" || s.Name != "Commit the changed recording" {
					t.Errorf("job %s step %q may not publish", name, label)
				}
			}
			if !strings.HasPrefix(s.Uses, "actions/checkout@") {
				continue
			}
			checkouts++
			if token := s.With["token"]; token != "" && token != "${{ github.token }}" { //nolint:gosec // G101: workflow key name, not a credential
				t.Errorf("job %s uses custom checkout token %q; require GITHUB_TOKEN recursion protection", name, token)
			}
			if name == "hero" && s.With["persist-credentials"] != "false" {
				t.Error("recording must not persist credentials")
			}
			if name == "publish" && (s.With["persist-credentials"] != "true" || s.With["fetch-depth"] != "0" || s.With["ref"] != "${{ github.sha }}") {
				t.Error("publishing needs the recorded revision, full ancestry and GITHUB_TOKEN credentials")
			}
		}
		if checkouts != 1 || (name == "publish" && commits != 1) {
			t.Errorf("job %s has %d checkouts and %d publishing steps", name, checkouts, commits)
		}
	}
	if strings.Contains(demoSteps(t), "secrets.") {
		t.Error("demo workflow must use its own GITHUB_TOKEN, without external publishing tokens")
	}
}

func TestDemoWorkflowRefusesUnsafePublishing(t *testing.T) {
	commit := demoNamedStep(t, parseDemoWorkflow(t).Jobs["publish"], "Commit the changed recording")
	if commit.Env["EXPECTED_HEAD"] != "${{ github.sha }}" {
		t.Errorf("expected head = %q, want the revision that was recorded", commit.Env["EXPECTED_HEAD"])
	}

	media := "assets/hero.gif assets/hero.mp4 assets/hero-poster.png"
	noChange := strings.Index(commit.Run, "git diff --quiet -- "+media)
	remoteHead := strings.Index(commit.Run, "git fetch origin main")
	compareHead := strings.Index(commit.Run, `if ! git merge-base --is-ancestor "$EXPECTED_HEAD" origin/main; then`)
	rejectStale := strings.Index(commit.Run, "exit 1")
	currentHead := strings.Index(commit.Run, `[ "$(git rev-parse HEAD)" != "$EXPECTED_HEAD" ]`)
	currentMain := strings.Index(commit.Run, `[ "$(git rev-parse origin/main)" != "$EXPECTED_HEAD" ]`)
	addGIF := strings.Index(commit.Run, "git add "+media)
	commitGIF := strings.Index(commit.Run, `git commit -m "Refresh homepage demo media"`)
	pushGIF := strings.Index(commit.Run, "git push origin HEAD:main")
	if noChange < 0 || remoteHead < 0 || noChange > remoteHead || !strings.Contains(commit.Run[noChange:remoteHead], "exit 0") {
		t.Error("demo.yml does not exit without a commit when all demo media are unchanged")
	}
	ordered := []int{noChange, remoteHead, compareHead, rejectStale, currentHead, currentMain, addGIF, commitGIF, pushGIF}
	prev := -1
	for _, position := range ordered {
		if position < 0 || position <= prev {
			t.Fatal("publishing must check for changes, reject unsafe or stale revisions, then add, commit and push the media")
		}
		prev = position
	}
	for _, want := range []string{
		`git config user.name "github-actions[bot]"`,
		`git config user.email "41898282+github-actions[bot]@users.noreply.github.com"`,
		"git add " + media,
		`git commit -m "Refresh homepage demo media" -- ` + media,
	} {
		if !strings.Contains(commit.Run, want) {
			t.Errorf("demo.yml commit step lacks %q", want)
		}
	}
	indiscriminateAdd := regexp.MustCompile(`(?m)^\s*git add\s+(?:-A|--all|\.(?:\s|$))`)
	indiscriminateCommit := regexp.MustCompile(`(?m)^\s*git commit\s+(?:-a|--all)(?:\s|$)`)
	if indiscriminateAdd.MatchString(commit.Run) || indiscriminateCommit.MatchString(commit.Run) {
		t.Error("demo.yml indiscriminately stages files instead of adding only the three demo assets")
	}
	if strings.Contains(commit.Run, "--force") || strings.Contains(commit.Run, " -f") || strings.Contains(commit.Run, "|| true") || !strings.HasPrefix(commit.Run, "set -euo pipefail\n") {
		t.Error("publishing must fail closed and must never force a push")
	}
}

func TestDemoWorkflowValidatesDerivativesBeforePublishing(t *testing.T) {
	workflow := parseDemoWorkflow(t)
	built, recorded, verified, converted, uploaded := -1, -1, -1, -1, -1
	for i, step := range workflow.Jobs["hero"].Steps {
		if step.Name == "Build Network Doctor" {
			built = i
			if step.Run != "go build -o netdoc ." || step.Env["CGO_ENABLED"] != "0" {
				t.Error("recording must build the release-shaped Network Doctor binary")
			}
		}
		if strings.HasPrefix(step.Uses, "charmbracelet/vhs-action@") {
			recorded = i
			if step.With["path"] != "hero.tape" {
				t.Error("recording must use hero.tape")
			}
		}
		if step.Name == "Verify the recording" {
			verified = i
			for _, check := range []string{"ffprobe", "-count_frames", `test "${recording[0]}" = "1100"`, `test "${recording[1]}" = "640"`, `test "${recording[2]}" -ge 100`} {
				if !strings.Contains(step.Run, check) {
					t.Errorf("recording validation lacks %q", check)
				}
			}
		}
		if strings.Contains(step.Run, "python3 .github/scripts/demo_media.py") {
			converted = i
			if step.If != "" || step.ContinueOnError {
				t.Fatal("media conversion must run before every publication")
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			uploaded = i
			if !slices.Equal(strings.Fields(step.With["path"]), []string{"assets/hero.gif", "assets/hero.mp4", "assets/hero-poster.png"}) || step.With["if-no-files-found"] != "error" {
				t.Error("artifact must contain exactly all three media files and reject missing files")
			}
			if step.ID != "media" || workflow.Jobs["hero"].Outputs["media-artifact-id"] != "${{ steps.media.outputs.artifact-id }}" {
				t.Error("recording must expose the exact uploaded artifact ID")
			}
		}
	}
	if built < 0 || built >= recorded || recorded >= verified || verified >= converted || converted >= uploaded {
		t.Fatal("recording must build, record, verify the GIF, generate and validate derivatives, then upload")
	}

	downloaded, validated, committed := -1, -1, -1
	for i, step := range workflow.Jobs["publish"].Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			downloaded = i
			want := map[string]string{
				"artifact-ids": "${{ needs.hero.outputs.media-artifact-id }}",
				"path":         "${{ runner.temp }}/hero-media",
			}
			if !maps.Equal(step.With, want) {
				t.Errorf("download inputs = %v, want only %v; no other run or repository may supply media", step.With, want)
			}
		}
		if step.Name == "Verify downloaded media" {
			validated = i
			if step.Env["MEDIA_DIR"] != "${{ runner.temp }}/hero-media" {
				t.Error("validation must read the downloaded artifact, not the checked-in media")
			}
			for _, check := range []string{
				"set -euo pipefail\n", `sys.path.insert(0, ".github/scripts")`,
				`media = Path(os.environ["MEDIA_DIR"])`, `gif = media / "hero.gif"`,
				`recording = demo_media.probe(gif)`, `(stream["width"], stream["height"]) != (1100, 640)`,
				`len(recording["frames"]) < 100`, `raise ValueError("incomplete hero recording")`,
			} {
				if !strings.Contains(step.Run, check) {
					t.Errorf("download validation lacks %q", check)
				}
			}
			verify := strings.Index(step.Run, `demo_media.verify(gif, media / "hero.mp4", media / "hero-poster.png")`)
			copyMedia := strings.Index(step.Run, `cp "$MEDIA_DIR/hero.gif" "$MEDIA_DIR/hero.mp4" "$MEDIA_DIR/hero-poster.png" assets/`)
			if verify < 0 || copyMedia < verify || strings.Contains(step.Run, "demo_media.refresh") {
				t.Error("all downloaded media must pass verification before copying, without regenerating derivatives")
			}
		}
		if strings.Contains(step.Run, "git commit") {
			committed = i
		}
	}
	if downloaded < 0 || downloaded >= validated || validated >= committed {
		t.Fatal("publishing must download its recording, verify every media file, then commit")
	}
}

func TestDemoDownloadedValidationFailsBeforeCopy(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash is not installed; workflow structure is checked separately")
	}
	verify := demoNamedStep(t, parseDemoWorkflow(t).Jobs["publish"], "Verify downloaded media")
	root := demoTempRoot(t)
	dir := root.Name()
	for _, subdir := range []string{"bin", "assets", "downloaded"} {
		if err := os.Mkdir(filepath.Join(dir, subdir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate the validator rejecting an artifact; copying must never follow.
	if err := root.WriteFile("bin/python3", []byte("#!/bin/sh\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("bin/python3", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hero.gif", "hero.mp4", "hero-poster.png"} {
		for subdir, content := range map[string]string{"assets": "original", "downloaded": "invalid"} {
			if err := os.WriteFile(filepath.Join(dir, subdir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	//nolint:gosec // G204: repository-owned validation script with Python stubbed to fail.
	cmd := exec.Command("bash", "-c", verify.Run)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "MEDIA_DIR="+filepath.Join(dir, "downloaded"),
		"PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("validation failure was ignored: %s", out)
	}
	for _, name := range []string{"hero.gif", "hero.mp4", "hero-poster.png"} {
		data, err := root.ReadFile(filepath.Join("assets", name))
		if err != nil || string(data) != "original" {
			t.Errorf("%s changed after validation failed: %q, %v", name, data, err)
		}
	}
}

func TestDemoPublishingGate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash is not installed; workflow structure is checked separately")
	}
	condition := parseDemoWorkflow(t).Jobs["publish"].If
	// These GitHub comparisons and conjunctions have the same meaning in [[ ]].
	condition = strings.NewReplacer(
		"success()", `"$RECORDING_RESULT" == 'success'`,
		"needs.hero.result", `"$RECORDING_RESULT"`,
		"github.event_name", `"$EVENT_NAME"`,
		"github.ref", `"$EVENT_REF"`,
	).Replace(condition)
	for _, tc := range []struct {
		name, event, ref, result string
		want                     bool
	}{
		{"release tag", "push", "refs/tags/v2.0.0", "success", false},
		{"manual tag", "workflow_dispatch", "refs/tags/v2.0.0", "success", false},
		{"manual branch", "workflow_dispatch", "refs/heads/feature", "success", false},
		{"main push", "push", "refs/heads/main", "success", false},
		{"manual main", "workflow_dispatch", "refs/heads/main", "success", true},
		{"failed recording", "workflow_dispatch", "refs/heads/main", "failure", false},
		{"cancelled recording", "workflow_dispatch", "refs/heads/main", "cancelled", false},
		{"skipped recording", "workflow_dispatch", "refs/heads/main", "skipped", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			//nolint:gosec // G204: repository-owned condition with fixed table inputs.
			cmd := exec.Command("bash", "-c", "[[ "+condition+" ]]")
			cmd.Env = append(os.Environ(), "RECORDING_RESULT="+tc.result, "EVENT_NAME="+tc.event, "EVENT_REF="+tc.ref)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("publish gate: %v\n%s; want allowed = %v", err, out, tc.want)
			}
		})
	}
}

func TestDemoPublishingScriptFailsClosed(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash is not installed; workflow structure is checked separately")
	}
	commit := demoNamedStep(t, parseDemoWorkflow(t).Jobs["publish"], "Commit the changed recording")
	root := demoTempRoot(t)
	dir := root.Name()
	// A Bash function shadows git.exe on Windows too, so no real git command runs.
	git := `git() {
  printf '%s\n' "$*" >> "$GIT_LOG"
  case "$*" in
    diff\ --quiet*) return "$DIFF_STATUS" ;;
    "fetch origin main") return "$FETCH_STATUS" ;;
    merge-base\ --is-ancestor*) return "$ANCESTOR_STATUS" ;;
    "rev-parse HEAD") printf '%s\n' "$CHECKOUT_HEAD" ;;
    "rev-parse origin/main") printf '%s\n' "$MAIN_HEAD" ;;
    push\ *) return "$PUSH_STATUS" ;;
    config\ *|add\ *|commit\ *) ;;
    *) return 99 ;;
  esac
}
`
	for _, tc := range []struct {
		name, checkout, main              string
		diff, fetch, ancestor, push       string
		wantSuccess, wantPublishAttempted bool
	}{
		{"current main", "recorded", "recorded", "1", "0", "0", "0", true, true},
		{"unchanged media", "recorded", "recorded", "0", "0", "0", "0", true, false},
		{"not on main", "recorded", "unrelated", "1", "0", "1", "0", false, false},
		{"main advanced", "recorded", "newer", "1", "0", "0", "0", false, false},
		{"wrong checkout", "different", "recorded", "1", "0", "0", "0", false, false},
		{"fetch failed", "recorded", "recorded", "1", "1", "0", "0", false, false},
		{"push rejected", "recorded", "recorded", "1", "0", "0", "1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logRoot := demoTempRoot(t)
			log := filepath.Join(logRoot.Name(), "git.log")
			//nolint:gosec // G204: repository-owned script, with every git invocation stubbed.
			cmd := exec.Command("bash", "-c", git+commit.Run)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GIT_LOG="+log, "EXPECTED_HEAD=recorded", "CHECKOUT_HEAD="+tc.checkout, "MAIN_HEAD="+tc.main,
				"DIFF_STATUS="+tc.diff, "FETCH_STATUS="+tc.fetch, "ANCESTOR_STATUS="+tc.ancestor, "PUSH_STATUS="+tc.push)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("publishing: %v\n%s; want success = %v", err, out, tc.wantSuccess)
			}
			calls, err := logRoot.ReadFile("git.log")
			if err != nil {
				t.Fatal(err)
			}
			var writes []string
			for _, call := range strings.Split(string(calls), "\n") {
				if strings.HasPrefix(call, "add ") || strings.HasPrefix(call, "commit ") || strings.HasPrefix(call, "push ") {
					writes = append(writes, call)
				}
			}
			var want []string
			if tc.wantPublishAttempted {
				want = []string{
					"add assets/hero.gif assets/hero.mp4 assets/hero-poster.png",
					"commit -m Refresh homepage demo media -- assets/hero.gif assets/hero.mp4 assets/hero-poster.png",
					"push origin HEAD:main",
				}
			}
			if !slices.Equal(writes, want) {
				t.Fatalf("publishing commands = %q, want %q", writes, want)
			}
		})
	}
}

func TestDemoMediaValidator(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python 3 is not installed; demo workflow runs these offline checks too")
	}
	out, err := exec.Command("python3", "-B", "-m", "unittest", "discover", "-s", ".github/scripts", "-p", "test_demo_media.py").CombinedOutput()
	if err != nil {
		t.Fatalf("demo media validation tests: %v\n%s", err, out)
	}
}
