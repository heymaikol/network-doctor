package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The README's hero GIF is recorded by .github/workflows/demo.yml from
// hero.tape. These tests hold the parts of that arrangement that break
// silently: a recording is still produced when the tape has drifted off the
// program, and each release tag's recording can refresh the tracked GIF.

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

func TestDemoWorkflowRefreshesTheTrackedGIFOnRelease(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/demo.yml")
	if err != nil {
		t.Fatal(err)
	}
	type step struct {
		Name string            `yaml:"name"`
		Uses string            `yaml:"uses"`
		If   string            `yaml:"if"`
		Run  string            `yaml:"run"`
		With map[string]string `yaml:"with"`
		Env  map[string]string `yaml:"env"`
	}
	var workflow struct {
		On          map[string]yaml.Node `yaml:"on"`
		Permissions map[string]string    `yaml:"permissions"`
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress *bool  `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
		Jobs map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
			Steps       []step            `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("demo.yml is not valid YAML: %v", err)
	}

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
	if len(workflow.Permissions) != 1 || workflow.Permissions["contents"] != "write" {
		t.Errorf("demo.yml permissions = %v, want only contents: write", workflow.Permissions)
	}
	if permissions := workflow.Jobs["hero"].Permissions; len(permissions) != 0 {
		t.Errorf("demo.yml hero job broadens permissions with %v", permissions)
	}
	if !strings.Contains(workflow.Concurrency.Group, "${{ github.ref }}") || workflow.Concurrency.CancelInProgress == nil || !*workflow.Concurrency.CancelInProgress {
		t.Errorf("demo.yml concurrency = group %q, cancel-in-progress %v; newer main runs must cancel obsolete ones", workflow.Concurrency.Group, workflow.Concurrency.CancelInProgress)
	}

	var checkout, commit *step
	for i := range workflow.Jobs["hero"].Steps {
		s := &workflow.Jobs["hero"].Steps[i]
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = s
		}
		if s.Name == "Commit the changed recording" {
			commit = s
		}
	}
	if checkout == nil || checkout.With["persist-credentials"] != "true" {
		t.Fatal("demo.yml checkout does not persist GITHUB_TOKEN credentials for the push")
	}
	if token := checkout.With["token"]; token != "" && token != "${{ github.token }}" { //nolint:gosec // G101: workflow key name, not a credential
		t.Errorf("demo.yml checkout uses custom token %q; the GITHUB_TOKEN recursion protection is required", token)
	}
	if commit == nil {
		t.Fatal("demo.yml does not commit the changed recording")
	}
	if commit.If != "" {
		t.Errorf("demo.yml commit condition = %q; a release tag is the only trigger that reaches this step", commit.If)
	}
	if checkout.With["fetch-depth"] != "0" {
		t.Error("demo.yml checkout is shallow; the ancestry check needs main's history")
	}
	if commit.Env["EXPECTED_HEAD"] != "${{ github.sha }}" {
		t.Errorf("demo.yml expected head = %q, want the revision that was recorded", commit.Env["EXPECTED_HEAD"])
	}

	noChange := strings.Index(commit.Run, "git diff --quiet -- assets/hero.gif")
	remoteHead := strings.Index(commit.Run, "git fetch origin main")
	compareHead := strings.Index(commit.Run, `if ! git merge-base --is-ancestor "$EXPECTED_HEAD" origin/main; then`)
	rejectStale := strings.Index(commit.Run, "exit 1")
	addGIF := strings.Index(commit.Run, "git add assets/hero.gif")
	commitGIF := strings.Index(commit.Run, `git commit -m "Refresh README hero GIF"`)
	pushGIF := strings.Index(commit.Run, "git push origin HEAD:main")
	if noChange < 0 || remoteHead < 0 || noChange > remoteHead || !strings.Contains(commit.Run[noChange:remoteHead], "exit 0") {
		t.Error("demo.yml does not exit without a commit when assets/hero.gif is unchanged")
	}
	ordered := []int{noChange, remoteHead, compareHead, rejectStale, addGIF, commitGIF, pushGIF}
	prev := -1
	for _, position := range ordered {
		if position < 0 || position <= prev {
			t.Fatal("demo.yml must check for a changed GIF, reject a tag that is not on main, then add, commit, and push the recording")
		}
		prev = position
	}
	for _, want := range []string{
		`git config user.name "github-actions[bot]"`,
		`git config user.email "41898282+github-actions[bot]@users.noreply.github.com"`,
		"git add assets/hero.gif",
		`git commit -m "Refresh README hero GIF"`,
	} {
		if !strings.Contains(commit.Run, want) {
			t.Errorf("demo.yml commit step lacks %q", want)
		}
	}
	indiscriminateAdd := regexp.MustCompile(`(?m)^\s*git add\s+(?:-A|--all|\.(?:\s|$))`)
	indiscriminateCommit := regexp.MustCompile(`(?m)^\s*git commit\s+(?:-a|--all)(?:\s|$)`)
	if indiscriminateAdd.MatchString(commit.Run) || indiscriminateCommit.MatchString(commit.Run) {
		t.Error("demo.yml indiscriminately stages files instead of adding only assets/hero.gif")
	}
}
