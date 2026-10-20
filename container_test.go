//go:build container

// Tests of the published artifact rather than of the source. Everything else in
// this repository proves that the code is right; this file proves that the
// image someone pulls contains that code, runs the real Linux namespace backend
// inside a container, and needs no more privilege than it says it does.
//
// They run against an already-built image because building it is the release
// pipeline's job, not a unit test's:
//
//	docker build -t netdoc-sim:test .
//	NETDOC_CONTAINER_IMAGE=netdoc-sim:test go test -tags container -count=1 -v .
//
// Without NETDOC_CONTAINER_IMAGE, or with no container engine on the machine,
// every test here skips. NETDOC_REQUIRE_CONTAINER=1 turns those skips into
// failures, which is what CI sets, the same contract NETDOC_SIM_REQUIRE_NETNS
// has for the namespace suite, and for the same reason: a job that silently
// tested nothing would go green.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

const (
	imageEnv   = "NETDOC_CONTAINER_IMAGE"
	engineEnv  = "NETDOC_CONTAINER_ENGINE"
	requireEnv = "NETDOC_REQUIRE_CONTAINER"
)

// challengeID is the current-generation challenge used by the container guide.
// Its base needs no forwarding sysctl, which a standard container keeps
// read-only even though the simulator's nested namespaces are otherwise usable.
const challengeID = simulation.ChallengeIDVersion + "-005CCD"
const challengeCorrectAnswer = "tcp_port_blocked"

func TestChallengeFixtureTracksCurrentDocumentedExample(t *testing.T) {
	challenge, err := simulation.BuildChallenge(challengeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge.Manifest.Mutations) != 1 || challenge.Manifest.Mutations[0].ID != "service.tcp_port_blocked" {
		t.Fatalf("%s mutations = %+v, want the fault behind the container's %q correct-answer assertion",
			challengeID, challenge.Manifest.Mutations, challengeCorrectAnswer)
	}
}

// documentedOptions is the run command the README and docs hand out, so every
// ordinary test here exercises the line users actually type. One capability,
// and it is there for the syscall filter rather than for the simulation:
// Docker's default seccomp profile refuses clone(CLONE_NEWUSER) unless the
// container was configured with CAP_SYS_ADMIN, and a user namespace is what the
// whole backend is built on. Podman's default profile permits it and needs no
// flag at all; passing this one there is harmless, which is why the docs can
// give one command for both. --privileged is never required.
//
// TestImageNeedsNoCapabilities is the other half: the simulator itself needs no
// capability whatsoever, and that test proves it by taking them all away.
var documentedOptions = []string{"--cap-add", "SYS_ADMIN"}

// containerTimeout bounds one container invocation. A challenge builds a
// network, runs netdoc through every probe, and tears it down; the slowest of
// these is well under a minute on an idle machine and this is the "something
// hung" line, not a performance assertion.
const containerTimeout = 4 * time.Minute

// engineAndImage resolves what to run and what to run it with, or skips.
func engineAndImage(t *testing.T) (engine, image string) {
	t.Helper()
	image = os.Getenv(imageEnv)
	engine = os.Getenv(engineEnv)
	if engine == "" {
		for _, candidate := range []string{"docker", "podman"} {
			if _, err := exec.LookPath(candidate); err == nil {
				engine = candidate
				break
			}
		}
	}
	switch {
	case image == "":
		skipOrFail(t, "set "+imageEnv+" to a built image (docker build -t netdoc-sim:test .)")
	case engine == "":
		skipOrFail(t, "no docker or podman on this machine; set "+engineEnv)
	}
	return engine, image
}

func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv(requireEnv) == "1" {
		t.Fatalf("%s is set, so this is a failure rather than a skip: %s", requireEnv, reason)
	}
	t.Skip(reason)
}

// result is one container invocation's outcome. Exit codes are the point of
// several tests here, so a non-zero one is data rather than an error.
type result struct {
	stdout, stderr string
	code           int
}

// runImage runs the image the documented way. args is a netdoc-sim command
// line, which is the boundary the image is built around: the entrypoint is
// netdoc-sim, so nothing re-parses what comes after the image name.
func runImage(t *testing.T, args ...string) result {
	t.Helper()
	return runImageWith(t, documentedOptions, args)
}

// runImageWith takes the engine options too, for the tests that are about the
// options rather than about netdoc-sim.
func runImageWith(t *testing.T, opts, args []string) result {
	t.Helper()
	engine, image := engineAndImage(t)
	argv := append([]string{"run", "--rm"}, opts...)
	if runtime.GOOS == "linux" && engine == "docker" {
		argv = append(argv, "--security-opt", "apparmor=unconfined")
	}
	argv = append(argv, image)
	argv = append(argv, args...)

	ctx, cancel := context.WithTimeout(t.Context(), containerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, argv...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := result{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("%s %s: %v\nstderr: %s", engine, strings.Join(argv, " "), err, res.stderr)
	}
	if ctx.Err() != nil {
		t.Fatalf("%s %s: timed out after %s", engine, strings.Join(argv, " "), containerTimeout)
	}
	return res
}

// imageLabel reads one OCI label off the image itself, which is the tag's own
// claim about which release it is.
func imageLabel(t *testing.T, name string) string {
	t.Helper()
	engine, image := engineAndImage(t)
	out, err := exec.Command(engine, "image", "inspect", "--format",
		"{{index .Config.Labels \""+name+"\"}}", image).Output()
	if err != nil {
		// Podman's inspect exposes labels one level up from Docker's.
		out, err = exec.Command(engine, "image", "inspect", "--format",
			"{{index .Labels \""+name+"\"}}", image).Output()
	}
	if err != nil {
		t.Fatalf("reading label %s: %v", name, err)
	}
	return strings.TrimSpace(string(out))
}

// 1, 2, 3 and 7 of the artifact contract at once: both binaries exist, at the
// paths the image promises, reporting the version the image tag claims.
//
// The paths matter as much as the versions. netdoc-sim finds netdoc as its own
// sibling, so /usr/bin/netdoc is what a challenge in this image will run, and
// a test that only asked "is netdoc somewhere" would pass on an image where the
// two came from different builds.
func TestImageShipsBothBinariesAtOneVersion(t *testing.T) {
	want := imageLabel(t, "org.opencontainers.image.version")
	if want == "" {
		t.Fatal("the image carries no org.opencontainers.image.version label")
	}
	for _, tt := range []struct {
		binary, printed string
		opts, args      []string
	}{
		// netdoc-sim is the entrypoint, so it answers for itself.
		{binary: "/usr/bin/netdoc-sim", printed: "netdoc-sim " + want, args: []string{"version"}},
		{binary: "/usr/bin/netdoc", printed: "netdoc " + want,
			opts: []string{"--entrypoint", "/usr/bin/netdoc"}, args: []string{"-version"}},
	} {
		got := strings.TrimSpace(runImageWith(t, append(slices.Clone(documentedOptions), tt.opts...), tt.args).stdout)
		if got != tt.printed {
			t.Errorf("%s reports %q, but the image is labelled version %q: the image tag and the "+
				"binaries in it have to be one release", tt.binary, got, want)
		}
	}
}

// The image runs the simulator this repository maintains, not a container-shaped
// imitation of it: a real scenario, on the linux-netns backend, with the
// scenario's own expectations met and every namespace released afterwards.
func TestImageRunsTheRealNamespaceBackend(t *testing.T) {
	res := runImage(t, "run", "broken-dns", "-json")
	if res.code != 0 {
		t.Fatalf("run broken-dns exited %d\nstderr: %s", res.code, res.stderr)
	}
	var report struct {
		Scenario string `json:"scenario"`
		Backend  string `json:"backend"`
		Result   string `json:"result"`
		Cleanup  struct {
			Done bool     `json:"done"`
			Kept bool     `json:"kept"`
			Err  []string `json:"errors"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("run -json did not produce a report: %v\n%s", err, res.stdout)
	}
	if report.Backend != "linux-netns" {
		t.Errorf("backend = %q, want linux-netns: the container must not introduce a second backend",
			report.Backend)
	}
	if report.Result != "PASS" {
		t.Errorf("result = %q, want PASS: the scenario's own expectations have to hold in here too",
			report.Result)
	}
	if !report.Cleanup.Done || report.Cleanup.Kept || len(report.Cleanup.Err) > 0 {
		t.Errorf("cleanup = %+v, want a completed release with no errors", report.Cleanup)
	}
}

// A challenge id is the whole puzzle, so the same id has to be the same puzzle
// in the container as anywhere else, twice running. The netdoc object is the
// other half of a reproducible result: it has to name the binary this image
// ships, so nobody can attribute a score to a netdoc that was never here.
func TestImageChallengeIsDeterministicAndRunsTheEmbeddedNetdoc(t *testing.T) {
	type challengeResult struct {
		ChallengeID     string `json:"challenge_id"`
		Difficulty      string `json:"difficulty"`
		Base            string `json:"base_scenario"`
		Case            int    `json:"case"`
		CaseFingerprint string `json:"case_fingerprint"`
		Netdoc          struct {
			Path    string `json:"path"`
			Version string `json:"version"`
		} `json:"netdoc"`
		Truth struct {
			Answer    string `json:"answer"`
			Scoreable bool   `json:"scoreable"`
		} `json:"truth"`
		NetworkDoctor struct {
			Score string `json:"score"`
		} `json:"network_doctor"`
	}
	play := func() challengeResult {
		t.Helper()
		res := runImage(t, "challenge", "-id", challengeID, "-give-up", "-json")
		// Giving up is a loss, and a loss is exit 1.
		if res.code != 1 {
			t.Fatalf("challenge exited %d, want 1\nstderr: %s", res.code, res.stderr)
		}
		var got challengeResult
		if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
			t.Fatalf("challenge -json did not produce a result: %v\n%s", err, res.stdout)
		}
		return got
	}

	first, second := play(), play()
	if first != second {
		t.Errorf("the same id produced two different challenges:\n%+v\n%+v", first, second)
	}
	if first.ChallengeID != challengeID {
		t.Errorf("result names challenge %q, want %q", first.ChallengeID, challengeID)
	}
	if !first.Truth.Scoreable || first.Truth.Answer == "" {
		t.Errorf("truth = %+v, want an independently established condition", first.Truth)
	}
	if first.NetworkDoctor.Score == "" {
		t.Error("Network Doctor was not scored, so the container ran no diagnosis")
	}
	if first.Netdoc.Path != "/usr/bin/netdoc" {
		t.Errorf("the challenge ran %q, want the /usr/bin/netdoc this image ships; a challenge that "+
			"found some other binary is a result nobody can attribute", first.Netdoc.Path)
	}
	if want := "netdoc " + imageLabel(t, "org.opencontainers.image.version"); first.Netdoc.Version != want {
		t.Errorf("the challenge recorded %q, want %q from this image's own build",
			first.Netdoc.Version, want)
	}
}

// The container runtime has to hand back what netdoc-sim decided, or the image
// is unusable in a script: 0 for a correct diagnosis, 1 for a wrong one, 2 for
// bad arguments, 3 for a simulation that could not run.
func TestImageExitStatusPropagates(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want int
	}{
		{"a correct answer", []string{"challenge", "-id", challengeID, "-answer", challengeCorrectAnswer, "-json"}, 0},
		{"a wrong answer", []string{"challenge", "-id", challengeID, "-answer", "healthy", "-json"}, 1},
		{"an unknown answer", []string{"challenge", "-id", challengeID, "-answer", "nonsense", "-json"}, 2},
		{"an unknown scenario", []string{"run", "no-such-scenario"}, 2},
		{"capabilities", []string{"capabilities"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := runImage(t, tt.args...).code; got != tt.want {
				t.Errorf("exit code %d, want %d", got, tt.want)
			}
		})
	}
}

// The privilege floor, measured rather than asserted in prose. A simulation
// creates a user namespace and becomes root inside it; on the host side of that
// namespace it needs no capability at all, so dropping every one of them must
// change nothing. This is the test that fails if someone later "fixes" a
// problem by adding a capability to the documented run command.
func TestImageNeedsNoCapabilities(t *testing.T) {
	res := runImageWith(t, []string{"--cap-drop", "ALL", "--security-opt", "seccomp=unconfined"},
		[]string{"run", "broken-dns"})
	if res.code != 0 {
		t.Fatalf("with every capability dropped, run broken-dns exited %d\nstdout: %s\nstderr: %s",
			res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "Cleanup:  ok") {
		t.Errorf("no clean teardown with capabilities dropped:\n%s", res.stdout)
	}
}

// The negative half of the same measurement: the one permission that is
// genuinely required is the ability to create a user namespace, which is why
// Docker's default seccomp profile, which denies clone(CLONE_NEWUSER) unless
// the container was given CAP_SYS_ADMIN, is the thing the documented
// --cap-add SYS_ADMIN is for.
//
// The profile below reproduces exactly that denial and nothing else, so a
// failure here means the requirement moved, and a pass proves the run command's
// one flag is load-bearing rather than superstition.
func TestImageWithoutUserNamespacesFailsCleanly(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "deny-userns.json")
	// clone with CLONE_NEWUSER (0x10000000) set, and the clone3/unshare routes
	// to the same thing, are refused; everything else is allowed, so the only
	// variable is the namespace.
	const denyUserNamespaces = `{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {"names": ["clone"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
     "args": [{"index": 0, "value": 268435456, "valueTwo": 268435456, "op": "SCMP_CMP_MASKED_EQ"}]},
    {"names": ["clone3", "unshare"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}
  ]
}`
	if err := os.WriteFile(profile, []byte(denyUserNamespaces), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runImageWith(t, append(slices.Clone(documentedOptions), "--security-opt", "seccomp="+profile),
		[]string{"run", "healthy"})
	if res.code != 3 {
		t.Fatalf("exit code %d, want 3 (the simulation could not run)\nstdout: %s\nstderr: %s",
			res.code, res.stdout, res.stderr)
	}
	// It has to say what was refused. "operation not permitted" on its own sends
	// somebody to their host's network settings.
	for _, want := range []string{"cannot create the user, network and mount namespaces", "netdoc-sim capabilities"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("stderr does not mention %q:\n%s", want, res.stderr)
		}
	}
	// Refusing is the whole behaviour: it must not fall back to a degraded
	// simulation, and it must not report one.
	if strings.Contains(res.stdout, "Cleanup:") {
		t.Errorf("a simulation ran anyway:\n%s", res.stdout)
	}
}

// A container that is reused, whether an interactive session where somebody
// plays several challenges or a shell someone kept open, must not accumulate the
// wreckage of the runs that went wrong. The simulator's guarantee is that a
// killed run leaks nothing, because the kernel reclaims namespaces with the
// processes holding them; this checks that the guarantee survives being inside
// a container, where those processes are children of PID 1 rather than of a
// login shell.
func TestImageCleansUpAfterAnInterruptedRun(t *testing.T) {
	const script = `
netdoc-sim run broken-dns >/dev/null 2>&1 &
sim=$!
sleep 5
kill -INT $sim 2>/dev/null
wait $sim 2>/dev/null
sleep 1
echo "leftover-processes: $(ps -eo comm | grep -c netdoc)"
echo "kept-simulations: $(netdoc-sim list)"
echo "leftover-workspaces: $(ls -d /tmp/netdoc-sim-* 2>/dev/null | wc -l)"
netdoc-sim run healthy >/dev/null 2>&1
echo "later-run: $?"
netdoc-sim challenge -id ` + challengeID + ` -give-up -json >/dev/null 2>&1
echo "later-challenge: $?"
echo "final-processes: $(ps -eo comm | grep -c netdoc)"
`
	res := runImageWith(t, append(slices.Clone(documentedOptions), "--entrypoint", "/bin/sh"),
		[]string{"-c", script})
	out := res.stdout
	for _, want := range []string{
		// Nothing of the interrupted run is left: no process still holding a
		// namespace, no state record, no workspace.
		"leftover-processes: 0",
		"kept-simulations: no simulations are being kept alive",
		"leftover-workspaces: 0",
		// And the container is still usable afterwards, for both commands.
		"later-run: 0",
		"later-challenge: 1",
		"final-processes: 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s\nstderr: %s", want, out, res.stderr)
		}
	}
}
