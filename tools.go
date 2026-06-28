package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key  string // single-key hotkey / stable id
	Name string // display label
	Bin  string // binary to resolve via LookPath
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	Build func(t *Target) (args, env []string, display string)
}

// Available reports whether the tool's binary is installed.
func (t Tool) Available() bool {
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// toolsFor returns the drill-down tools applicable to the target. The
// target-independent tools (ip route, ss) are always offered; the
// target-dependent set (ping, dig, curl, traceroute, mtr) only when a host is
// given.
func toolsFor(t *Target) []Tool {
	tools := []Tool{
		{
			Key: "i", Name: "ip route", Bin: "ip",
			Build: func(*Target) ([]string, []string, string) {
				args := []string{"route"}
				return args, nil, "ip " + shellArgs(args)
			},
		},
		{
			Key: "s", Name: "ss", Bin: "ss",
			Build: func(*Target) ([]string, []string, string) {
				args := []string{"-tunp"}
				return args, nil, "ss " + shellArgs(args)
			},
		},
	}
	if t == nil {
		return tools
	}
	host := t.Host
	return append(tools,
		Tool{
			Key: "p", Name: "ping", Bin: "ping",
			Build: func(*Target) ([]string, []string, string) {
				args := []string{"-c", "4", "-W", "2", host}
				return args, nil, "ping " + shellArgs(args)
			},
		},
		Tool{
			Key: "d", Name: "dig", Bin: "dig",
			Build: func(*Target) ([]string, []string, string) {
				args := []string{"+time=2", "+tries=1", host}
				return args, nil, "dig " + shellArgs(args)
			},
		},
		Tool{
			Key: "c", Name: "curl", Bin: "curl",
			Build: func(t *Target) ([]string, []string, string) {
				url := schemeFor(t) + "://" + host
				if t.PortExplicit {
					url += ":" + strconv.Itoa(t.Port)
				}
				args := []string{
					"-q", "-sS", "--head", "-o", "/dev/null",
					"--max-redirs", "0", "--noproxy", "*",
					"--proto", "=https,http",
					"--connect-timeout", "3", "--max-time", "10",
					"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
					url,
				}
				// LC_ALL=C is set via env, not an argv token, for locale-proof -w output.
				env := append(os.Environ(), "LC_ALL=C")
				return args, env, "LC_ALL=C curl " + shellArgs(args)
			},
		},
		Tool{
			Key: "t", Name: "traceroute", Bin: "traceroute",
			Build: func(*Target) ([]string, []string, string) {
				args := []string{"-w", "2", "-q", "1", "-m", "20", host}
				return args, nil, "traceroute " + shellArgs(args)
			},
		},
		Tool{
			Key: "m", Name: "mtr", Bin: "mtr",
			Build: func(*Target) ([]string, []string, string) {
				// report mode only — never curses inside our TUI.
				args := []string{"--report", "--report-cycles", "5", host}
				return args, nil, "mtr " + shellArgs(args)
			},
		},
	)
}

func schemeFor(t *Target) string {
	if t.Proto == ProtoHTTP {
		return "http"
	}
	return "https"
}

// shellArgs renders argv for *display only* (never executed), quoting tokens with
// shell-special characters so the shown command is copy-pasteable.
func shellArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'\\$*?#&|;<>(){}[]`") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// Confidence grades a best-effort extracted fact.
type Confidence int

const (
	Low Confidence = iota
	Medium
	High
)

// Fact is a typed, generation-scoped datum extracted from a finished tool's
// output. Facts are display-only evidence — they never feed the diagnosis.
type Fact struct {
	Key, Value string
	Confidence Confidence
	Source     string
	Target     string
	Generation int
	JobID      string
	At         time.Time
}

// extractFacts pulls a few stable facts from a finished tool's stdout. Best
// effort across tool versions; the raw (sanitized) output stays authoritative.
func extractFacts(toolKey string, stdout []string, gen int, jobID, target string) []Fact {
	mk := func(k, v string, c Confidence) Fact {
		return Fact{Key: k, Value: v, Confidence: c, Source: toolKey, Target: target, Generation: gen, JobID: jobID, At: time.Now()}
	}
	var facts []Fact
	switch toolKey {
	case "c": // curl -w "http_code time_total remote_ip ssl_verify_result"
		for i := len(stdout) - 1; i >= 0; i-- {
			f := strings.Fields(stdout[i])
			if len(f) == 4 {
				facts = append(facts,
					mk("http_code", f[0], High),
					mk("time_total", f[1]+"s", High),
					mk("remote_ip", f[2], High),
					mk("ssl_verify", f[3], Medium))
				break
			}
		}
	case "p": // ping: "rtt min/avg/max/mdev = a/b/c/d ms" and "X% packet loss"
		for _, ln := range stdout {
			if i := strings.Index(ln, "packet loss"); i >= 0 {
				end := i + len("packet loss")
				if j := strings.LastIndex(ln[:i], ","); j >= 0 {
					facts = append(facts, mk("packet_loss", strings.TrimSpace(ln[j+1:end]), High))
				}
			}
			if i := strings.Index(ln, "min/avg/max"); i >= 0 {
				if eq := strings.Index(ln, "="); eq >= 0 {
					facts = append(facts, mk("rtt", strings.TrimSpace(ln[eq+1:]), High))
				}
			}
		}
	case "d": // dig: collect answer-section A records
		var as []string
		for _, ln := range stdout {
			f := strings.Fields(ln)
			if len(f) >= 5 && f[3] == "A" {
				as = append(as, f[4])
			}
		}
		if len(as) > 0 {
			facts = append(facts, mk("A_records", strings.Join(as, ", "), High))
		}
	}
	return facts
}
