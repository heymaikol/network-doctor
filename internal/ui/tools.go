package ui

import (
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key     string        // single-key hotkey / stable id
	Name    string        // display label
	Purpose string        // plain-English toolbox label
	Bin     string        // binary to resolve via LookPath
	Timeout time.Duration // per-tool job timeout; 0 = default toolTimeout
	Confirm bool          // show the exact command and wait for a keypress before running
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	Build func(t *diagnostic.Target) (args, env []string, display string)

	available bool
}

var toolLookPath = exec.LookPath

const lanDiscoveryName = "LAN discovery"

// Available reports whether the tool's binary is installed.
func (t Tool) Available() bool { return t.available }

func cacheAvailability(tools []Tool) []Tool {
	for i := range tools {
		_, err := toolLookPath(tools[i].Bin)
		tools[i].available = err == nil
	}
	return tools
}

// toolsFor returns the drill-down tools for the target on the given GOOS
// (production passes runtime.GOOS; tests exercise all tables from one OS).
// Same hotkeys everywhere. The target-independent tools (routes, sockets) are
// always offered; the target-dependent set only when a host is given.
func toolsFor(t *diagnostic.Target, goos string) []Tool {
	quote := quoterFor(goos)

	var tools []Tool
	switch goos {
	case "darwin":
		tools = []Tool{
			staticTool(quote, "i", "route table", "netstat -rn", "netstat", "-rn"),
			staticTool(quote, "s", "open sockets", "netstat", "netstat", "-an", "-p", "tcp"),
		}
	case "windows":
		tools = []Tool{
			staticTool(quote, "i", "route table", "route print", "route", "print", "-4"),
			staticTool(quote, "s", "open sockets", "netstat", "netstat", "-ano"),
		}
	default: // linux (and any other unix)
		tools = []Tool{
			staticTool(quote, "i", "route table", "ip route", "ip", "route"),
			staticTool(quote, "s", "open sockets", "ss", "ss", "-tunp"),
		}
	}
	if t == nil {
		return cacheAvailability(tools)
	}
	host := t.Host

	switch goos {
	case "darwin":
		// BSD ping's -W is milliseconds and semantics differ; omit it.
		tools = append(tools, staticTool(quote, "p", "ping the host", "ping", "ping", "-c", "4", host))
	case "windows":
		tools = append(tools, staticTool(quote, "p", "ping the host", "ping", "ping", "-n", "4", "-w", "2000", host))
	default:
		tools = append(tools, staticTool(quote, "p", "ping the host", "ping", "ping", "-c", "4", "-W", "2", host))
	}

	if goos == "windows" {
		tools = append(tools, staticTool(quote, "d", "DNS lookup", "nslookup", "nslookup", host))
	} else if t.IsLiteral {
		tools = append(tools, staticTool(quote, "d", "reverse DNS lookup", "dig", "dig", "+time=2", "+tries=1", "-x", host))
	} else {
		tools = append(tools, staticTool(quote, "d", "DNS lookup", "dig", "dig", "+time=2", "+tries=1", host))
	}

	// The "c" slot is the application-layer check, matched to the target's
	// protocol: curl only fits HTTP(S), so SSH and SMTP targets get a bounded
	// handshake probe instead.
	switch t.Proto {
	case diagnostic.ProtoSSH:
		tools = append(tools, sshTool(quote, host, t.Port, goos))
	case diagnostic.ProtoSMTP:
		tools = append(tools, smtpTool(quote, host, t.Port))
	default:
		tools = append(tools, curlTool(host, goos))
	}

	if goos == "windows" {
		tools = append(tools,
			staticTool(quote, "t", "trace the path", "tracert", "tracert", "-w", "2000", "-h", "20", host))
		// pathping's full run takes ~30–60 s; give it its own budget.
		pp := staticTool(quote, "m", "path quality", "pathping", "pathping", "-h", "20", "-q", "5", "-p", "100", "-w", "500", host)
		pp.Timeout = 90 * time.Second
		tools = append(tools, pp)
	} else {
		tools = append(tools,
			staticTool(quote, "t", "trace the path", "traceroute", "traceroute", "-w", "2", "-q", "1", "-m", "20", host),
			// mtr report mode only — never curses inside our TUI.
			staticTool(quote, "m", "path quality", "mtr", "mtr", "--report", "--report-cycles", "5", host))
	}

	// Targeted nmap actively scans the host, so it is gated behind a shown-command
	// confirmation (Confirm) rather than launching like passive tools.
	tools = append(tools, nmapTool(quote, host))
	return cacheAvailability(tools)
}

// nmapTool builds the nmap adapter: an explicitly-confirmed port scan with
// conservative defaults, because a scan can trip the target's intrusion
// detection. A plain TCP connect scan (-sT — no raw sockets or root, so the
// shown command is exactly what runs at any privilege), polite timing (-T2) to
// keep the probe rate low, host discovery skipped (-Pn, the target is already
// known reachable), and a hard --host-timeout so the run always ends and yields
// partial results before the job timeout kills it. An explicit target port
// scans only that port; otherwise the 100 most common ports. Deliberately no
// -sV/-O/-A: version and OS detection are louder, slower, and not needed to
// answer "is the port open?".
func nmapTool(quote func([]string) string, host string) Tool {
	return Tool{
		Key: "n", Name: "nmap", Purpose: "port scan", Bin: "nmap", Confirm: true, Timeout: 120 * time.Second,
		Build: func(t *diagnostic.Target) ([]string, []string, string) {
			args := []string{"-sT", "-T2", "-Pn", "--host-timeout", "90s"}
			if t.IsLiteral && t.IP.To4() == nil {
				args = append(args, "-6")
			}
			if t.PortExplicit {
				args = append(args, "-p", strconv.Itoa(t.Port))
			} else {
				args = append(args, "--top-ports", "100")
			}
			args = append(args, host)
			return args, nil, "nmap " + quote(args)
		},
	}
}

func lanDiscoveryTool(quote func([]string) string, cidr string) Tool {
	return Tool{
		Key: "v", Name: lanDiscoveryName, Purpose: "discover LAN devices", Bin: "nmap", Confirm: true, Timeout: 60 * time.Second,
		Build: func(*diagnostic.Target) ([]string, []string, string) {
			args := []string{"--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", cidr}
			return args, nil, "nmap " + quote(args)
		},
	}
}

// curlTool builds the curl adapter. On Windows the binary and the displayed
// command are both curl.exe, so the pasted line bypasses PowerShell 5.1's
// curl→Invoke-WebRequest alias; the display targets PowerShell quoting (cmd.exe
// paste is not supported). Elsewhere the display keeps the POSIX LC_ALL=C form.
func curlTool(host, goos string) Tool {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	bin, devNull := "curl", "/dev/null"
	if goos == "windows" {
		bin, devNull = "curl.exe", "NUL"
	}
	return Tool{
		Key: "c", Name: "curl", Purpose: "web check", Bin: bin,
		Build: func(t *diagnostic.Target) ([]string, []string, string) {
			scheme := "https"
			if t.Proto == diagnostic.ProtoHTTP {
				scheme = "http"
			}
			url := scheme + "://" + host
			if t.PortExplicit {
				url += ":" + strconv.Itoa(t.Port)
			}
			// -q is load-bearing and must come first: it stops curl from
			// reading ~/.curlrc, whose surprises (a proxy, extra -w output)
			// would otherwise make the report's concise write-out ambiguous.
			args := []string{
				"-q", "-sS", "--head", "-o", devNull,
				"--max-redirs", "0", "--noproxy", "*",
				"--proto", "=https,http",
				"--connect-timeout", "3", "--max-time", "10",
				"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
				url,
			}
			// LC_ALL=C is set via env, not an argv token, for locale-proof -w
			// output (harmless on Windows).
			env := append(os.Environ(), "LC_ALL=C")
			if goos == "windows" {
				return args, env, "curl.exe " + psArgs(args)
			}
			return args, env, "LC_ALL=C curl " + shellArgs(args)
		},
	}
}

// sshTool builds a bounded SSH handshake check for the "c" slot: -v prints the
// server's protocol banner and key exchange on stderr, BatchMode=yes forbids
// prompts so the run never blocks on input, and a throwaway known-hosts file
// avoids both host-key prompts and writes to the user's known_hosts. If an
// agent key does authenticate, the remote command is a bare "exit".
// ConnectTimeout plus the job timeout bound the run.
func sshTool(quote func([]string) string, host string, port int, goos string) Tool {
	knownHosts := "/dev/null"
	if goos == "windows" {
		knownHosts = "NUL"
	}
	return staticTool(quote, "c", "SSH check", "ssh", "ssh",
		"-v",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-p", strconv.Itoa(port),
		host, "exit")
}

// smtpTool builds a bounded SMTP STARTTLS check for the "c" slot (ProtoSMTP is
// only inferred for ports 25 and 587, both STARTTLS). In the TUI the process
// gets an empty stdin, so s_client exits right after the handshake instead of
// waiting for commands; the job timeout bounds the rest.
func smtpTool(quote func([]string) string, host string, port int) Tool {
	return staticTool(quote, "c", "SMTP check", "openssl s_client", "openssl",
		"s_client", "-starttls", "smtp", "-connect", net.JoinHostPort(host, strconv.Itoa(port)))
}

// staticTool builds a target-independent Tool whose argv is fixed at construction
// (a host, if any, is already baked into args). slices.Clone gives each Build call
// independent slices, matching the per-call allocation of the literals it replaces.
func staticTool(quote func([]string) string, key, purpose, name, bin string, args ...string) Tool {
	return Tool{Key: key, Name: name, Purpose: purpose, Bin: bin, Build: func(*diagnostic.Target) ([]string, []string, string) {
		a := slices.Clone(args)
		return a, nil, bin + " " + quote(a)
	}}
}

func quoterFor(goos string) func([]string) string {
	if goos == "windows" {
		return psArgs
	}
	return shellArgs
}

// shellArgs renders argv for *display only* (never executed), quoting tokens with
// shell-special characters so the shown command is copy-pasteable in a POSIX shell.
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

// psArgs renders argv for *display only* targeting PowerShell: single-quote
// literals with embedded quotes doubled, which also keeps curl's %{…} format
// string inert. cmd.exe paste is explicitly not supported (one shell, exact rules).
func psArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'`$*?#&|;<>(){}[],%^@") {
			out[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}
