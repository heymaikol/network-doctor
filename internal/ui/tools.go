package ui

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Tool is a drill-down adapter: a bounded external command keyed to a hotkey.
type Tool struct {
	Key     string        // single-key hotkey / stable id
	Name    string        // plain-English display label
	Bin     string        // binary to resolve via LookPath
	Timeout time.Duration // per-tool job timeout; 0 = default toolTimeout
	Confirm bool          // show the exact command and wait for a keypress before running
	// Build returns the argv (never a shell string), the process env (nil =
	// inherit), and a human-display command string (shell-quoted, display only).
	// sel is the address the diagnostic chain actually reached the target on
	// (ProbeTargetTCP's SelectedIP), or nil when unknown; family-sensitive
	// tools use it so a hostname that resolved to AAAA isn't probed over IPv4.
	Build func(t *diagnostic.Target, sel net.IP) (args, env []string, display string)

	Available   bool   // whether the tool's binary is installed
	networkCIDR string // LAN snapshot context, committed only when discovery starts
}

var toolLookPath = exec.LookPath

// selectedIP is the address the target TCP probe reached the host on, or nil
// before that probe has a result (toolbox mode, a failed or unfinished run).
func (m model) selectedIP() net.IP { return m.results[diagnostic.ProbeTargetTCP].SelectedIP }

// toolBind is the --iface selection as the drill-down tools need it: the
// interface name the user named (empty when --iface named an exact local IP,
// or was not given) and the one source address per family the probes are
// pinned to. The zero value means "no --iface", and every builder below then
// emits exactly the command it emitted before this existed.
//
// The split matters because the tools disagree: some options take an interface
// name (traceroute -i), some take a source address (pathping -i), and one takes
// either (Linux ping -I). A name binds both families at once; an address binds
// one, so it must match the family of the address the tool will actually talk
// to.
type toolBind struct {
	iface  string
	v4, v6 net.IP
}

func bindFor(sources *diagnostic.SourceAddresses) toolBind {
	if sources == nil {
		return toolBind{}
	}
	return toolBind{iface: sources.Iface, v4: sources.IPv4, v6: sources.IPv6}
}

// source is the local address to bind for a destination in dst's family, or
// nil when the selection has none: no source of the right family means the
// caller must leave the option off, never substitute the other family.
//
// A nil dst (a hostname with no probe result yet) has no family to follow. A
// single-family selection is still unambiguous, and --iface <address> always
// is one, so it binds; a dual-stack interface does not, because picking one
// half would pin a command the resolver might have taken the other way.
func (b toolBind) source(dst net.IP) net.IP {
	switch {
	case isIPv6(dst):
		return b.v6
	case dst != nil:
		return b.v4
	case b.v6 == nil:
		return b.v4
	case b.v4 == nil:
		return b.v6
	}
	return nil
}

// bindFunc renders a tool's binding option for a destination address, or nil
// when that tool cannot bind for this destination.
type bindFunc func(dst net.IP) []string

// addr binds through an option that takes a source address only.
func (b toolBind) addr(flag string) bindFunc {
	return func(dst net.IP) []string {
		if src := b.source(dst); src != nil {
			return []string{flag, src.String()}
		}
		return nil
	}
}

// named binds through nameFlag when --iface named an interface, and falls back
// to addrFlag with the family-matched source when it named an exact IP.
func (b toolBind) named(nameFlag, addrFlag string) bindFunc {
	return func(dst net.IP) []string {
		if b.iface != "" {
			return []string{nameFlag, b.iface}
		}
		return b.addr(addrFlag)(dst)
	}
}

// either binds through a single option that accepts a name or an address.
func (b toolBind) either(flag string) bindFunc { return b.named(flag, flag) }

// v6Only gates a binding to IPv6 destinations. Microsoft documents both
// Windows source-address options that netdoc could use, ping /S and
// tracert /S, as "available on IPv6 only", so an IPv4 or not-yet-known
// destination keeps the unbound command instead of carrying an option that
// command rejects for the family it is about to use.
func v6Only(bind bindFunc) bindFunc {
	return func(dst net.IP) []string {
		if !isIPv6(dst) {
			return nil
		}
		return bind(dst)
	}
}

const lanDiscoveryName = "LAN scan"

func cacheAvailability(tools []Tool) []Tool {
	for i := range tools {
		_, err := toolLookPath(tools[i].Bin)
		tools[i].Available = err == nil
	}
	return tools
}

// toolsFor returns the drill-down tools for the target on the given GOOS
// (production passes runtime.GOOS; tests exercise all tables from one OS).
// Same hotkeys everywhere. The target-independent tools (routes, sockets) are
// always offered; the target-dependent set only when a host is given.
// b is the --iface selection the probes are pinned to, so the drill-downs
// leave from the same interface the evidence came from; a zero b is "no
// --iface" and every command keeps the shape it has without one.
func toolsFor(t *diagnostic.Target, goos string, b toolBind) []Tool {
	quote := quoterFor(goos)

	var tools []Tool
	switch goos {
	case "darwin":
		tools = []Tool{
			staticTool(quote, "I", "route table", "netstat", "-rn"),
			staticTool(quote, "s", "open sockets", "netstat", "-an", "-p", "tcp"),
		}
	case "windows":
		tools = []Tool{
			staticTool(quote, "I", "route table", "route", "print", "-4"),
			staticTool(quote, "s", "open sockets", "netstat", "-ano"),
		}
	default: // linux (and any other unix)
		tools = []Tool{
			staticTool(quote, "I", "route table", "ip", "route"),
			staticTool(quote, "s", "open sockets", "ss", "-tunp"),
		}
	}
	if t == nil {
		return cacheAvailability(tools)
	}
	// A link-local target is only reachable with its zone, and every tool
	// that connects takes the scoped spelling. A name lookup never does.
	host, name := t.ScopedHost(), t.Host

	switch goos {
	case "darwin":
		// BSD ping's -W is milliseconds and semantics differ; omit it.
		// macOS ping binds an interface with -b boundif (an Apple addition)
		// and a source address with -S src_addr.
		tools = append(tools, boundTool(quote, "p", "ping the host", "ping", b.named("-b", "-S"), host, "-c", "4"))
	case "windows":
		// Windows ping has no interface option, and its -S srcaddr is
		// documented IPv6-only.
		tools = append(tools, boundTool(quote, "p", "ping the host", "ping", v6Only(b.addr("-S")), host, "-n", "4", "-w", "2000"))
	default:
		// iputils ping's -I takes "either interface name or address".
		tools = append(tools, boundTool(quote, "p", "ping the host", "ping", b.either("-I"), host, "-c", "4", "-W", "2"))
	}

	if goos == "windows" {
		tools = append(tools, staticTool(quote, "d", "DNS lookup", "nslookup", name))
	} else if t.IP != nil {
		tools = append(tools, staticTool(quote, "d", "reverse DNS lookup", "dig", "+time=2", "+tries=1", "-x", name))
	} else {
		tools = append(tools, digTool(quote, name))
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
		tools = append(tools, curlTool(host, goos, b))
	}

	if goos == "windows" {
		tools = append(tools,
			boundTool(quote, "t", "trace the path", "tracert", v6Only(b.addr("-S")), host, "-w", "2000", "-h", "20"))
		// pathping's full run takes ~30–60 s; give it its own budget.
		// Unlike ping and tracert, pathping's -i IPaddress carries no family
		// restriction.
		pp := boundTool(quote, "m", "path quality", "pathping", b.addr("-i"), host, "-h", "20", "-q", "5", "-p", "100", "-w", "500")
		pp.Timeout = 90 * time.Second
		tools = append(tools, pp)
	} else {
		// mtr report mode only, never curses inside our TUI. Report mode
		// prints nothing until the last cycle, so a run cut short by the
		// default budget yields no output at all; five cycles plus reverse DNS
		// against a distant host regularly passes 12s, so it gets its own.
		mt := boundTool(quote, "m", "path quality", "mtr", b.named("-I", "-a"), host, "--report", "--report-cycles", "5")
		mt.Timeout = 45 * time.Second
		tools = append(tools,
			// Both Linux and BSD traceroute take -i device and -s src_addr.
			boundTool(quote, "t", "trace the path", "traceroute", b.named("-i", "-s"), host, "-w", "2", "-q", "1", "-m", "20"),
			mt)
	}

	// Targeted nmap actively scans the host, so it is gated behind a shown-command
	// confirmation (Confirm) rather than launching like passive tools.
	tools = append(tools, nmapTool(quote, host))
	return cacheAvailability(tools)
}

// nmapTool builds the nmap adapter: an explicitly-confirmed port scan with
// conservative defaults, because a scan can trip the target's intrusion
// detection. A plain TCP connect scan (-sT, so no raw sockets or root, and the
// shown command is exactly what runs at any privilege), nmap's default -T3
// timing (deliberately not bumped to -T4, which risks false negatives on
// lossy/high-latency paths to arbitrary hosts), host discovery skipped (-Pn,
// the target is
// already known reachable), and a hard --host-timeout so the run always ends
// and yields partial results before the job timeout kills it. An explicit
// target port scans only that port; otherwise nmap's default top-1000 ports
// (which include 22/80/443). A full -p- sweep is deliberately avoided: it can't
// cover all 65535 ports inside --host-timeout, so it times out and reports
// nothing, which is worse than a top-1000 scan that finishes. Deliberately no
// -sV/-O/-A: version and OS detection are louder, slower, and not needed to
// answer "is the port open?".
//
// Deliberately not bound to --iface: nmap documents -S only as "Spoof source
// address", a raw-packet feature whose effect on a connect scan is stated
// nowhere but a runtime warning, and -e needs the raw sockets netdoc never
// asks for. A scan that silently ignored the binding would be worse evidence
// than one that visibly does not claim it.
func nmapTool(quote func([]string) string, host string) Tool {
	return Tool{
		Key: "n", Name: "port scan", Bin: "nmap", Confirm: true, Timeout: 120 * time.Second,
		Build: func(t *diagnostic.Target, sel net.IP) ([]string, []string, string) {
			args := []string{"-sT", "-Pn", "--host-timeout", "110s"}
			if isIPv6(targetIP(t, sel)) {
				args = append(args, "-6")
			}
			if t.PortExplicit {
				args = append(args, "-p", strconv.Itoa(t.Port))
			}
			args = append(args, host)
			return args, nil, "nmap " + quote(args)
		},
	}
}

// targetIP is the address a family-sensitive tool should assume: a literal
// target pins the family outright, otherwise the address the chain actually
// reached the host on. nil (no literal, no successful target probe) means
// "unknown", and callers keep their resolver-default behaviour.
func targetIP(t *diagnostic.Target, sel net.IP) net.IP {
	if t != nil && t.IP != nil {
		return t.IP
	}
	return sel
}

func isIPv6(ip net.IP) bool { return ip != nil && ip.To4() == nil }

// digTool builds the forward DNS lookup for a hostname target. The query type
// follows the family the chain reached the host on, so an AAAA-only name isn't
// looked up as an A record that doesn't exist; with no selected IP the type is
// left off and dig's default (A) applies.
func digTool(quote func([]string) string, host string) Tool {
	return Tool{
		Key: "d", Name: "DNS lookup", Bin: "dig",
		Build: func(t *diagnostic.Target, sel net.IP) ([]string, []string, string) {
			args := []string{"+time=2", "+tries=1"}
			if ip := targetIP(t, sel); ip != nil {
				if isIPv6(ip) {
					args = append(args, "-t", "AAAA")
				} else {
					args = append(args, "-t", "A")
				}
			}
			args = append(args, host)
			return args, nil, "dig " + quote(args)
		},
	}
}

func lanDiscoveryTool(quote func([]string) string, cidr string) Tool {
	return Tool{
		Key: "v", Name: lanDiscoveryName, Bin: "nmap", Confirm: true, Timeout: 60 * time.Second, networkCIDR: cidr,
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) {
			args := []string{"--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", cidr}
			return args, nil, "nmap " + quote(args)
		},
	}
}

// curlTool builds the curl adapter. On Windows the binary and the displayed
// command are both curl.exe, so the pasted line bypasses PowerShell 5.1's
// curl→Invoke-WebRequest alias; the display targets PowerShell quoting (cmd.exe
// paste is not supported). Elsewhere the display keeps the POSIX LC_ALL=C form.
//
// --interface takes an "interface name, IP address or hostname", with one
// documented exception: "curl does not support using network interface names
// for this option on Windows". Windows therefore gets the family-matched
// source address instead: the same link, spelled the way that build honors.
func curlTool(host, goos string, b toolBind) Tool {
	if strings.Contains(host, ":") {
		// A URL spells a zone "%25" (RFC 6874).
		host = "[" + strings.Replace(host, "%", "%25", 1) + "]"
	}
	bin, devNull := "curl", "/dev/null"
	bind := b.either("--interface")
	if goos == "windows" {
		bin, devNull = "curl.exe", "NUL"
		bind = b.addr("--interface")
	}
	return Tool{
		Key: "c", Name: "web check", Bin: bin,
		Build: func(t *diagnostic.Target, sel net.IP) ([]string, []string, string) {
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
			}
			args = append(args, bind(targetIP(t, sel))...)
			args = append(args, url)
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
// avoids both host-key prompts and writes to the user's known_hosts. Since
// host keys aren't verified, PreferredAuthentications=none stops after
// banner/kex, never offering agent keys or a username's worth of trust to
// whatever answered. ConnectTimeout plus the job timeout bound the run.
func sshTool(quote func([]string) string, host string, port int, goos string) Tool {
	knownHosts := "/dev/null"
	if goos == "windows" {
		knownHosts = "NUL"
	}
	return staticTool(quote, "c", "SSH check", "ssh",
		"-v",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-o", "PreferredAuthentications=none",
		"-p", strconv.Itoa(port),
		host)
}

// smtpTool builds a bounded SMTP STARTTLS check for the "c" slot. In the TUI
// the process gets an empty stdin, so s_client exits right after the handshake
// instead of waiting for commands; the job timeout bounds the rest.
func smtpTool(quote func([]string) string, host string, port int) Tool {
	return staticTool(quote, "c", "SMTP check", "openssl",
		"s_client", "-starttls", "smtp", "-connect", net.JoinHostPort(host, strconv.Itoa(port)))
}

// staticTool builds a target-independent Tool whose argv is fixed at construction
// (a host, if any, is already baked into args). Callers never mutate the argv,
// and exec.Command copies it, so Build hands out the captured slice as-is.
func staticTool(quote func([]string) string, key, name, bin string, args ...string) Tool {
	return Tool{Key: key, Name: name, Bin: bin, Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) {
		return args, nil, bin + " " + quote(args)
	}}
}

// boundTool builds a host-directed tool as fixed flags, then the binding
// option for the --iface selection, then the host, since every command shaped this
// way takes its destination last. bind returns nothing when there is no
// --iface, or when this tool has no option that fits the destination's family,
// so the argv is then exactly the unbound one.
func boundTool(quote func([]string) string, key, name, bin string, bind bindFunc, host string, flags ...string) Tool {
	return Tool{Key: key, Name: name, Bin: bin, Build: func(t *diagnostic.Target, sel net.IP) ([]string, []string, string) {
		// Full-slice expression: each Build owns its argv, so a later append
		// can never write into the captured flags.
		args := append(flags[:len(flags):len(flags)], bind(targetIP(t, sel))...)
		args = append(args, host)
		return args, nil, bin + " " + quote(args)
	}}
}

func quoterFor(goos string) func([]string) string {
	if goos == "windows" {
		return psArgs
	}
	return shellArgs
}

// quoteArgs single-quotes any token containing one of special (and empty tokens),
// escaping embedded quotes as escQuote. Both shells agree on everything but those
// two, so they differ only in the arguments they pass here.
func quoteArgs(args []string, special, escQuote string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, special) {
			out[i] = "'" + strings.ReplaceAll(a, "'", escQuote) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// shellArgs renders argv for *display only* (never executed), quoting tokens with
// shell-special characters so the shown command is copy-pasteable in a POSIX shell.
func shellArgs(args []string) string {
	return quoteArgs(args, " \t\"'\\$*?#&|;<>(){}[]`", `'\''`)
}

// psArgs renders argv for *display only* targeting PowerShell: single-quote
// literals with embedded quotes doubled, which also keeps curl's %{…} format
// string inert. cmd.exe paste is explicitly not supported (one shell, exact rules).
func psArgs(args []string) string {
	return quoteArgs(args, " \t\"'`$*?#&|;<>(){}[],%^@", "''")
}
