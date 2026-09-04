package app

import (
	"flag"
	"fmt"
	"io"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
)

// printUsage writes the full help text: usage line, the target grammar
// ParseTarget accepts, and the flags.
func printUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: netdoc [flags] [target]
       netdoc --profile github
       netdoc --profile ssh target
       netdoc --via ssh-destination [flags] [target]
       netdoc --peer-listen IP:port [--peer-listen IP:port]
       netdoc --peer-connect [--json]
       netdoc --compare before.ndoc after.ndoc [--json]
       netdoc --two-sided here.ndoc there.ndoc [--json]
       netdoc --two-sided --via ssh-destination [target] [--json]

Diagnoses network connectivity layer by layer. With no target it runs the
generic checks; with a target it also probes that endpoint. Flags may be
given before or after the target.

--profile runs a built-in service plan headlessly. Use --profile list to see
which profiles need a target and which fixed endpoints they test.

--via runs the checks on an SSH destination and presents the finished
diagnosis here. The destination goes to the system ssh client as typed, so
~/.ssh/config aliases work; the SSH host needs its own netdoc on the PATH of a
non-interactive session, or NETDOC_VIA_COMMAND set to its path. It is headless
and needs no terminal. With --two-sided, the same ordinary diagnosis also runs
locally and the two snapshots are localized together.

Peer mode is headless. The listener prints a temporary direct-connect pairing
string; the connector reads it from a hidden prompt so it does not enter argv.

Compare mode is headless and runs no probes: it reads two snapshots written by
--save or --support and reports what changed between them. It exits 0 when they describe the
same state and 1 when they do not.

--two-sided reads two snapshots as two machines looking at one target and says
whether the evidence places a failure on side A, side B, something shared, or
nowhere. With two file arguments it stays offline. With --via it concurrently
acquires side A locally and side B on the SSH host, then applies the same
snapshot localization. Both forms refuse different effective targets.

Target forms:
`+diagnostic.TargetForms+"\n\nFlags:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func printProfiles(w io.Writer, registry profile.Registry) {
	fmt.Fprintln(w, "Available service profiles:")
	for _, definition := range registry.List() {
		target := "no target"
		if definition.Target == profile.TargetRequired {
			target = "target required"
		}
		fmt.Fprintf(w, "  %s (%s): %s\n", definition.Name, target, definition.Description)
	}
}
