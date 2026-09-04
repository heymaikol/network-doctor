package app

import (
	"fmt"
	"io"
	"strings"
)

// askpass answers one ssh prompt, whose text arrives as the argument. ssh is
// told to force askpass, which routes *every* prompt here, including the
// unknown-host-key question, where handing over the password would silently
// spend it on a host nobody vouched for. So only a password or passphrase
// prompt is answered; anything else is refused and ssh says so on the
// terminal, leaving the user to answer it themselves on a run with the
// password field left blank.
// host is the machine the password was collected for; a prompt naming any
// other one is refused, since ssh's whole subtree inherits the helper. proxied
// says a jump host or proxy command is in the way, which is the one case where
// a prompt that names nobody is refused too; see promptHost.
func askpass(args []string, secret, host string, proxied bool, stdout, stderr io.Writer) int {
	prompt := strings.ToLower(strings.Join(args, " "))
	// The host-key question embeds the host name, so a target like
	// "passwordless.example.com" would otherwise satisfy the check below and
	// spend the secret on a host nobody has vouched for. Refuse the
	// confirmation question on its own terms, and refuse a promptless call
	// rather than guessing what it wanted.
	confirm := strings.Contains(prompt, "(yes/no") || strings.Contains(prompt, "fingerprint")
	if prompt == "" || confirm || (!strings.Contains(prompt, "password") && !strings.Contains(prompt, "passphrase")) {
		fmt.Fprintln(stderr, "netdoc: not answering this prompt with the stored password")
		return 1
	}
	h := promptHost(prompt)
	if h != "" && h != strings.ToLower(host) {
		fmt.Fprintln(stderr, "netdoc: not answering a password prompt for", h)
		return 1
	}
	// With a proxy in the way an unattributed prompt could be either end's, and
	// the wording is no help: a keyboard-interactive prompt is the far end's to
	// write, so a jump host that calls its question a passphrase would collect
	// the target's password. Nothing in the text is evidence, so refuse them
	// all, since the run with the password field blank puts the question back on the
	// terminal, where the user can see who is asking.
	if h == "" && proxied {
		fmt.Fprintln(stderr, "netdoc: not answering an unattributed prompt on a proxied connection")
		return 1
	}
	fmt.Fprintln(stdout, secret)
	return 0
}

// promptHost names the machine an ssh password prompt is for, or "" when the
// prompt names none. ssh asks two ways: "user@host's password:" for password
// auth, and "(user@host) " in front of whatever the server sent for
// keyboard-interactive. A ProxyJump or ProxyCommand child asks in the same
// shapes for the jump host: a prompt that matches on "password" but wants a
// secret this form never collected.
//
// The parenthesized form is read first, and it settles the question: it is
// ssh's own prefix, while the text after it belongs to the server, which is
// free to send "root@target's password:" and would otherwise pass itself off
// as the machine the user meant to log in to.
//
// A key passphrase carries no host, and neither does a keyboard-interactive
// prompt from a client too old to prefix them (< OpenSSH 8.6). Both stay
// answerable only while there is one machine it could be, since a proxy makes them
// indistinguishable from each other, and the wording can't tell them apart.
func promptHost(prompt string) string {
	if rest, ok := strings.CutPrefix(prompt, "("); ok {
		if head, _, ok := strings.Cut(rest, ")"); ok {
			return hostAfterAt(head)
		}
	}
	if head, _, ok := strings.Cut(prompt, "'s password"); ok {
		return hostAfterAt(head)
	}
	return ""
}

// hostAfterAt takes the host half of a "user@host" pair. Last "@" wins: the
// login is the free-text half, and one containing an "@" must not be able to
// pass its own tail off as the host.
func hostAfterAt(pair string) string {
	if i := strings.LastIndex(pair, "@"); i >= 0 {
		return pair[i+1:]
	}
	return ""
}
