// The SSH credential check (S). It is a panel drawn where the help bar goes,
// like the theme picker, so the run behind it stays on screen. Discovery lists
// the methods the server offers and sends no credential. A check sends one
// credential, once, and reports the result. Nothing is retried or cycled, no
// shell is opened, and a host key that does not match is refused.

package ui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// verifyRow is one line of the panel. The rows shown depend on the method.
type verifyRow int

const (
	vrUser verifyRow = iota
	vrMethod
	vrSecret
	vrKey
	vrAgent
	vrDiscover
	vrCheck
	vrTrust
)

// verifyMethods is the order the method chooser cycles through.
var verifyMethods = []sshverify.Method{sshverify.MethodPassword, sshverify.MethodKey, sshverify.MethodAgent}

var verifyMethodNames = map[sshverify.Method]string{
	sshverify.MethodPassword: "password",
	sshverify.MethodKey:      "key file",
	sshverify.MethodAgent:    "ssh-agent",
}

// verifyPanel is the state of one open panel. Its secret lives only in the
// secret input, which is cleared after every attempt and on close.
type verifyPanel struct {
	target     sshverify.Target
	resolved   bool
	resolveErr string
	user       textinput.Model
	secret     textinput.Model
	method     int
	keys       []string
	keyIdx     int
	agentKeys  []sshverify.AgentKey
	agentIdx   int
	row        verifyRow
	// targetKey is the target the panel was opened for. A switch to another target
	// closes the panel, so it never shows or runs against the previous one.
	targetKey string
	// host and port are the destination the configuration read is asked for, kept
	// so a login edit can read the route again.
	host string
	port int
	// resolveSeq numbers the configuration reads. A login edit starts a newer one, and a
	// result for an older read is dropped, so the route in use is always the one read for
	// the login now typed.
	resolveSeq uint64
	// trust is an unknown host key the user confirmed for the next action only.
	trust string
	// pin is the host key the last trusted discovery presented. The next check
	// must present that key, so a key that changed since discovery is refused
	// before the secret is sent.
	pin    string
	result *sshverify.Result
	note   string
	busy   bool
	id     uint64
	cancel context.CancelFunc
	// resolveCancel ends the configuration read this panel started, if it is
	// still running.
	resolveCancel context.CancelFunc
	// keysCancel ends the agent listing a discovery started, if it is still running.
	keysCancel context.CancelFunc
	// keysSeq numbers the agent listings, so a result from a replaced one is recognized.
	keysSeq uint64
}

// verifyResolvedMsg carries the off-loop configuration read. The id rejects a
// result for a panel that was closed and reopened since.
type verifyResolvedMsg struct {
	id     uint64
	seq    uint64
	target sshverify.Target
	err    error
}

// verifyResultMsg carries one discovery or check.
type verifyResultMsg struct {
	id     uint64
	result sshverify.Result
}

// verifyKeysMsg carries the agent's keys for the chooser. It arrives in its own
// message, so a slow agent cannot hold a discovery result.
type verifyKeysMsg struct {
	id   uint64
	seq  uint64
	keys []sshverify.AgentKey
}

// newVerifyPanel opens the panel for the run target. The inputs are created
// here, not per frame, so their cursor and echo state survive a repaint.
func newVerifyPanel(st styles, id uint64) verifyPanel {
	p := verifyPanel{id: id, row: vrUser}
	p.user = textinput.New()
	p.user.Prompt = "Login     "
	p.user.Placeholder = "from your SSH configuration"
	p.user.PromptStyle = st.key
	p.secret = textinput.New()
	p.secret.Prompt = "Password  "
	p.secret.Placeholder = "typed here, never shown"
	p.secret.PromptStyle = st.key
	// A secret is echoed as dots and is held only in this input, which is
	// cleared after each attempt. It never reaches a notice, a report, or argv.
	p.secret.EchoMode = textinput.EchoPassword
	p.focus(vrUser)
	return p
}

// verifyTarget returns the host and port the configuration read is asked for.
func verifyTarget(t *diagnostic.Target) (host string, port int) {
	if t.PortExplicit {
		return t.ScopedHost(), t.Port
	}
	return t.ScopedHost(), 0
}

// openVerifySSH opens the panel for the run target. It reads the target's SSH
// configuration off the loop; nothing is sent to the server until a button is
// pressed.
func (m model) openVerifySSH() (model, tea.Cmd) {
	if m.target == nil {
		return m, nil
	}
	m.verifySeq++
	m.verifying = true
	m.verify = newVerifyPanel(m.st, m.verifySeq)
	m.verify.targetKey = verifyKey(m.target)
	m.verify.host, m.verify.port = verifyTarget(m.target)
	// The read belongs to this panel: closing the panel cancels it, so a slow or
	// hung configuration read never outlives the panel that asked for it.
	return m, m.verify.readRoute()
}

// readRoute starts the configuration read for the login typed now, in a tea.Cmd. It
// connects to nothing; the result is what a check needs before it can run. It replaces
// any read still running, so only the newest one can land.
func (p *verifyPanel) readRoute() tea.Cmd {
	if p.resolveCancel != nil {
		p.resolveCancel()
	}
	p.resolveSeq++
	ctx, cancel := context.WithCancel(context.Background())
	p.resolveCancel = cancel
	p.resolveErr = ""
	id, seq, host, port := p.id, p.resolveSeq, p.host, p.port
	login := strings.TrimSpace(p.user.Value())
	return func() tea.Msg {
		t, err := resolveTarget(ctx, host, port, login)
		return verifyResolvedMsg{id: id, seq: seq, target: t, err: err}
	}
}

// dropRoute forgets the route and everything that depends on it, when the login
// changes. A check then cannot run until the route is read for the new login.
func (p *verifyPanel) dropRoute() {
	if p.resolveCancel != nil {
		p.resolveCancel()
		p.resolveCancel = nil
	}
	if p.keysCancel != nil {
		p.keysCancel()
		p.keysCancel = nil
	}
	p.resolveSeq++
	p.keysSeq++
	p.resolved = false
	p.resolveErr = ""
	p.target = sshverify.Target{}
	p.keys, p.keyIdx = nil, 0
	p.agentKeys, p.agentIdx = nil, 0
	p.result = nil
	p.pin, p.trust = "", ""
	p.note = ""
}

// moveFrom moves the cursor by delta. Leaving the login row reads the route, unless
// one is already read or being read, so the next check uses the route for this login.
func (p *verifyPanel) moveFrom(delta int) tea.Cmd {
	var leave tea.Cmd
	if p.row == vrUser && !p.resolved && p.resolveCancel == nil {
		leave = p.readRoute()
	}
	return tea.Batch(p.step(delta), leave)
}

// resolveTarget reads a target's configuration. Tests replace it to observe
// the read's context without running ssh.
var resolveTarget = sshverify.Resolve

// discoverCmd lists the methods the server offers. It sends no credential.
func discoverCmd(ctx context.Context, id uint64, t sshverify.Target, opts sshverify.Options) tea.Cmd {
	return func() tea.Msg {
		return verifyResultMsg{id: id, result: sshverify.Discover(ctx, t, opts)}
	}
}

// agentKeysCmd lists the agent's keys for the chooser. The listing ends with
// its context, or at the check's timeout, whichever comes first.
func agentKeysCmd(ctx context.Context, id, seq uint64, t sshverify.Target, opts sshverify.Options) tea.Cmd {
	return func() tea.Msg {
		keys, _ := sshverify.ListAgentKeys(ctx, t, opts)
		return verifyKeysMsg{id: id, seq: seq, keys: keys}
	}
}

// checkCmd sends one credential. The attempt's secret is cleared by Verify.
func checkCmd(ctx context.Context, id uint64, t sshverify.Target, a sshverify.Attempt, opts sshverify.Options) tea.Cmd {
	return func() tea.Msg {
		return verifyResultMsg{id: id, result: sshverify.Verify(ctx, t, a, opts)}
	}
}

// visibleRows is the order of rows for the current method and result. A
// trust row appears only after an unknown host key, which is the one case
// where the user may confirm a key for the next check.
func (p verifyPanel) visibleRows() []verifyRow {
	rows := []verifyRow{vrUser, vrMethod}
	switch verifyMethods[p.method] {
	case sshverify.MethodPassword:
		rows = append(rows, vrSecret)
	case sshverify.MethodKey:
		rows = append(rows, vrKey, vrSecret)
	case sshverify.MethodAgent:
		rows = append(rows, vrAgent)
	}
	rows = append(rows, vrDiscover, vrCheck)
	if p.result != nil && p.result.Outcome == sshverify.HostKeyUnknown && p.result.HostKey != "" {
		rows = append(rows, vrTrust)
	}
	return rows
}

// syncSecretPrompt names the secret for the method: a password, or a key's
// passphrase, which is needed only when the key file is encrypted.
func (p *verifyPanel) syncSecretPrompt() {
	if verifyMethods[p.method] == sshverify.MethodKey {
		p.secret.Prompt = "Passphrase"
		return
	}
	p.secret.Prompt = "Password  "
}

// focus moves the cursor to row and gives the matching text input the focus.
func (p *verifyPanel) focus(row verifyRow) tea.Cmd {
	p.row = row
	p.user.Blur()
	p.secret.Blur()
	switch row {
	case vrUser:
		return p.user.Focus()
	case vrSecret:
		return p.secret.Focus()
	}
	return nil
}

// step moves the cursor to the next or previous visible row, wrapping.
func (p *verifyPanel) step(delta int) tea.Cmd {
	rows := p.visibleRows()
	at := 0
	for i, r := range rows {
		if r == p.row {
			at = i
		}
	}
	return p.focus(rows[(at+delta+len(rows))%len(rows)])
}

// attempt builds the one credential the panel would send. note says why it
// cannot be sent yet, so nothing is started from an incomplete form.
func (p *verifyPanel) attempt() (sshverify.Attempt, string) {
	a := sshverify.Attempt{User: strings.TrimSpace(p.user.Value())}
	a.Method = verifyMethods[p.method]
	switch a.Method {
	case sshverify.MethodPassword:
		if p.secret.Value() == "" {
			return a, "type the password in the Password field first"
		}
		a.Password = []byte(p.secret.Value())
	case sshverify.MethodKey:
		if len(p.keys) == 0 {
			return a, "no key file is available to choose; set one up in ~/.ssh or your SSH configuration"
		}
		a.KeyPath = p.keys[p.keyIdx]
		if p.secret.Value() != "" {
			a.Passphrase = []byte(p.secret.Value())
		}
	case sshverify.MethodAgent:
		if len(p.agentKeys) == 0 {
			return a, "no agent key is listed yet; press enter on Discover methods"
		}
		a.AgentFingerprint = p.agentKeys[p.agentIdx].Fingerprint
	}
	return a, ""
}

// verifyOptions are the options for the next action. A confirmed host key
// applies to exactly one action, and so does the pin: both are cleared as the
// action starts. A check presents the key discovery trusted, or else the key the
// user confirmed.
func (p *verifyPanel) verifyOptions(check bool) sshverify.Options {
	opts := sshverify.Options{TrustHostKey: p.trust}
	if check {
		opts.PinHostKey = p.pin
		if opts.PinHostKey == "" {
			opts.PinHostKey = p.trust
		}
	}
	p.trust, p.pin = "", ""
	return opts
}

// startAction begins a discovery or a check, and reports whether it started.
// Each starts a fresh context, so esc can cancel it and release an agent that
// is waiting for a touch or a PIN.
func (m model) startVerifyAction(check bool) (model, tea.Cmd) {
	p := &m.verify
	if p.busy || !p.resolved {
		return m, nil
	}
	var a sshverify.Attempt
	if check {
		att, note := p.attempt()
		if note != "" {
			p.note = note
			return m, nil
		}
		// The secret is sent only to the host key that was trusted: one a
		// discovery presented, or one the user confirmed.
		if p.pin == "" && p.trust == "" {
			p.note = "press enter on Discover methods first, so the host key is trusted before the secret is sent"
			return m, nil
		}
		a = att
	}
	p.note = ""
	wasTicking := m.spinnerActive()
	p.busy = true
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	opts := p.verifyOptions(check)
	if check {
		// The attempt holds its own copy, so the input can be cleared as the check
		// starts. Discovery sends no secret, so the input is left as typed.
		p.secret.SetValue("")
	}
	var cmd tea.Cmd
	if check {
		cmd = checkCmd(ctx, p.id, p.target, a, opts)
	} else {
		cmd = discoverCmd(ctx, p.id, p.target, opts)
	}
	cmds := []tea.Cmd{cmd}
	if !check && verifyMethods[p.method] == sshverify.MethodAgent {
		// Only the agent method uses the agent's keys, so a password discovery never
		// starts an agent listing at all.
		if p.keysCancel != nil {
			p.keysCancel()
		}
		keysCtx, keysCancel := context.WithCancel(context.Background())
		p.keysCancel = keysCancel
		p.keysSeq++
		cmds = append(cmds, agentKeysCmd(keysCtx, p.id, p.keysSeq, p.target, opts))
	}
	if !wasTicking {
		cmds = append(cmds, m.spinner.Tick)
	}
	return m, tea.Batch(cmds...)
}

// closeVerifyPanel ends the panel. A configuration read or a check still in
// flight is cancelled, and the panel's state, including any typed secret, is
// dropped. A late result for the closed panel is then ignored, because its id
// no longer matches.
func (m *model) closeVerifyPanel() {
	if m.verify.resolveCancel != nil {
		m.verify.resolveCancel()
	}
	if m.verify.cancel != nil {
		m.verify.cancel()
	}
	if m.verify.keysCancel != nil {
		m.verify.keysCancel()
	}
	m.verifying = false
	m.verify = verifyPanel{}
}

// verifyKey identifies the target the SSH panel checks: its host and port as the
// configuration read is asked for them.
func verifyKey(t *diagnostic.Target) string {
	if t == nil {
		return ""
	}
	host, port := verifyTarget(t)
	return fmt.Sprintf("%s:%d", host, port)
}

// handleVerifyKey handles keys while the panel is open. esc closes it and
// cancels a check in flight. While busy, nothing else is accepted.
func (m model) handleVerifyKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := &m.verify
	if msg.String() == "esc" {
		m.closeVerifyPanel()
		return m, nil
	}
	if p.busy {
		return m, nil
	}
	switch msg.String() {
	case "tab", "down":
		return m, p.moveFrom(1)
	case "shift+tab", "up":
		return m, p.moveFrom(-1)
	case "left", "right":
		// On a text row the key moves the caret in the field below, so it is not consumed here.
		if p.row == vrUser || p.row == vrSecret {
			break
		}
		delta := 1
		if msg.String() == "left" {
			delta = -1
		}
		switch p.row {
		case vrMethod:
			p.method = (p.method + delta + len(verifyMethods)) % len(verifyMethods)
			// The secret belongs to the method that was chosen when it was typed. A
			// passphrase must never become a password, so a change clears it.
			p.secret.SetValue("")
			p.note = ""
			p.syncSecretPrompt()
		case vrKey:
			if n := len(p.keys); n > 0 {
				p.keyIdx = (p.keyIdx + delta + n) % n
			}
		case vrAgent:
			if n := len(p.agentKeys); n > 0 {
				p.agentIdx = (p.agentIdx + delta + n) % n
			}
		}
		return m, nil
	case "enter":
		switch p.row {
		case vrDiscover:
			return m.startVerifyAction(false)
		case vrCheck:
			return m.startVerifyAction(true)
		case vrTrust:
			p.trust = p.result.HostKey
			p.result = nil
			p.note = "host key confirmed for the next check only; nothing is written. Enter the credential again and press enter on Verify."
			return m, p.focus(vrCheck)
		}
		return m, p.moveFrom(1)
	}
	var cmd tea.Cmd
	switch p.row {
	case vrUser:
		before := p.user.Value()
		p.user, cmd = p.user.Update(msg)
		if p.user.Value() != before {
			p.dropRoute()
			// A secret is typed for the login it was typed under, so a new login starts with none.
			p.secret.SetValue("")
		}
	case vrSecret:
		p.secret, cmd = p.secret.Update(msg)
	}
	return m, cmd
}

// handleVerifyMsg applies a configuration read or a finished action. A result
// for a closed or replaced panel is dropped.
func (m model) handleVerifyMsg(msg tea.Msg) (model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case verifyResolvedMsg:
		if !m.verifying || msg.id != m.verify.id || msg.seq != m.verify.resolveSeq {
			return m, nil, true
		}
		m.verify.resolveCancel = nil
		if msg.err != nil {
			m.verify.resolveErr = textsafe.Clean(msg.err.Error())
			return m, nil, true
		}
		m.verify.target = msg.target
		m.verify.resolved = true
		m.verify.resolveErr = ""
		m.verify.keys = sshverify.ExistingIdentityFiles(msg.target)
		return m, nil, true
	case verifyKeysMsg:
		if !m.verifying || msg.id != m.verify.id || msg.seq != m.verify.keysSeq {
			return m, nil, true
		}
		if m.verify.keysCancel != nil {
			m.verify.keysCancel()
		}
		m.verify.keysCancel = nil
		m.verify.agentKeys = msg.keys
		m.verify.agentIdx = min(m.verify.agentIdx, max(len(msg.keys)-1, 0))
		return m, nil, true
	case verifyResultMsg:
		if !m.verifying || msg.id != m.verify.id {
			return m, nil, true
		}
		m.verify.busy = false
		m.verify.cancel = nil
		m.verify.result = &msg.result
		// Only a discovery that trusted the host sets the key the next check must
		// present; any other result clears it, so a check needs a fresh discovery.
		m.verify.pin = ""
		if msg.result.Outcome == sshverify.Discovered {
			m.verify.pin = msg.result.HostKey
		}
		m.verify.note = ""
		// The focus may now sit on a row that is no longer visible.
		if !slices.Contains(m.verify.visibleRows(), m.verify.row) {
			m.verify.focus(vrCheck)
		}
		return m, nil, true
	}
	return m, nil, false
}

// verifyView is the panel, drawn where the help bar goes.
func (m model) verifyView() string {
	p := m.verify
	w := min(fitPanelWidth(m.st.focusPanel, m.width), 76)
	inputW := func(prompt string) int { return max(w-6-lipgloss.Width(prompt), 8) }
	p.user.Width = inputW(p.user.Prompt)
	p.secret.Width = inputW(p.secret.Prompt)

	label := "the run target"
	if p.resolved {
		label = fmt.Sprintf("%s@%s:%d", p.target.User, p.target.Host, p.target.Port)
	}
	focused := func(r verifyRow) string {
		if p.row == r {
			return m.st.sel.Render("▸ ")
		}
		return "  "
	}

	var b strings.Builder
	b.WriteString(m.st.panelTitle.Render("Verify SSH credentials for "+textsafe.Clean(label)) + "\n")
	if p.resolveErr != "" {
		b.WriteString(m.st.fail.Render("✗ "+p.resolveErr) + "\n")
	}
	b.WriteString(focused(vrUser) + p.user.View() + "\n")
	method := ""
	for i, mt := range verifyMethods {
		name := verifyMethodNames[mt]
		if i == p.method {
			method += m.st.sel.Render("["+name+"]") + " "
		} else {
			method += m.st.faint.Render(name) + " "
		}
	}
	hint := ""
	if p.row == vrMethod {
		hint = m.st.faint.Render("  ←/→")
	}
	b.WriteString(focused(vrMethod) + m.st.key.Render("Method    ") + method + hint + "\n")
	switch verifyMethods[p.method] {
	case sshverify.MethodPassword:
		b.WriteString(focused(vrSecret) + p.secret.View() + "\n")
	case sshverify.MethodKey:
		keyLine := "none found: set one up in ~/.ssh"
		if len(p.keys) > 0 {
			keyLine = textsafe.Clean(p.keys[p.keyIdx])
			if len(p.keys) > 1 {
				keyLine += m.st.faint.Render(fmt.Sprintf("  (%d of %d)", p.keyIdx+1, len(p.keys)))
			}
		}
		b.WriteString(focused(vrKey) + m.st.key.Render("Key file  ") + keyLine + "\n")
		b.WriteString(focused(vrSecret) + p.secret.View() + "\n")
	case sshverify.MethodAgent:
		keyLine := m.st.faint.Render("none listed yet: press enter on Discover methods")
		if len(p.agentKeys) > 0 {
			k := p.agentKeys[p.agentIdx]
			keyLine = textsafe.Clean(k.Fingerprint+"  "+k.Comment) + m.st.faint.Render(fmt.Sprintf("  (%d of %d)", p.agentIdx+1, len(p.agentKeys)))
		}
		b.WriteString(focused(vrAgent) + m.st.key.Render("Agent key ") + keyLine + "\n")
	}
	b.WriteString("\n")
	b.WriteString(focused(vrDiscover) + "[ Discover methods ]  " + m.st.faint.Render("sends no credential") + "\n")
	b.WriteString(focused(vrCheck) + "[ Verify credential ]  " + m.st.faint.Render("sends one credential, once") + "\n")
	if p.result != nil && p.result.Outcome == sshverify.HostKeyUnknown && p.result.HostKey != "" {
		b.WriteString(focused(vrTrust) + "[ Trust this host key once ]  " + textsafe.Clean(p.result.HostKey) + "\n")
	}

	if p.busy {
		b.WriteString("\n" + m.spinner.View() + " working; esc cancels")
	} else if p.result != nil {
		b.WriteString("\n" + resultLines(m, *p.result))
	}
	if p.note != "" {
		b.WriteString("\n" + m.st.warn.Render(textsafe.Clean(p.note)))
	}
	keys := []string{"tab", "next", "enter", "run", "esc", "close"}
	return m.st.focusPanel.Width(w).Render(strings.TrimRight(b.String(), "\n")) + "\n" +
		m.quitNoticeFooter(helpKeys(m.st, m.width, keys...))
}

// resultLines renders one result: its label, what the server listed, and the
// reason. Every server-supplied string is sanitized in the sshverify package.
func resultLines(m model, r sshverify.Result) string {
	style := m.st.warn
	switch r.Outcome {
	case sshverify.Verified, sshverify.Discovered:
		style = m.st.pass
	case sshverify.Refused, sshverify.NotOffered, sshverify.Partial, sshverify.NoCredentialAccepted:
		style = m.st.fail
	}
	lines := []string{style.Render("result: " + r.Outcome.Describe())}
	if r.Outcome == sshverify.HostKeyChanged && r.HostKey != "" {
		// The presented key is the only fingerprint netdoc has for the server, so it is shown
		// for the user to compare with the key they expect.
		lines = append(lines, style.Render("presented host key: "+textsafe.Clean(r.HostKey)))
	}
	if len(r.Methods) > 0 {
		lines = append(lines, m.st.faint.Render("server offers: "+textsafe.Clean(strings.Join(r.Methods, ", "))))
	}
	if len(r.Remaining) > 0 {
		lines = append(lines, m.st.faint.Render("still required: "+textsafe.Clean(strings.Join(r.Remaining, ", "))))
	}
	if r.Detail != "" {
		lines = append(lines, m.st.faint.Render(textsafe.Clean(r.Detail)))
	}
	return strings.Join(lines, "\n")
}
