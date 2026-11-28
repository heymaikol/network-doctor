// The SSH credential check (S). It is a panel drawn where the help bar goes,
// like the theme picker, so the run behind it stays on screen. Discovery lists
// the methods the server offers and sends no credential. A check sends one
// credential, once, and reports the result. Nothing is retried or cycled, no
// shell is opened, and a host key that does not match is refused.

package ui

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// verifyRow is one line of the panel. The rows shown depend on the method.
type verifyRow int

const (
	vrUser verifyRow = iota
	vrProfile
	vrMethod
	vrSecret
	vrKey
	vrAgent
	vrDiscover
	vrCheck
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
	// scannedIP remains the IP target, whether typed or selected from the LAN
	// map. Choosing an SSH profile changes the connection destination, not it.
	scannedIP   string
	host        string // effective destination argument passed to ssh -G
	profile     string // selected Host alias; empty means No SSH Profile
	profiles    []string
	profileIdx  int // cursor 0 is No SSH Profile, then the suggested aliases
	user        textinput.Model
	secret      textinput.Model
	method      int
	keys        []string
	keyIdx      int
	keyChosen   bool
	keyScanErr  bool
	agentKeys   []sshverify.AgentKey
	agentIdx    int
	agentChosen bool
	row         verifyRow
	// targetKey is the target the panel was opened for. A switch to another target
	// closes the panel, so it never shows or runs against the previous one.
	targetKey string
	// port is the device's SSH port; the profile list selects the host argument.
	port int
	// resolveSeq numbers the configuration reads. A login edit starts a newer one, and a
	// result for an older read is dropped, so the route in use is always the one read for
	// the login now typed.
	resolveSeq uint64
	result     *sshverify.Result
	// trusted is set when the last result was a discovery that OpenSSH trusted the host for.
	// The secret waits for it, so a check starts only after the host key is trusted.
	trusted bool
	// identity is the host identity that discovery trusted. A check binds to it, so a
	// key other than the one shown is refused before the secret is sent.
	identity sshverify.HostIdentity
	note     string
	busy     bool
	id       uint64
	cancel   context.CancelFunc
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
	id       uint64
	seq      uint64
	target   sshverify.Target
	err      error
	keys     []string
	keyErr   error
	profiles []string
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
	p.user.Placeholder = "username"
	p.user.PromptStyle = st.key
	p.secret = textinput.New()
	p.secret.Prompt = "Password  "
	p.secret.Placeholder = "type here"
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
	host, port := verifyTarget(m.target)
	m.verify.host = host
	m.verify.port = port
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		m.verify.scannedIP = host
		m.verify.focus(vrProfile)
	}
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
		profiles := listSSHHostProfiles(ctx)
		// Key candidates come from the user's .ssh directory, never from the
		// identity files OpenSSH chose for this particular host or alias.
		keys, keyErr := userSSHPrivateKeys(ctx)
		return verifyResolvedMsg{id: id, seq: seq, target: t, err: err, keys: keys, keyErr: keyErr, profiles: profiles}
	}
}

// dropRoute forgets the route and everything that depends on it, when the login
// changes. A check then cannot run until the route is read for the new login.
// abandon ends everything the panel has running and clears the typed secret. A quit calls it, so
// the process keeps no check and no credential after the TUI has gone.
func (p *verifyPanel) abandon() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.busy = false
	if p.resolveCancel != nil {
		p.resolveCancel()
		p.resolveCancel = nil
	}
	if p.keysCancel != nil {
		p.keysCancel()
		p.keysCancel = nil
	}
	p.secret.SetValue("")
}

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
	p.keyChosen = false
	p.keyScanErr = false
	p.agentKeys, p.agentIdx = nil, 0
	p.agentChosen = false
	p.result = nil
	p.trusted = false
	p.identity = sshverify.HostIdentity{}
	p.note = ""
}

// moveFrom moves the cursor by delta. Leaving the login row reads the route, unless
// one is already read or being read, so the next check uses the route for this login.
func (p *verifyPanel) moveFrom(delta int) tea.Cmd {
	var leave tea.Cmd
	if (p.row == vrUser || p.row == vrProfile) && !p.resolved && p.resolveCancel == nil {
		leave = p.readRoute()
	}
	return tea.Batch(p.step(delta), leave)
}

// moveArrow moves between visible rows without wrapping past the form's ends.
// Tab remains available for wrapping navigation.
func (p *verifyPanel) moveArrow(delta int) tea.Cmd {
	rows := p.visibleRows()
	if delta < 0 && p.row == rows[0] || delta > 0 && p.row == rows[len(rows)-1] {
		return nil
	}
	return p.moveFrom(delta)
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
		return verifyResultMsg{id: id, result: verifyCheck(ctx, t, a, opts)}
	}
}

// verifyCheck sends one credential. Tests replace it to see the attempt the panel built.
var verifyCheck = sshverify.Verify

// visibleRows is the order of rows for the current method.
func (p verifyPanel) visibleRows() []verifyRow {
	rows := []verifyRow{}
	if p.scannedIP != "" {
		rows = append(rows, vrProfile)
	}
	rows = append(rows, vrUser, vrMethod)
	switch verifyMethods[p.method] {
	case sshverify.MethodPassword:
		rows = append(rows, vrSecret)
	case sshverify.MethodKey:
		rows = append(rows, vrKey, vrSecret)
	case sshverify.MethodAgent:
		rows = append(rows, vrAgent)
	}
	rows = append(rows, vrDiscover, vrCheck)
	return rows
}

// syncSecretPrompt names the secret for the method: a password, or a key's
// passphrase, which is needed only when the key file is encrypted.
func (p *verifyPanel) syncSecretPrompt() {
	if verifyMethods[p.method] == sshverify.MethodKey {
		p.secret.Prompt = "Passphrase "
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
		if p.keyScanErr {
			return a, "could not list private keys in ~/.ssh"
		}
		if len(p.keys) == 0 {
			return a, "no private keys found in ~/.ssh"
		}
		if !p.keyChosen || p.keyIdx >= len(p.keys) || p.keyIdx < 0 {
			return a, "select a private key from ~/.ssh using the arrow keys and enter"
		}
		a.KeyPath = p.keys[p.keyIdx]
		if p.secret.Value() != "" {
			a.Passphrase = []byte(p.secret.Value())
		}
	case sshverify.MethodAgent:
		if len(p.agentKeys) == 0 {
			return a, "no agent key is listed yet; press enter on Discover methods"
		}
		if !p.agentChosen || p.agentIdx < 0 || p.agentIdx >= len(p.agentKeys) {
			return a, "select an ssh-agent key using the arrow keys and enter"
		}
		a.AgentFingerprint = p.agentKeys[p.agentIdx].Fingerprint
	}
	return a, ""
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
		// The secret is sent only after a discovery trusted the host, so OpenSSH has
		// decided on the host key before the credential is sent.
		if !p.trusted {
			p.note = "press enter on Discover methods first, so the host key is trusted before the secret is sent"
			return m, nil
		}
		a = att
		a.Identity = p.identity
	}
	p.note = ""
	wasTicking := m.spinnerActive()
	p.busy = true
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	opts := sshverify.Options{}
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
		p.agentKeys = nil
		p.agentIdx = 0
		p.agentChosen = false
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
	case "tab":
		return m, p.moveFrom(1)
	case "shift+tab":
		return m, p.moveFrom(-1)
	case "up", "down":
		delta := 1
		if msg.String() == "up" {
			delta = -1
		}
		if p.row == vrProfile {
			if next := p.profileIdx + delta; next >= 0 && next <= len(p.profiles) {
				p.profileIdx = next
				return m, nil
			}
		}
		if p.row == vrKey {
			if next := p.keyIdx + delta; next >= 0 && next < len(p.keys) {
				p.keyIdx = next
				p.keyChosen = false
				p.secret.SetValue("")
				p.note = ""
				p.result = nil
				return m, nil
			}
		}
		if p.row == vrAgent {
			if next := p.agentIdx + delta; next >= 0 && next < len(p.agentKeys) {
				p.agentIdx = next
				p.agentChosen = false
				p.note = ""
				p.result = nil
				return m, nil
			}
		}
		return m, p.moveArrow(delta)
	case "left", "right":
		// Horizontal arrows still move the caret inside text inputs.
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
			p.result = nil
		default:
			return m, nil
		}
		return m, nil
	case "enter":
		switch p.row {
		case vrProfile:
			p.profile = ""
			p.host = p.scannedIP
			if p.profileIdx > 0 && p.profileIdx <= len(p.profiles) {
				p.profile = p.profiles[p.profileIdx-1]
				p.host = p.profile
			}
			p.dropRoute()
			p.secret.SetValue("")
			return m, tea.Batch(p.step(1), p.readRoute())
		case vrDiscover:
			return m.startVerifyAction(false)
		case vrCheck:
			return m.startVerifyAction(true)
		case vrKey:
			if len(p.keys) == 0 {
				p.note = "no private keys found in ~/.ssh"
				if p.keyScanErr {
					p.note = "could not list private keys in ~/.ssh"
				}
				return m, nil
			}
			p.keyChosen = true
			p.secret.SetValue("")
			p.note = ""
			p.result = nil
		case vrAgent:
			if len(p.agentKeys) == 0 {
				p.note = "no agent key is listed yet; press enter on Discover methods"
				return m, nil
			}
			p.agentChosen = true
			p.note = ""
			p.result = nil
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
		// The field takes no text until a discovery has trusted the host: a secret typed before
		// that would sit in the panel for a host nobody has checked.
		if !p.trusted {
			p.note = "press enter on Discover methods first, so the host key is trusted before you type the secret"
			return m, nil
		}
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
		m.verify.keys = msg.keys
		m.verify.profiles = msg.profiles
		m.verify.profileIdx = min(m.verify.profileIdx, len(msg.profiles))
		m.verify.keyIdx = 0
		m.verify.keyChosen = false
		m.verify.keyScanErr = msg.keyErr != nil
		if msg.err != nil {
			m.verify.resolveErr = textsafe.Clean(msg.err.Error())
			return m, nil, true
		}
		m.verify.target = msg.target
		m.verify.resolved = true
		m.verify.resolveErr = ""
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
		m.verify.agentIdx = 0
		m.verify.agentChosen = false
		return m, nil, true
	case verifyResultMsg:
		if !m.verifying || msg.id != m.verify.id {
			return m, nil, true
		}
		m.verify.busy = false
		m.verify.cancel = nil
		m.verify.result = &msg.result
		// Only a discovery that trusted the host sets the gate for the next check; any other
		// result clears it, so a check needs a fresh discovery.
		m.verify.trusted = msg.result.Outcome == sshverify.Discovered && msg.result.Identity.Valid()
		m.verify.identity = sshverify.HostIdentity{}
		if m.verify.trusted {
			m.verify.identity = msg.result.Identity
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
	if p.scannedIP != "" {
		original := textsafe.Clean(p.scannedIP)
		if p.port > 0 {
			original = fmt.Sprintf("%s:%d", original, p.port)
		}
		b.WriteString("  " + m.st.faint.Render("Original target: "+original) + "\n")
		profileName := "No SSH Profile"
		if p.profile != "" {
			profileName = textsafe.Clean(p.profile)
		}
		b.WriteString(focused(vrProfile) + m.st.key.Render("SSH Profile  ") + profileName + "\n")
		if p.row == vrProfile {
			visible := verifyPickerVisibleRows(m.height)
			count := len(p.profiles) + 1 // the explicit No SSH Profile choice
			start := min(max(0, p.profileIdx-visible/2), max(0, count-visible))
			for i := start; i < min(start+visible, count); i++ {
				name := "No SSH Profile"
				if i > 0 {
					name = textsafe.Clean(p.profiles[i-1])
				}
				marker := "▹ "
				if (i == 0 && p.profile == "") || (i > 0 && p.profile == p.profiles[i-1]) {
					marker = "✓ "
				}
				if i == p.profileIdx {
					marker = "▸ "
				}
				line := marker + name
				if i == p.profileIdx {
					line = m.st.sel.Render(line)
				}
				b.WriteString("    " + line + "\n")
			}
			b.WriteString("\n    " + m.st.faint.Render("choose with arrows, press enter to select") + "\n")
		}
	}
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
		if !p.resolved && p.resolveCancel != nil {
			b.WriteString(focused(vrKey) + m.st.faint.Render("reading private keys in ~/.ssh") + "\n")
		} else if p.keyScanErr {
			b.WriteString(focused(vrKey) + m.st.warn.Render("could not list private keys in ~/.ssh") + "\n")
		} else if len(p.keys) == 0 {
			b.WriteString(focused(vrKey) + m.st.faint.Render("no private keys found in ~/.ssh") + "\n")
		} else {
			visible := verifyPickerVisibleRows(m.height)
			start := min(max(0, p.keyIdx-visible/2), max(0, len(p.keys)-visible))
			for i := start; i < min(start+visible, len(p.keys)); i++ {
				name := keyPickerPathLabel(p.keys[i], max(w-9, 12))
				marker := "▹ "
				if p.keyChosen && i == p.keyIdx {
					marker = "✓ "
				} else if p.row == vrKey && i == p.keyIdx {
					marker = "▸ "
				}
				line := marker + name
				if i == p.keyIdx && (p.keyChosen || p.row == vrKey) {
					line = m.st.sel.Render(line)
				}
				b.WriteString("    " + line + "\n")
			}
			b.WriteString("\n    " + m.st.faint.Render("choose with arrows, press enter to select") + "\n")
		}
		b.WriteString(focused(vrSecret) + p.secret.View() + "\n")
	case sshverify.MethodAgent:
		if len(p.agentKeys) == 0 {
			b.WriteString(focused(vrAgent) + m.st.faint.Render("no agent keys listed: press enter on Discover methods") + "\n")
		} else {
			visible := verifyPickerVisibleRows(m.height)
			start := min(max(0, p.agentIdx-visible/2), max(0, len(p.agentKeys)-visible))
			for i := start; i < min(start+visible, len(p.agentKeys)); i++ {
				k := p.agentKeys[i]
				name := agentPickerKeyLabel(k, max(w-9, 12))
				marker := "▹ "
				if p.agentChosen && i == p.agentIdx {
					marker = "✓ "
				} else if p.row == vrAgent && i == p.agentIdx {
					marker = "▸ "
				}
				line := marker + name
				if i == p.agentIdx && (p.agentChosen || p.row == vrAgent) {
					line = m.st.sel.Render(line)
				}
				b.WriteString("    " + line + "\n")
			}
			b.WriteString("\n    " + m.st.faint.Render("choose with arrows, press enter to select") + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(focused(vrDiscover) + "[ Discover methods ]  " + m.st.faint.Render("sends no credential") + "\n")
	b.WriteString(focused(vrCheck) + "[ Verify credential ]  " + m.st.faint.Render("sends one credential") + "\n")

	if p.busy {
		b.WriteString("\n" + m.spinner.View() + " working; esc cancels")
	} else if p.result != nil {
		b.WriteString("\n" + resultLines(m, *p.result))
	}
	if p.note != "" {
		b.WriteString("\n" + m.st.warn.Render(textsafe.Clean(p.note)))
	}
	keys := []string{"↑/↓", "navigate", "enter", "run", "tab", "next", "esc", "close"}
	if p.row == vrProfile || (p.row == vrKey && verifyMethods[p.method] == sshverify.MethodKey) || (p.row == vrAgent && verifyMethods[p.method] == sshverify.MethodAgent) {
		keys = []string{"↑/↓", "choose/move", "enter", "select", "tab", "next", "esc", "close"}
	}
	return m.st.focusPanel.Width(w).Render(strings.TrimRight(b.String(), "\n")) + "\n" +
		m.quitNoticeFooter(helpKeys(m.st, m.width, keys...))
}

// Leave the verification buttons reachable when the terminal is short. The
// arrow-key selection still traverses every key regardless of the row count.
func verifyPickerVisibleRows(height int) int {
	switch {
	case height > 0 && height <= 16:
		return 1
	case height > 0 && height <= 20:
		return 3
	default:
		return 5
	}
}

// Key paths often have long shared directory prefixes. Clip from the left so
// the filename, which usually distinguishes the credentials, remains visible.
func keyPickerPathLabel(path string, width int) string {
	label := textsafe.Clean(shortSSHKeyPath(path))
	return pickerKeepRight(label, width)
}

func pickerKeepRight(label string, width int) string {
	if extra := ansi.StringWidth(label) - width; extra > 0 {
		return ansi.TruncateLeft(label, extra+1, "…")
	}
	return label
}

// Keep the fingerprint on screen even when an agent supplies a long comment.
// The comment identifies the key informally; the fingerprint identifies it.
func agentPickerKeyLabel(key sshverify.AgentKey, width int) string {
	fingerprint := textsafe.Clean(key.Fingerprint)
	if ansi.StringWidth(fingerprint) >= width {
		return pickerKeepRight(fingerprint, width)
	}
	comment := strings.TrimSpace(key.Comment)
	if comment == "" {
		comment = key.Type
	}
	comment = textsafe.Clean(comment)
	available := width - ansi.StringWidth(fingerprint) - 2
	if available <= 0 {
		return fingerprint
	}
	return ansi.Truncate(comment, available, "…") + "  " + fingerprint
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
	if (r.Outcome == sshverify.HostKeyUnknown || r.Outcome == sshverify.HostKeyChanged || r.Outcome == sshverify.HostKeyRevoked) && r.HostKey != "" {
		// The presented key is the only fingerprint netdoc has for the server, so it is shown
		// for the user to compare with the key they expect. An unknown key is shown too, so the
		// user can compare it before establishing trust with their normal SSH client. Showing it
		// trusts nothing: the check still refuses until a discovery trusts the key.
		lines = append(lines, style.Render("presented host key: "+textsafe.Clean(r.HostKey)))
	}
	if r.Outcome == sshverify.Discovered && r.Identity.Valid() {
		// The check binds to this key: a later check refuses any other, so it is shown to compare.
		lines = append(lines, style.Render("trusted host key: "+textsafe.Clean(r.Identity.Fingerprint)))
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
