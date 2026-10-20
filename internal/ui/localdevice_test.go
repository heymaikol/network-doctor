// The local-device workflow: pick a device off the network map, see what it
// actually answers on, and diagnose one of those endpoints. Nothing here
// touches a real network; the service check runs through its seam.

package ui

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// stubServices replaces the service check for one test, recording the hosts it
// was asked about so a test can prove which device was opened.
func stubServices(t *testing.T, scan diagnostic.ServiceScan) *[]string {
	t.Helper()
	var asked []string
	old := discoverServices
	discoverServices = func(_ context.Context, _ *diagnostic.SourceAddresses, host string, _ time.Duration) diagnostic.ServiceScan {
		asked = append(asked, host)
		return scan
	}
	t.Cleanup(func() { discoverServices = old })
	return &asked
}

// mapModel is a finished run sitting on a network map with two devices found.
func mapModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:22"), false)
	doneResults(&m, "")
	m.width, m.height = 100, 40
	m.networkMap = true
	m.networkCIDR = "192.168.12.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{
		"Host: 192.168.12.1 (router.lan)\tStatus: Up",
		"Host: 192.168.12.50 (printer.lan)\tStatus: Up",
	}
	return m
}

// msgsFrom resolves a command to the messages it produces, following batches,
// so a test does not have to know whether the spinner was already ticking.
func msgsFrom(t *testing.T, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	if cmd == nil {
		return nil
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		var out []tea.Msg
		for _, c := range msg {
			out = append(out, msgsFrom(t, c)...)
		}
		return out
	default:
		return []tea.Msg{msg}
	}
}

// openDevice presses enter on the map and delivers the service check's reply.
func openDevice(t *testing.T, m model) model {
	t.Helper()
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	found := false
	for _, msg := range msgsFrom(t, cmd) {
		if _, ok := msg.(lanServicesMsg); !ok {
			continue
		}
		found = true
		u, _ = m.Update(msg)
		m = asModel(t, u)
	}
	if !found {
		t.Fatal("opening a device must ask it which services it has")
	}
	return m
}

// flat reflows a rendered view so a sentence can be matched across the panel
// borders and line wrapping the renderer put through it.
func flat(view string) string {
	box := func(r rune) rune {
		if r >= '\u2500' && r <= '\u257f' {
			return ' '
		}
		return r
	}
	return strings.Join(strings.Fields(strings.Map(box, view)), " ")
}

func scanOf(services ...diagnostic.LocalService) diagnostic.ServiceScan {
	return diagnostic.ServiceScan{Open: services, Refused: 15 - len(services)}
}

// The whole point of the two-step flow: the endpoint that gets diagnosed comes
// from what the device answered, not from a default port.
func TestOpenedDeviceDiagnosesTheChosenService(t *testing.T) {
	cases := []struct {
		name      string
		scan      diagnostic.ServiceScan
		down      int // times to press down in the service list
		wantHost  string
		wantPort  int
		wantProto diagnostic.Proto
	}{
		{
			name:     "one service is the only choice",
			scan:     scanOf(diagnostic.LocalService{Port: 9100, Name: "JetDirect"}),
			wantHost: "192.168.12.50", wantPort: 9100, wantProto: diagnostic.ProtoNone,
		},
		{
			name: "the first of several is preselected",
			scan: scanOf(
				diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"},
				diagnostic.LocalService{Port: 631, Name: "IPP"},
				diagnostic.LocalService{Port: 9100, Name: "JetDirect"}),
			wantHost: "192.168.12.50", wantPort: 80, wantProto: diagnostic.ProtoHTTP,
		},
		{
			name: "a printing port is diagnosed at the TCP rung, not as a web server",
			scan: scanOf(
				diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"},
				diagnostic.LocalService{Port: 631, Name: "IPP"},
				diagnostic.LocalService{Port: 9100, Name: "JetDirect"}),
			down:     2,
			wantHost: "192.168.12.50", wantPort: 9100, wantProto: diagnostic.ProtoNone,
		},
		{
			name: "an admin page on an unusual port still gets the HTTP rows",
			scan: scanOf(
				diagnostic.LocalService{Port: 22, Name: "SSH", Scheme: "ssh"},
				diagnostic.LocalService{Port: 8080, Name: "HTTP (alt)", Scheme: "http"}),
			down:     1,
			wantHost: "192.168.12.50", wantPort: 8080, wantProto: diagnostic.ProtoHTTP,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubServices(t, c.scan)
			m := mapModel(t)
			u, _ := m.Update(keyMsg("j")) // the printer, not the router
			m = openDevice(t, asModel(t, u))

			if !strings.Contains(m.helpView(false), "diagnose it") {
				t.Errorf("help = %q, want the service list to offer a diagnosis", m.helpView(false))
			}
			for range c.down {
				u, _ = m.Update(keyMsg("j"))
				m = asModel(t, u)
			}
			u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			m = asModel(t, u)
			if m.target == nil || m.target.Host != c.wantHost || m.target.Port != c.wantPort || m.target.Proto != c.wantProto {
				t.Fatalf("target = %+v, want %s:%d over %s", m.target, c.wantHost, c.wantPort, c.wantProto)
			}
			if m.networkMap || m.svc.host != "" || m.generation != 1 || cmd == nil {
				t.Fatalf("picking a service must close the map and restart: map=%v device=%q gen=%d", m.networkMap, m.svc.host, m.generation)
			}
			// The rebuilt DAG has to be the one the chosen endpoint deserves.
			var names []string
			for _, p := range m.probes {
				names = append(names, p.Name)
			}
			joined := strings.Join(names, "\n")
			wantRow := "TCP " + net.JoinHostPort(c.wantHost, "0")
			wantRow = strings.TrimSuffix(wantRow, "0")
			if !strings.Contains(joined, wantRow) {
				t.Errorf("probe rows = %v, want a TCP row for the chosen endpoint", names)
			}
			if hasHTTP := strings.Contains(joined, "HTTP "); hasHTTP != (c.wantProto == diagnostic.ProtoHTTP) {
				t.Errorf("probe rows = %v, want HTTP rows only for an HTTP service", names)
			}
		})
	}
}

// Nothing answering is a result, not a reason to invent an endpoint.
func TestOpenedDeviceWithNoServices(t *testing.T) {
	cases := []struct {
		name string
		scan diagnostic.ServiceScan
		want string
	}{
		{
			// Refusals prove the device is still there.
			name: "device answers but offers nothing",
			scan: diagnostic.ServiceScan{Refused: 15},
			want: "refused the connection, so the device is on the network",
		},
		{
			// Discovery found it; the service check did not. Both readings
			// stay on the table because nothing here can separate them.
			name: "device went quiet between the scan and now",
			scan: diagnostic.ServiceScan{Silent: 15},
			want: "may be powered off, may have left the network, or may be dropping connections",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubServices(t, c.scan)
			m := openDevice(t, mapModel(t))
			view := flat(m.View())
			if !strings.Contains(view, c.want) {
				t.Fatalf("view must say what was learned:\n%s", view)
			}
			if !strings.Contains(view, "Press r to name a port yourself") {
				t.Errorf("a device with no services must still leave a way forward:\n%s", view)
			}
			if strings.Contains(m.helpView(false), "diagnose it") {
				t.Errorf("help = %q, want no diagnosis offered when there is no endpoint", m.helpView(false))
			}

			before := m.target
			u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			m = asModel(t, u)
			if m.target != before || m.generation != 0 {
				t.Fatalf("target = %+v, want no endpoint invented out of an empty list", m.target)
			}
			if !strings.Contains(m.notice, "no service answered") {
				t.Errorf("notice = %q, want it to say why nothing happened", m.notice)
			}
		})
	}
}

// A reply for a device the user has already left must never repaint the one
// they moved to.
func TestOpenedDeviceIgnoresStaleScans(t *testing.T) {
	fresh := scanOf(diagnostic.LocalService{Port: 22, Name: "SSH", Scheme: "ssh"})
	stale := scanOf(diagnostic.LocalService{Port: 5900, Name: "VNC"})
	stubServices(t, fresh)
	m := openDevice(t, mapModel(t))

	for _, msg := range []lanServicesMsg{
		{gen: m.generation + 1, host: m.svc.host, scan: stale},  // a restart happened
		{gen: m.generation, host: "192.168.12.99", scan: stale}, // another device
	} {
		u, _ := m.Update(msg)
		m = asModel(t, u)
		if len(m.svc.scan.Open) != 1 || m.svc.scan.Open[0].Port != 22 {
			t.Fatalf("services = %+v, want the stale reply dropped", m.svc.scan.Open)
		}
	}
}

// esc steps back out of the device rather than cancelling the finished scan
// that produced the list behind it.
func TestOpenedDeviceEscapeReturnsToTheDeviceList(t *testing.T) {
	stubServices(t, scanOf(diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"}))
	m := openDevice(t, mapModel(t))

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = asModel(t, u)
	if m.svc.host != "" || !m.networkMap {
		t.Fatalf("esc must return to the devices: device=%q map=%v", m.svc.host, m.networkMap)
	}
	if view := m.View(); !strings.Contains(view, "192.168.12.50 (printer)") {
		t.Fatalf("the device list must come back:\n%s", view)
	}
	// And v from there is still the way back to the checks.
	u, _ = m.Update(keyMsg("v"))
	if asModel(t, u).networkMap {
		t.Error("v must still close the map")
	}
}

// The cursor keys walk whichever list is on screen, and leave the Checks panel
// alone while the map owns them.
func TestNetworkMapCursorWalksTheListOnScreen(t *testing.T) {
	stubServices(t, scanOf(
		diagnostic.LocalService{Port: 22, Name: "SSH", Scheme: "ssh"},
		diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"},
		diagnostic.LocalService{Port: 443, Name: "HTTPS", Scheme: "https"}))
	m := mapModel(t)
	m.keys, _ = PresetKeymap("vim")
	selected := m.selected

	// Devices: down past the end clamps, and top/bottom are the ends.
	for range 5 {
		u, _ := m.Update(keyMsg("j"))
		m = asModel(t, u)
	}
	if m.mapSelected != 1 {
		t.Fatalf("device cursor = %d, want it clamped at the last device", m.mapSelected)
	}
	for range 2 { // g g
		u, _ := m.Update(keyMsg("g"))
		m = asModel(t, u)
	}
	if m.mapSelected != 0 {
		t.Fatalf("device cursor = %d, want the first device", m.mapSelected)
	}
	u, _ := m.Update(keyMsg("G"))
	m = asModel(t, u)
	if m.mapSelected != 1 {
		t.Fatalf("device cursor = %d, want the last device", m.mapSelected)
	}

	// Services: the same keys now walk the opened device's list.
	m = openDevice(t, m)
	u, _ = m.Update(keyMsg("G"))
	m = asModel(t, u)
	if m.svc.sel != 2 || m.mapSelected != 1 {
		t.Fatalf("service cursor = %d (device %d), want the last service and the device left alone", m.svc.sel, m.mapSelected)
	}
	for range 5 {
		u, _ = m.Update(keyMsg("k"))
		m = asModel(t, u)
	}
	if m.svc.sel != 0 {
		t.Fatalf("service cursor = %d, want it clamped at the first service", m.svc.sel)
	}
	if m.selected != selected {
		t.Errorf("checks cursor = %d, want %d: the map owns the keys while it is up", m.selected, selected)
	}
}

// Every state of the opened device has to survive a terminal nobody widened.
func TestOpenedDeviceRendersOnANarrowTerminal(t *testing.T) {
	for _, scan := range []diagnostic.ServiceScan{
		scanOf(diagnostic.LocalService{Port: 8443, Name: "HTTPS (alt)", Scheme: "https"}, diagnostic.LocalService{Port: 9100, Name: "JetDirect"}),
		{Refused: 15},
		{Silent: 15},
	} {
		stubServices(t, scan)
		m := mapModel(t)
		m.width, m.height = 30, 10
		m = openDevice(t, m)
		for _, line := range strings.Split(m.View(), "\n") {
			if got := lipgloss.Width(line); got > m.width {
				t.Fatalf("line %q is %d columns wide on a %d-column terminal", line, got, m.width)
			}
		}
		if strings.Count(m.View(), "\n")+1 > m.height {
			t.Errorf("the view is taller than the terminal:\n%s", m.View())
		}
	}
}

// The scan is per device list: a fresh sweep and a restart both retire it.
func TestOpenedDeviceClearedByANewSweepAndByARestart(t *testing.T) {
	stubServices(t, scanOf(diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"}))
	m := openDevice(t, mapModel(t))

	restarted := m
	restarted.doRestart()
	if restarted.svc.host != "" {
		t.Errorf("restart left device %q open on a list that no longer exists", restarted.svc.host)
	}

	relaunched := m
	relaunched.launchTool(Tool{Key: "v", Name: lanDiscoveryName, Bin: "nmap"})
	if relaunched.svc.host != "" {
		t.Errorf("a fresh sweep left device %q open from the previous one", relaunched.svc.host)
	}
}

// A finished run with nothing to fix is the one moment there is room to point
// at what else netdoc does, and the only moment it is offered.
func TestLocalDeviceHint(t *testing.T) {
	privateSource := func(m *model) {
		r := m.results[diagnostic.ProbeInternet]
		r.Source = net.ParseIP("192.168.12.34")
		m.results[diagnostic.ProbeInternet] = r
	}
	cases := []struct {
		name   string
		target *diagnostic.Target
		setup  func(*model)
		want   bool
	}{
		{"finished generic run on a private network", nil, privateSource, true},
		{"a run with a target has its own subject", mustTarget(t, "example.com:443"), privateSource, false},
		{"no private network to sweep", nil, func(*model) {}, false},
		{"already on the map", nil, func(m *model) { privateSource(m); m.networkMap = true }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newModel(c.target, false)
			doneResults(&m, "")
			c.setup(&m)
			if got := strings.Contains(m.banner(), "to find a device on your network"); got != c.want {
				t.Errorf("hint shown = %v, want %v; banner:\n%s", got, c.want, m.banner())
			}
			if !c.want {
				return
			}
			// The hint is the widest sentence a healthy run prints, so it is
			// the one that would run off a narrow terminal.
			u, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
			nm := asModel(t, u)
			for _, line := range strings.Split(nm.View(), "\n") {
				if got := lipgloss.Width(line); got > nm.width {
					t.Errorf("line %q is %d columns wide on a %d-column terminal", line, got, nm.width)
				}
			}
			if !strings.Contains(flat(nm.View()), "to find a device on your network") {
				t.Errorf("the hint did not survive a narrow terminal:\n%s", nm.View())
			}
		})
	}
}

// Discovery that produced no device list has to say which of the ways it
// produced none, and must not leave enter pointing at nothing.
func TestNetworkMapWithoutDevices(t *testing.T) {
	cases := []struct {
		name   string
		status JobStatus
		want   string
	}{
		{"nothing replied", JobDone, "No other devices replied"},
		{"the sweep failed", JobFailed, "Discovery failed"},
		{"the sweep was cancelled", JobCanceled, "Discovery canceled"},
		{"the sweep timed out", JobTimedOut, "Discovery timed out"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := mapModel(t)
			m.cur.lines, m.cur.status = nil, c.status
			if view := m.View(); !strings.Contains(view, c.want) {
				t.Fatalf("view must explain the empty map:\n%s", view)
			}
			// Enter falls through to the job output, which is the only thing
			// left to look at.
			u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			nm := asModel(t, u)
			if nm.svc.host != "" || nm.target != m.target {
				t.Errorf("enter on an empty map opened device %q / target %+v", nm.svc.host, nm.target)
			}
		})
	}
}

// nmap is what discovery needs, and its absence has to be said rather than
// discovered as a blank panel.
func TestNetworkMapWithoutNmap(t *testing.T) {
	old := toolLookPath
	toolLookPath = func(string) (string, error) { return "", net.UnknownNetworkError("not found") }
	t.Cleanup(func() { toolLookPath = old })

	m := newModel(nil, false)
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r

	u, _ := m.Update(keyMsg("v"))
	nm := asModel(t, u)
	if nm.confirmTool != nil || nm.networkMap {
		t.Fatal("v must not open a map it cannot fill")
	}
	if !strings.Contains(nm.notice, "nmap") {
		t.Errorf("notice = %q, want it to name the missing binary", nm.notice)
	}
}
