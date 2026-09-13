// The set of tool runs: iteration, lookup by job id, and which one is selected.
// The selected run lives in model.cur and the parked ones in model.otherJobs;
// that split is this file's business, and nothing outside it should walk both
// fields by hand.

package ui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// jobs yields every run worth counting, selected first. An empty cur slot is
// not a run, so callers that mean "all jobs" never trip over the zero value.
func (m *model) jobs(yield func(*jobState) bool) {
	if m.hasJob() && !yield(&m.cur) {
		return
	}
	for i := range m.otherJobs {
		if !yield(&m.otherJobs[i]) {
			return
		}
	}
}

// jobByID finds the run a tool message belongs to. nil means the job is gone,
// cleared by a restart, and the message should be dropped.
func (m *model) jobByID(id string) *jobState {
	for j := range m.jobs {
		if j.active != nil && j.active.id == id {
			return j
		}
	}
	return nil
}

// runningJobs counts live subprocesses, the selected slot included. A job with
// no active handle has already delivered its ToolDoneMsg.
func (m model) runningJobs() int {
	n := 0
	for j := range m.jobs {
		if j.active != nil {
			n++
		}
	}
	return n
}

func (m model) jobsRunning() bool { return m.runningJobs() > 0 }

// dropJobs forgets every run. Anything still streaming gets a background
// drainer, since after this there's no jobState left to route its messages to.
func (m *model) dropJobs() {
	for j := range m.jobs {
		j.active.drain()
	}
	m.cur, m.otherJobs = jobState{}, nil
}

func (m *model) cancelJobs() {
	for j := range m.jobs {
		if j.active != nil && j.active.cancel != nil {
			j.active.cancel()
		}
	}
}

// stashJob parks the selected run at the end of the ring, leaving the slot free
// for a new one. An empty slot is dropped rather than parked: a zero jobState
// must never become a tab stop.
//
// The network map is a rendering of the selected slot, not a view of its own:
// it reads the scan's hosts and status straight out of m.cur. Freeing the slot
// therefore closes the map, and every path that replaces the selected run comes
// through here. Callers that mean to keep it open reopen it afterwards, which
// is what launching the scan and recalling a parked one already do; without
// this, a run that lands in the slot from elsewhere, such as a finished ssh
// session, would be read as the scan's own outcome.
func (m *model) stashJob() {
	m.networkMap = false
	if m.hasJob() {
		m.otherJobs = append(m.otherJobs, m.cur)
		m.cur = jobState{}
		m.trimJobs()
	}
}

// trimJobs drops the oldest finished runs until the ring is back under
// maxParkedJobs. A live run is never dropped: its output still needs a jobState
// to route to, and the user didn't ask for it to be killed. That means the ring
// can sit over the cap while jobs are in flight, and maxActiveJobs bounds how far.
func (m *model) trimJobs() {
	for i := 0; i < len(m.otherJobs) && len(m.otherJobs) > maxParkedJobs; {
		if m.otherJobs[i].active != nil {
			i++
			continue
		}
		m.otherJobs = append(m.otherJobs[:i], m.otherJobs[i+1:]...)
	}
}

// selectJob pulls otherJobs[i] into the selected slot, parking whatever was
// there at the end of the ring. Both tab (round-robin) and 'v' (re-show the LAN
// scan by name) go through here, so they can't disagree about the ring order.
func (m *model) selectJob(i int) {
	next := m.otherJobs[i]
	m.otherJobs = append(m.otherJobs[:i], m.otherJobs[i+1:]...)
	m.stashJob()
	m.cur = next
}

// switchJob is tab: select the oldest parked run.
func (m *model) switchJob() tea.Cmd {
	if len(m.otherJobs) == 0 {
		return nil
	}
	m.selectJob(0)
	if m.viewing {
		m.follow = true
	}
	// Keep the armed quit intact so the next Ctrl+C still quits.
	if m.notice == ctrlCNotice && time.Now().Before(m.noticeDeadline) {
		if m.viewing {
			m.refreshViewport()
		}
		return nil
	}
	return m.setNotice("switched to "+m.cur.name, true)
}
