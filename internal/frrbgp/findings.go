package frrbgp

// StateEstablished is the state FRR prints for an established session.
const StateEstablished = "Established"

// stateLimits says what each session state RFC 4271 names does not establish.
// FRR prints these six names in a summary. Only they get their own text: any
// other state, such as one with a qualifier, is shown as printed with no meaning
// claimed until a genuine capture shows it.
var stateLimits = map[string]string{
	"Idle":           "Idle means the session is not established and FRR was not attempting a connection when the capture was taken. It names no cause.",
	"Connect":        "Connect means the session is not established and FRR was waiting for its TCP connection to the peer to complete. It names no cause.",
	"Active":         "Active means the session is not established and FRR was waiting to accept or retry a TCP connection to the peer. It names no cause.",
	"OpenSent":       "OpenSent means the session is not established: FRR sent its OPEN and was waiting for the peer's. It names no cause.",
	"OpenConfirm":    "OpenConfirm means the session is not established: FRR accepted the peer's OPEN and was waiting for a KEEPALIVE. It names no cause.",
	StateEstablished: "Established means the session was up when the capture was taken. It does not show that any route was exchanged, accepted, or installed, or that the session stayed up.",
}

// StateLimit says what one session state, as FRR printed it, does not
// establish. A state that is not Established is never reported as down, and no
// state alone shows whether the peer is reachable. The summary names the peer by
// address alone, so the far end is never identified. A state outside the six is
// matched exactly and given no meaning, so a word such as "Down" is never
// contradicted or read as a cause.
func StateLimit(state string) string {
	limit, ok := stateLimits[state]
	switch {
	case !ok:
		limit = "This import does not interpret this state. It is shown as FRR printed it, and no meaning or cause is claimed."
	case state != StateEstablished:
		limit += " The session is not reported as down."
	}
	return limit + " The state alone does not show whether the peer is reachable. The far end is not identified; the summary maps no address to a node."
}
