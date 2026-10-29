package collector

// RefusalCode is a stable machine-readable reason. Diagnostics never echo input.
type RefusalCode string

const (
	MalformedJSON      RefusalCode = "malformed_json"
	ResourceLimit      RefusalCode = "resource_limit"
	InvalidEnvelope    RefusalCode = "invalid_envelope"
	ReadFailure        RefusalCode = "read_failure"
	ContractFailure    RefusalCode = "contract_failure"
	Unauthenticated    RefusalCode = "unauthenticated"
	InvalidTransition  RefusalCode = "invalid_transition"
	Incomplete         RefusalCode = "incomplete"
	Replay             RefusalCode = "replay"
	Aborted            RefusalCode = "aborted"
	MaxDiagnosticBytes             = 160
)

type Refusal struct{ code RefusalCode }

func (r *Refusal) Code() RefusalCode { return r.code }

func (r *Refusal) Error() string {
	switch r.code {
	case MalformedJSON:
		return "malformed_json: expected one strict JSON object"
	case ResourceLimit:
		return "resource_limit: envelope exceeds a fixed parsing limit"
	case InvalidEnvelope:
		return "invalid_envelope: required fields or identities violate the cohort contract"
	case ReadFailure:
		return "read_failure: could not read the complete envelope"
	case ContractFailure:
		return "contract_failure: installed cohort schema is invalid"
	case Unauthenticated:
		return "unauthenticated: serialized data cannot establish trust"
	case InvalidTransition:
		return "invalid_transition: required lifecycle stage missing or repeated"
	case Incomplete:
		return "incomplete: trusted validation and handoff have not completed"
	case Replay:
		return "replay: lifecycle result has already been consumed"
	case Aborted:
		return "aborted: collection lifecycle was cancelled"
	default:
		return "unauthenticated: no trusted validation result"
	}
}

func refusal(code RefusalCode) *Refusal { return &Refusal{code: code} }
