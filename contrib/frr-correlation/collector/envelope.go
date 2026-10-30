// Package collector defines an untrusted cohort contract and an internal
// validation lifecycle. It does not collect or authenticate live evidence.
package collector

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	SchemaVersion    = "netdoc-frr-cohort/v1"
	MaxEnvelopeBytes = 16 * 1024
	MaxDepth         = 8
	MaxTokens        = 256
	MaxStringBytes   = 128
	MaxNumberBytes   = 20
)

// Envelope contains claims, never proof of namespace lifetime or cohort membership.
// Its identifiers and digests are labels until independently authenticated.
type Envelope struct {
	Schema              string    `json:"schema"`
	CohortID            string    `json:"cohort_id"`
	BootID              string    `json:"boot_id"`
	Namespace           Namespace `json:"namespace"`
	BuildID             string    `json:"build_id"`
	CertificateSHA256   string    `json:"certificate_sha256"`
	Producers           Producers `json:"producers"`
	BundleSHA256        string    `json:"bundle_sha256"`
	SelectedFIBVerified bool      `json:"selected_fib_verified"`
}

type Namespace struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Producers names separate captures, not a shared writable inbox.
type Producers struct {
	BGPD  Producer `json:"bgpd"`
	Zebra Producer `json:"zebra"`
}

type Producer struct {
	PID            uint64 `json:"pid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	Epoch          string `json:"epoch"`
	CaptureSHA256  string `json:"capture_sha256"`
	CaptureBytes   uint64 `json:"capture_bytes"`
}

// UntrustedEnvelope can only be populated by Decode. Copies share immutable data.
type UntrustedEnvelope struct{ envelope *Envelope }

// Claims returns a value copy; changing it cannot change a lifecycle's input.
func (u UntrustedEnvelope) Claims() Envelope {
	if u.envelope == nil {
		return Envelope{}
	}
	return *u.envelope
}

//go:embed schema.json
var schemaJSON []byte

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	const id = "urn:netdoc:frr:cohort:v1"
	if err := c.AddResource(id, doc); err != nil {
		return nil, err
	}
	return c.Compile(id)
})

// Decode accepts one bounded JSON object. It does not authenticate any claims.
// Callers must impose a read deadline on blocking readers; byte limits are not timeouts.
func Decode(r io.Reader) (UntrustedEnvelope, error) {
	if r == nil {
		return UntrustedEnvelope{}, refusal(MalformedJSON)
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxEnvelopeBytes+1))
	if err != nil {
		return UntrustedEnvelope{}, refusal(ReadFailure)
	}
	if len(data) > MaxEnvelopeBytes {
		return UntrustedEnvelope{}, refusal(ResourceLimit)
	}
	if !utf8.Valid(data) {
		return UntrustedEnvelope{}, refusal(MalformedJSON)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	w := jsonWalk{decoder: d}
	doc, err := w.value(0)
	if err != nil {
		return UntrustedEnvelope{}, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return UntrustedEnvelope{}, refusal(MalformedJSON)
	}
	sch, err := compiledSchema()
	if err != nil {
		return UntrustedEnvelope{}, refusal(ContractFailure)
	}
	if err := sch.Validate(doc); err != nil {
		return UntrustedEnvelope{}, refusal(InvalidEnvelope)
	}
	var envelope Envelope
	// Tokens and schema were validated without converting integers through float64.
	if err := json.Unmarshal(data, &envelope); err != nil {
		return UntrustedEnvelope{}, refusal(InvalidEnvelope)
	}
	if envelope.Producers.BGPD.PID == envelope.Producers.Zebra.PID ||
		envelope.Producers.BGPD.Epoch == envelope.Producers.Zebra.Epoch {
		return UntrustedEnvelope{}, refusal(InvalidEnvelope)
	}
	return UntrustedEnvelope{envelope: &envelope}, nil
}

type jsonWalk struct {
	decoder *json.Decoder
	tokens  int
}

func (w *jsonWalk) token() (json.Token, error) {
	w.tokens++
	if w.tokens > MaxTokens {
		return nil, refusal(ResourceLimit)
	}
	t, err := w.decoder.Token()
	if err != nil {
		return nil, refusal(MalformedJSON)
	}
	if s, ok := t.(string); ok && len(s) > MaxStringBytes {
		return nil, refusal(ResourceLimit)
	}
	// Bound numeric work before the schema library's arbitrary-precision arithmetic.
	if n, ok := t.(json.Number); ok {
		if len(n) > MaxNumberBytes {
			return nil, refusal(ResourceLimit)
		}
		if _, err := strconv.ParseUint(string(n), 10, 64); err != nil {
			return nil, refusal(InvalidEnvelope)
		}
	}
	return t, nil
}

func (w *jsonWalk) value(depth int) (any, error) {
	t, err := w.token()
	if err != nil {
		return nil, err
	}
	d, container := t.(json.Delim)
	if !container {
		return t, nil
	}
	if depth >= MaxDepth {
		return nil, refusal(ResourceLimit)
	}
	switch d {
	case '{':
		obj := make(map[string]any)
		for w.decoder.More() {
			key, err := w.token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, refusal(MalformedJSON)
			}
			if _, duplicate := obj[name]; duplicate {
				return nil, refusal(MalformedJSON)
			}
			v, err := w.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj[name] = v
		}
		end, err := w.token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim('}') {
			return nil, refusal(MalformedJSON)
		}
		return obj, nil
	case '[':
		var list []any
		for w.decoder.More() {
			v, err := w.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		end, err := w.token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim(']') {
			return nil, refusal(MalformedJSON)
		}
		return list, nil
	default:
		return nil, refusal(MalformedJSON)
	}
}
