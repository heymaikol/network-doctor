package collector_test

import (
	"encoding/json"
	"testing"

	"github.com/heymaikol/network-doctor/v2/contrib/frr-correlation/collector"
)

// This caller is outside the package's trusted implementation boundary.
func TestPublicAPICannotAuthenticateSerializedData(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"envelope":{"selected_fib_verified":false},"authenticated":true}`,
		`{"attempt":{"stage":6},"receipt":{"envelope":{}},"valid":true}`,
	} {
		var input collector.UntrustedEnvelope
		//nolint:staticcheck // Negative control: JSON must not populate private state (SA9005).
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatal(err)
		}
		l := collector.NewLifecycle(input)
		result, err := l.Result()
		if err == nil || result.Valid() || result.SelectedFIBVerified() {
			t.Fatal("forged input authenticated")
		}
		var forged collector.Lifecycle
		//nolint:staticcheck // Negative control: JSON must not populate private state (SA9005).
		if err := json.Unmarshal([]byte(raw), &forged); err != nil {
			t.Fatal(err)
		}
		result, err = forged.Result()
		if err == nil || result.Valid() {
			t.Fatal("forged lifecycle authenticated")
		}
		var receipt collector.TrustedResult
		if err := json.Unmarshal([]byte(raw), &receipt); err == nil {
			t.Fatal("serialized receipt accepted")
		}
		if receipt.Valid() {
			t.Fatal("forged receipt authenticated")
		}
	}
}
