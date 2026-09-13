package snapshot

import (
	"os"
	"strings"
	"testing"
)

// MaxArtifactBytes is a property of the format, not one reader's policy, so
// the writer and every reader have to hold the same line: Encode never
// publishes an artifact that Decode would refuse, and Decode refuses an
// oversized one whatever wrote it. The bounded offline read in internal/app
// stops at the same size for the same reason, one step earlier.
func TestMaxArtifactBytesBoundsEncodeAndDecode(t *testing.T) {
	t.Run("Encode refuses an oversized snapshot", func(t *testing.T) {
		s := diagnosed()
		// Valid in every other respect. Only the encoded size is out of bounds.
		s.Diagnosis.Summary = strings.Repeat("x", MaxArtifactBytes)
		data, err := Encode(s)
		if err == nil {
			t.Fatalf("Encode published %d bytes, over the %d byte maximum", len(data), MaxArtifactBytes)
		}
		if !strings.Contains(err.Error(), "maximum artifact size") {
			t.Errorf("Encode error = %v, want it to name the maximum artifact size", err)
		}
	})

	t.Run("Decode refuses oversized input", func(t *testing.T) {
		over := make([]byte, MaxArtifactBytes+1)
		_, err := Decode(over)
		if err == nil || !strings.Contains(err.Error(), "maximum artifact size") {
			t.Fatalf("Decode(%d bytes) error = %v, want the maximum artifact size refusal", len(over), err)
		}
		// One byte less is refused by the decoder rather than by the ceiling,
		// which is what makes the boundary itself accepted rather than off by
		// one in either direction.
		_, err = Decode(make([]byte, MaxArtifactBytes))
		if err == nil || strings.Contains(err.Error(), "maximum artifact size") {
			t.Fatalf("Decode(%d bytes) error = %v, want a decoding failure and not a size refusal", MaxArtifactBytes, err)
		}
	})

	t.Run("an ordinary generated snapshot is unaffected", func(t *testing.T) {
		golden, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read %s: %v", goldenPath, err)
		}
		s, err := Decode(golden)
		if err != nil {
			t.Fatalf("Decode(%s): %v", goldenPath, err)
		}
		data, err := Encode(s)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if len(data) > MaxArtifactBytes {
			t.Errorf("a generated snapshot encodes to %d bytes, over the %d byte maximum", len(data), MaxArtifactBytes)
		}
	})
}
