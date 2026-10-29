//go:build gofuzz

package frrbgp

import (
	"reflect"
	"testing"
)

// FuzzOSSDecodeSummary checks the security boundary for untrusted FRR text.
// The build tag excludes this harness from production and the normal CI suite.
func FuzzOSSDecodeSummary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		got, err := Decode(data, "r1")
		if err != nil {
			if !reflect.DeepEqual(got, Summary{}) {
				t.Fatal("failed decode returned nonzero summary")
			}
			return
		}
		second, err := Decode(data, "r1")
		if err != nil || !reflect.DeepEqual(got, second) {
			t.Fatal("same summary input returned a different result")
		}
	})
}

// FuzzOSSDecodeRouteCapture exercises hostile FRR route payloads.
func FuzzOSSDecodeRouteCapture(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		got, err := DecodeRouteCapture(data, "r1")
		if err != nil {
			if !reflect.DeepEqual(got, RouteTable{}) {
				t.Fatal("failed route decode returned nonzero table")
			}
			return
		}
		second, err := DecodeRouteCapture(data, "r1")
		if err != nil || !reflect.DeepEqual(got, second) {
			t.Fatal("same route input returned a different result")
		}
	})
}
