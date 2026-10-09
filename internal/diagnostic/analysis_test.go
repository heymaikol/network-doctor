package diagnostic

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDiagnosisReuseDerivedViews(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			before, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if got := d.Collateral(c.order, c.res); !reflect.DeepEqual(got, Collateral(c.target, c.order, c.res)) {
				t.Fatal("precomputed collateral differs")
			}
			if got := d.Explain(c.target, c.order, c.res); got != Explain(c.target, c.order, c.res) {
				t.Fatal("precomputed explanation differs")
			}
			probes := make([]Probe, len(c.order))
			for i, id := range c.order {
				probes[i] = Probe{ID: id, Name: string(id)}
			}
			shared, err := json.Marshal(BuildSnapshotWithDiagnosis(c.target, probes, c.res, d))
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := json.Marshal(BuildSnapshot(c.target, probes, c.res))
			if err != nil {
				t.Fatal(err)
			}
			if string(shared) != string(fresh) {
				t.Fatal("precomputed snapshot serialization differs")
			}
			after, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("a derived view mutated the diagnosis")
			}
		})
	}
}
