package main

import (
	"bytes"
	"maps"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// Scorecard publishes signed results, so its one job holds an OIDC token and
// the code scanning upload scope, and nothing more. The top level grants
// nothing, so a job added later starts with no token instead of inheriting
// one; api.scorecard.dev also rejects any top-level write.
func TestScorecardWorkflowGrantsOnlyWhatPublishingNeeds(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/scorecard.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Permissions yaml.Node `yaml:"permissions"`
		Jobs        map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if p := workflow.Permissions; p.Kind != yaml.MappingNode || len(p.Content) != 0 {
		top, _ := yaml.Marshal(&p)
		t.Errorf("top-level permissions = %s, want {}", bytes.TrimSpace(top))
	}
	want := map[string]string{"security-events": "write", "id-token": "write"}
	if len(workflow.Jobs) != 1 || !maps.Equal(workflow.Jobs["scorecard"].Permissions, want) {
		t.Errorf("jobs = %v, want only a scorecard job with exactly %v", workflow.Jobs, want)
	}
}
