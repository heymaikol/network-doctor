package main

// Entry point for the test binary. TestMain serves the sender role that runCase starts, so it stays in the default build.
// The R6 reproductions that open socket pairs are in repro_integration_test.go, which carries the integration tag.

import (
	"os"
	"testing"
)

// TestMain lets runCase start this test binary as the sender role (the same dispatch as main).
func TestMain(m *testing.M) {
	if os.Getenv("FRAME61_ROLE") == "sender" {
		sender()
		os.Exit(0)
	}
	var err error
	self, err = os.Executable()
	must(err)
	os.Exit(m.Run())
}
