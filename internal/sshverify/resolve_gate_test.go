package sshverify

import "testing"

// requireConfigRead skips a test that reads configuration on a platform that refuses the
// read. ReadConfig refuses before any client starts, so a fake client or a headless child
// would only report that refusal.
func requireConfigRead(t *testing.T) {
	t.Helper()
	if !configPlatformSupported {
		t.Skip("the configuration read is refused on this platform, so no client is started")
	}
}
