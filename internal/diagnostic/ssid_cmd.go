//go:build darwin || windows

package diagnostic

import (
	"os/exec"
)

// ssidCommand starts a platform SSID lookup. Production uses
// exec.CommandContext; tests replace it with a fixture so the wrappers can
// run without a wireless adapter. Darwin/Windows-only: Linux uses ioctl.
var ssidCommand = exec.CommandContext
