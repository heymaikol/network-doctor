//go:build linux

package diagnostic

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// siocgiwessid is the wireless-extensions ioctl that reads an interface's
// current ESSID (its Wi-Fi network name). Deprecated in the kernel but still
// served via the cfg80211 compat shim by mainstream drivers.
const siocgiwessid = 0x8B1B

// iwEssidMaxSize is IW_ESSID_MAX_SIZE: the longest ESSID the kernel returns.
const iwEssidMaxSize = 32

// iwreq mirrors the kernel's struct iwreq for the ESSID iw_point case. The
// trailing pad makes it 32 bytes == sizeof(struct iwreq) on amd64, so the
// kernel's copy_from_user stays in bounds.
type iwreq struct {
	name    [16]byte
	pointer *byte
	length  uint16
	flags   uint16
	_       [4]byte
}

// ssid returns the Wi-Fi network name for iface, or "" if it isn't wireless,
// isn't associated, or the kernel doesn't support wireless extensions. The
// result is untrusted (an AP broadcasts its own SSID) so it is sanitized.
// ctx is unused — the ioctl doesn't block (shared signature with the
// exec-based macOS/Windows impls).
func ssid(_ context.Context, iface string) string {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)

	var buf [iwEssidMaxSize + 1]byte
	req := iwreq{pointer: &buf[0], length: iwEssidMaxSize}
	copy(req.name[:len(req.name)-1], iface) // leave room for NUL; long names won't be wireless anyway

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocgiwessid, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return ""
	}
	return parseESSID(buf[:], int(req.length))
}

// parseESSID trims the ioctl's reported length to the buffer and strips the
// trailing NUL / any hostile control bytes via textsafe.Clean.
func parseESSID(buf []byte, n int) string {
	if n < 0 {
		return ""
	}
	if n > len(buf) {
		n = len(buf)
	}
	return textsafe.Clean(string(buf[:n]))
}
