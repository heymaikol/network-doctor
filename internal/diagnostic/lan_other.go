//go:build !linux && !darwin && !windows

package diagnostic

import (
	"errors"
	"net/netip"
)

func bindLANSocket(uintptr, lanLink) error       { return errors.ErrUnsupported }
func lanEchoProbe(lanLink) (lanProbe, error)     { return nil, errors.ErrUnsupported }
func lanNeighbors(lanLink) ([]netip.Addr, error) { return nil, errors.ErrUnsupported }
