// Package supervisor owns the Linux namespace lifetime and child processes of
// one future FRR cohort attempt. It launches and observes; it does not
// authenticate, collect, freeze, package or hand off evidence, and it never
// advances a collector.Lifecycle.
//
// Identity here is a set of kernel facts read through descriptors and process
// handles this package holds. A numeric PID, start tick, namespace inode, label
// or producer-supplied value is never authentication. Device and inode numbers
// are compared only between descriptors that are open at the same moment.
package supervisor

import "errors"

var (
	ErrUnsupported       = errors.New("supervisor: unsupported platform or kernel")
	ErrClosed            = errors.New("supervisor: namespace closed")
	ErrNotIsolated       = errors.New("supervisor: namespace not isolated from the supervisor")
	ErrIdentityMismatch  = errors.New("supervisor: process is not in the retained namespaces")
	ErrFDLeak            = errors.New("supervisor: inheritable descriptor refused")
	ErrCleanupIncomplete = errors.New("supervisor: cleanup incomplete")
)

// Identity holds device and inode numbers of the retained user and network
// namespaces. They are observations, comparable only while the retaining
// descriptors are open, and never proof of ownership.
type Identity struct {
	NetDev, NetIno, UserDev, UserIno uint64
}
