//go:build !linux

package capture

import "context"

// Inbox and Snapshot are unavailable off Linux: the proof they give needs file
// leases and sealed memory files. NewInbox, Seal, Inbox.Close and Snapshot.ReadAt
// refuse with unsupported. Path, Size and SHA256 return zero values, and
// Snapshot.Close returns nil.
type Inbox struct{}

type Snapshot struct{}

func NewInbox(Role) (*Inbox, error) { return nil, refuse(Unsupported) }

func (*Inbox) Path() string { return "" }

func (*Inbox) Seal(context.Context) (*Snapshot, error) { return nil, refuse(Unsupported) }

func (*Inbox) Close() error { return refuse(Unsupported) }

func (*Snapshot) Size() int64 { return 0 }

func (*Snapshot) SHA256() [32]byte { return [32]byte{} }

func (*Snapshot) ReadAt([]byte, int64) (int, error) { return 0, refuse(Unsupported) }

func (*Snapshot) Close() error { return nil }
