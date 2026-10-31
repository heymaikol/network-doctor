// Package capture is the boundary between a producer-writable inbox and
// collector-owned evidence. It creates one private directory per producer and
// turns the single stream inside it into a sealed, immutable, hashed snapshot
// held in memory.
//
// A Snapshot is not frozen evidence and carries no trust. It proves that when it
// was taken no file description open for writing existed on the stream's inode,
// and that its bytes cannot change afterwards. It does not prove that the
// producer's processes have exited, that the other producer could not write the
// inbox, or who wrote the bytes. This package imports neither the collector nor
// the supervisor and cannot advance a collector.Lifecycle.
//
// Nothing here parses producer content. A name is checked for shape and never
// echoed; a digest is computed from the sealed bytes, never read from them.
package capture

// Role names the daemon whose inbox this is. It decides the only stream name an
// inbox accepts.
type Role string

const (
	BGPD  Role = "bgpd"
	Zebra Role = "zebra"
)

// MaxStreamBytes is the per-daemon capture cap of the v1 packager.
const MaxStreamBytes = 64 << 20

// Code is a stable machine-readable refusal reason.
type Code string

const (
	Unsupported       Code = "unsupported"
	InvalidRole       Code = "invalid_role"
	Closed            Code = "closed"
	AlreadyUsed       Code = "already_used"
	UnexpectedEntry   Code = "unexpected_entry"
	MixedEpochs       Code = "mixed_epochs"
	NotRegular        Code = "not_regular"
	LinkRefused       Code = "link_refused"
	OwnerRefused      Code = "owner_refused"
	FilesystemRefused Code = "filesystem_refused"
	WriterPresent     Code = "writer_present"
	Modified          Code = "modified_during_seal"
	ResourceLimit     Code = "resource_limit"
	ReadFailure       Code = "read_failure"
	SealFailure       Code = "seal_failure"
	Cancelled         Code = "cancelled"
	CleanupIncomplete Code = "cleanup_incomplete"

	// MaxDiagnosticBytes bounds every Refusal message.
	MaxDiagnosticBytes = 160
)

// Refusal is the only error this package returns. Its text is fixed per code and
// never contains a file name, path, errno or producer-supplied byte.
type Refusal struct{ code Code }

func (r *Refusal) Code() Code { return r.code }

func (r *Refusal) Error() string {
	if msg, ok := messages[r.code]; ok {
		return msg
	}
	return "unsupported: no usable capture result"
}

var messages = map[Code]string{
	Unsupported:       "unsupported: this platform, kernel or filesystem cannot prove the capture is quiet",
	InvalidRole:       "invalid_role: the inbox role is not bgpd or zebra",
	Closed:            "closed: the inbox or snapshot is closed",
	AlreadyUsed:       "already_used: this inbox has already been sealed or refused",
	UnexpectedEntry:   "unexpected_entry: the inbox must hold exactly one stream for its role",
	MixedEpochs:       "mixed_epochs: the inbox holds more than one stream",
	NotRegular:        "not_regular: the stream is not a regular file",
	LinkRefused:       "link_refused: the stream is a symlink or has more than one link",
	OwnerRefused:      "owner_refused: the stream is not owned by the collector's user",
	FilesystemRefused: "filesystem_refused: the filesystem is not one whose writers the kernel can see",
	WriterPresent:     "writer_present: a process still holds the stream open for writing",
	Modified:          "modified_during_seal: the stream or its inbox changed while it was read",
	ResourceLimit:     "resource_limit: the inbox exceeds a fixed size or entry limit",
	ReadFailure:       "read_failure: the stream could not be read completely",
	SealFailure:       "seal_failure: the snapshot could not be made immutable",
	Cancelled:         "cancelled: sealing was cancelled",
	CleanupIncomplete: "cleanup_incomplete: the inbox could not be fully removed, retry Close",
}

func refuse(code Code) *Refusal { return &Refusal{code: code} }
