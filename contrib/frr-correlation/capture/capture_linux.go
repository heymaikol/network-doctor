//go:build linux

package capture

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	maxEntries = 8
	chunkBytes = 1 << 20
	sealAll    = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
)

// streamName is the v1 writer's final name for one role: lowercase UUID, no
// .partial or .failed suffix.
func streamName(r Role) *regexp.Regexp {
	return regexp.MustCompile(`^` + string(r) + `\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl$`)
}

// readableFS lists filesystems whose writers all go through this kernel's VFS on
// the inode, which is what the write-lease proof sees. FUSE, network and overlay
// filesystems can change bytes outside it, so they are refused, not guessed at.
var readableFS = map[int64]bool{
	unix.TMPFS_MAGIC:       true,
	unix.EXT4_SUPER_MAGIC:  true,
	unix.BTRFS_SUPER_MAGIC: true,
	unix.XFS_SUPER_MAGIC:   true,
}

// Inbox is one producer's private writable directory. The collector keeps the
// directory open from creation and reaches the stream only through that
// descriptor; Path exists for the producer and is never used to open anything.
// It is safe for concurrent use. Callers must Close it: dropping it leaves the
// directory on disk.
//
// An Inbox moves one way through its states. It starts open. Seal moves it to
// used, whether the Seal succeeds or refuses, and later Seals return already_used.
// The first call to Close moves it to closing, whether or not that call finishes
// the removal, and from then on Seal returns closed and accepts nothing new, even
// if the producer changes the directory between Close attempts. A closing Inbox
// keeps its directory descriptor so that later Close calls can finish the removal;
// it becomes closed once the directory is proven removed. None of these moves
// affects a Snapshot already returned.
type Inbox struct {
	role    Role
	re      *regexp.Regexp
	path    string
	mu      sync.Mutex // guards the fields below and serializes Seal and Close
	dir     *os.File
	dev     uint64
	ino     uint64
	euid    int // the collector's user, which must own the directory and the stream
	used    bool
	closing bool // Close has begun: Seal accepts nothing new, Close may still be retried
	closed  bool // the directory is proven removed and the descriptor is released

	// Test seams. Production leaves them nil and uses the real values.
	maxBytes    int64
	statfs      func(fd int, st *unix.Statfs_t) error
	afterList   func()         // after the listing, before the stream is opened
	afterCopy   func()         // after the bytes are copied, before they are rechecked
	afterChunk  func()         // after each chunk is written to the sealed copy
	reorder     func([]string) // permutes the names Close is about to remove
	beforeRmdir func()         // after Close checked the pathname, immediately before it removes it
}

// NewInbox creates an empty 0700 directory for role under the temporary
// directory and keeps it open. Mode 0700 only excludes other users: producers run
// as the collector's user and are not kept out by it.
func NewInbox(role Role) (*Inbox, error) { return newInbox(role, unix.Fstatfs) }

func newInbox(role Role, statfs func(int, *unix.Statfs_t) error) (*Inbox, error) {
	if role != BGPD && role != Zebra {
		return nil, refuse(InvalidRole)
	}
	path, err := os.MkdirTemp("", "netdoc-"+string(role)+"-")
	if err != nil {
		return nil, refuse(ReadFailure)
	}
	i := &Inbox{role: role, re: streamName(role), path: path, euid: os.Geteuid(), maxBytes: MaxStreamBytes, statfs: statfs}
	if err := i.adopt(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return i, nil
}

// adopt opens the new directory without following links and requires it to be
// the empty private directory MkdirTemp just made.
func (i *Inbox) adopt() error {
	f, err := os.OpenFile(i.path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0) // Go adds close-on-exec
	if err != nil {
		return refuse(ReadFailure)
	}
	var st, byName unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || unix.Lstat(i.path, &byName) != nil {
		_ = f.Close()
		return refuse(ReadFailure)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o777 != 0o700 || int(st.Uid) != i.euid ||
		st.Dev != byName.Dev || st.Ino != byName.Ino {
		_ = f.Close()
		return refuse(OwnerRefused)
	}
	if err := i.checkFS(int(f.Fd())); err != nil {
		_ = f.Close()
		return err
	}
	if names, err := f.Readdirnames(1); err != io.EOF || len(names) != 0 {
		_ = f.Close()
		return refuse(UnexpectedEntry)
	}
	i.dir, i.dev, i.ino = f, uint64(st.Dev), st.Ino //nolint:unconvert // Dev is uint32 on some architectures.
	return nil
}

func (i *Inbox) checkFS(fd int) error {
	var fs unix.Statfs_t
	if i.statfs(fd, &fs) != nil {
		return refuse(FilesystemRefused)
	}
	// Type is int32 on some architectures, where the btrfs magic reads negative.
	if !readableFS[int64(uint32(fs.Type))] { //nolint:gosec // G115: the magic numbers all fit in 32 bits.
		return refuse(FilesystemRefused)
	}
	return nil
}

// Path is where the producer is told to write. It is an untrusted pathname: a
// producer can rename or replace it, so the collector never resolves it again.
func (i *Inbox) Path() string {
	if i == nil {
		return ""
	}
	return i.path
}

// Seal turns the inbox's single stream into a Snapshot. Call it only after the
// producers were stopped; a success then still does not prove they are gone.
//
// Seal consumes the inbox whatever happens, so a restarted producer's later
// stream can never be spliced into this attempt. It refuses unless the inbox
// holds exactly one stream with the role's v1 name, which is a regular file with
// one link, owned by this user, on a filesystem the lease proof can trust, no
// larger than MaxStreamBytes, and unmodified while read. A write-lease on the
// inode is the writer check: the kernel grants it only when no file description
// open for writing exists anywhere, and it makes a late writer both wait and
// show up as a broken lease.
func (i *Inbox) Seal(ctx context.Context) (*Snapshot, error) {
	if i == nil {
		return nil, refuse(Closed)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.dir == nil || i.closing || i.closed {
		return nil, refuse(Closed)
	}
	if i.used {
		return nil, refuse(AlreadyUsed)
	}
	i.used = true
	if ctx.Err() != nil {
		return nil, refuse(Cancelled)
	}
	return i.seal(ctx)
}

func (i *Inbox) seal(ctx context.Context) (*Snapshot, error) {
	dirfd := int(i.dir.Fd())
	names, more, err := i.list()
	if err != nil {
		return nil, err
	}
	if more {
		return nil, refuse(ResourceLimit)
	}
	name, err := i.pick(names)
	if err != nil {
		return nil, err
	}
	var byName unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &byName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, refuse(Modified)
	}
	switch byName.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFLNK:
		return nil, refuse(LinkRefused)
	default:
		return nil, refuse(NotRegular)
	}
	if i.afterList != nil {
		i.afterList()
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, refuse(LinkRefused)
	case err != nil:
		return nil, refuse(Modified)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := i.checkFS(fd); err != nil {
		return nil, err
	}
	var pre unix.Stat_t
	if err := unix.Fstat(fd, &pre); err != nil {
		return nil, refuse(ReadFailure)
	}
	if pre.Mode&unix.S_IFMT != unix.S_IFREG { // a lease on anything else is not a writer proof
		return nil, refuse(NotRegular)
	}
	// The lease comes before the baseline: kernel timestamps are coarse, so a
	// write that ended just before the lease could otherwise match the baseline.
	// Closing the descriptor drops the lease too; the explicit release only keeps
	// a legitimate writer from waiting on a lease that outlives this call.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_RDLCK); err != nil {
		if errors.Is(err, unix.EAGAIN) {
			return nil, refuse(WriterPresent)
		}
		return nil, refuse(Unsupported)
	}
	defer func() { _, _ = unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_UNLCK) }()
	var base unix.Stat_t
	if err := unix.Fstat(fd, &base); err != nil {
		return nil, refuse(ReadFailure)
	}
	if err := i.admit(&base, &byName); err != nil {
		return nil, err
	}
	m, err := i.copyOut(ctx, fd, base.Size)
	if err != nil {
		return nil, err
	}
	if i.afterCopy != nil {
		i.afterCopy()
	}
	snap, err := i.finish(fd, name, &base, m)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return snap, nil
}

// list reads the inbox through a new description of the retained directory, so a
// swapped pathname cannot redirect it. It returns at most maxEntries names and
// reports whether there were more.
func (i *Inbox) list() (names []string, more bool, err error) {
	fd, err := unix.Openat(int(i.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, refuse(ReadFailure)
	}
	d := os.NewFile(uintptr(fd), "")
	defer func() { _ = d.Close() }()
	names, err = d.Readdirnames(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, refuse(ReadFailure)
	}
	if len(names) > maxEntries {
		return names[:maxEntries], true, nil
	}
	return names, false, nil
}

// pick requires exactly one entry and that it has this role's stream name.
func (i *Inbox) pick(names []string) (string, error) {
	var hit []string
	for _, n := range names {
		if i.re.MatchString(n) {
			hit = append(hit, n)
		}
	}
	switch {
	case len(hit) > 1:
		return "", refuse(MixedEpochs)
	case len(hit) == 0 || len(names) != 1:
		return "", refuse(UnexpectedEntry)
	}
	return hit[0], nil
}

// admit checks the opened descriptor against the entry that was listed.
func (i *Inbox) admit(st, listed *unix.Stat_t) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return refuse(NotRegular)
	case st.Dev != listed.Dev || st.Ino != listed.Ino:
		return refuse(Modified)
	case st.Nlink != 1:
		return refuse(LinkRefused)
	case int(st.Uid) != i.euid:
		return refuse(OwnerRefused)
	case st.Size > i.maxBytes:
		return refuse(ResourceLimit)
	}
	return nil
}

// copyOut copies exactly size bytes into a new memfd and requires end of file
// right after them. The cap on size was checked before, so the copy is bounded.
func (i *Inbox) copyOut(ctx context.Context, src int, size int64) (*os.File, error) {
	mfd, err := unix.MemfdCreate("netdoc-capture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_NOEXEC_SEAL)
	if errors.Is(err, unix.EINVAL) { // kernel older than 6.3 does not know the flag
		mfd, err = unix.MemfdCreate("netdoc-capture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, refuse(Unsupported)
	}
	m := os.NewFile(uintptr(mfd), "")
	buf := make([]byte, chunkBytes)
	for off := int64(0); off < size; {
		if ctx.Err() != nil {
			_ = m.Close()
			return nil, refuse(Cancelled)
		}
		n, err := unix.Pread(src, buf[:min(int64(len(buf)), size-off)], off)
		if err != nil || n == 0 { // a short file means it was truncated under the lease
			_ = m.Close()
			return nil, refuse(Modified)
		}
		if _, err := m.Write(buf[:n]); err != nil {
			_ = m.Close()
			return nil, refuse(ReadFailure)
		}
		off += int64(n)
		if i.afterChunk != nil {
			i.afterChunk()
		}
	}
	if n, err := unix.Pread(src, buf[:1], size); err != nil || n != 0 {
		_ = m.Close()
		return nil, refuse(Modified)
	}
	return m, nil
}

// finish rechecks everything that could show the read raced a writer, then seals
// and hashes. The checks are conservative: any difference refuses.
func (i *Inbox) finish(fd int, name string, base *unix.Stat_t, m *os.File) (*Snapshot, error) {
	var now, byName unix.Stat_t
	if unix.Fstat(fd, &now) != nil || unix.Fstatat(int(i.dir.Fd()), name, &byName, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, refuse(Modified)
	}
	// The name must still map to the inode that was read. A hard link made outside
	// the inbox before a forged file is renamed over the name would leave the old
	// inode with one link, so the link count alone does not show replacement.
	// ctime is only a best-effort extra signal: its resolution depends on the
	// kernel, so the mode and owner are compared directly.
	if now.Dev != base.Dev || now.Ino != base.Ino || now.Size != base.Size || now.Nlink != 1 ||
		now.Mode != base.Mode || now.Uid != base.Uid || now.Gid != base.Gid ||
		now.Mtim != base.Mtim || now.Ctim != base.Ctim ||
		byName.Dev != base.Dev || byName.Ino != base.Ino {
		return nil, refuse(Modified)
	}
	if l, err := unix.FcntlInt(uintptr(fd), unix.F_GETLEASE, 0); err != nil || l != unix.F_RDLCK {
		return nil, refuse(Modified) // a write open was attempted while the lease was held
	}
	if names, more, err := i.list(); err != nil || more || len(names) != 1 || names[0] != name {
		return nil, refuse(Modified)
	}
	mfd := int(m.Fd())
	if _, err := unix.FcntlInt(uintptr(mfd), unix.F_ADD_SEALS, sealAll); err != nil {
		return nil, refuse(SealFailure)
	}
	if got, err := unix.FcntlInt(uintptr(mfd), unix.F_GET_SEALS, 0); err != nil || got&sealAll != sealAll {
		return nil, refuse(SealFailure)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(m, 0, base.Size)); err != nil {
		return nil, refuse(ReadFailure)
	}
	s := &Snapshot{f: m, size: base.Size}
	h.Sum(s.sum[:0])
	return s, nil
}

// Close removes the inbox's entries and directory without following anything.
// Each call makes a bounded, best-effort pass over the first maxEntries names
// through the retained descriptor: it unlinks every plain entry and removes every
// empty subdirectory it can, and a name it cannot remove does not stop the rest.
// It never descends into a subdirectory.
//
// Close returns nil only when the retained descriptor proves that the original
// directory is unlinked, whoever unlinked it. The result of the removal by
// pathname is not that proof, because a user that can write the inbox's parent
// can move the original away and install another directory at its name, and the
// removal then deletes the replacement. In that case, or if anything remains, or
// the pathname no longer names this directory, Close returns CleanupIncomplete,
// keeps the descriptor, and a later Close retries. A producer that moved the
// original away leaves Close incomplete until that directory is removed or the
// process exits.
//
// The first call also ends the inbox's acceptance of new capture: from then on
// Seal returns closed, even if this call was incomplete.
func (i *Inbox) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.dir == nil || i.closed {
		return nil
	}
	i.closing = true
	if i.gone() { // removed already, by a producer or by an earlier attempt
		return i.release()
	}
	names, incomplete, err := i.list()
	if err != nil {
		return refuse(CleanupIncomplete)
	}
	if i.reorder != nil {
		i.reorder(names)
	}
	dirfd := int(i.dir.Fd())
	for _, n := range names {
		if unix.Unlinkat(dirfd, n, 0) != nil && unix.Unlinkat(dirfd, n, unix.AT_REMOVEDIR) != nil { // an empty subdirectory only
			incomplete = true // keep going: later names may still be removable
		}
	}
	var st unix.Stat_t
	if left, _, err := i.list(); incomplete || err != nil || len(left) != 0 || unix.Lstat(i.path, &st) != nil ||
		uint64(st.Dev) != i.dev || st.Ino != i.ino { //nolint:unconvert // Dev is uint32 on some architectures.
		return refuse(CleanupIncomplete)
	}
	// Linux removes a directory by name, never by descriptor, so the check above
	// and this removal cannot be made one step. If the name was swapped in between,
	// this removes the replacement, and only the proof below decides the result.
	if i.beforeRmdir != nil {
		i.beforeRmdir()
	}
	_ = unix.Rmdir(i.path)
	if !i.gone() {
		return refuse(CleanupIncomplete)
	}
	return i.release()
}

// release records that the original directory is proven gone and drops the
// retained descriptor.
func (i *Inbox) release() error {
	i.closed = true
	_ = i.dir.Close()
	return nil
}

// gone reports whether the retained directory has been unlinked. The kernel
// marks a directory dead only when an rmdir succeeds on it or a rename replaces
// it, and reading a dead directory fails with ENOENT while its link count is
// zero. A directory that was merely moved, or whose name now belongs to another
// directory, is still alive and reads normally. Anything unexpected counts as not
// gone.
func (i *Inbox) gone() bool {
	fd := int(i.dir.Fd())
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Nlink != 0 {
		return false
	}
	nfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(nfd) }()
	_, err = unix.ReadDirent(nfd, make([]byte, 1024))
	return errors.Is(err, unix.ENOENT)
}

// Snapshot holds sealed, immutable bytes in an anonymous memory file. No path and
// no descriptor leave this type, so nothing outside it can write them. The bytes
// are a copy taken when no file description open for writing existed on the
// source inode; the hash is computed from the sealed copy, not from the source or
// from anything the producer claimed.
type Snapshot struct {
	mu   sync.Mutex
	f    *os.File
	size int64
	sum  [sha256.Size]byte
}

func (s *Snapshot) Size() int64 {
	if s == nil {
		return 0
	}
	return s.size
}

// SHA256 is the digest of the sealed bytes. An invalid Snapshot returns zeros.
func (s *Snapshot) SHA256() [sha256.Size]byte {
	if s == nil {
		return [sha256.Size]byte{}
	}
	return s.sum
}

// ReadAt reads the sealed bytes. It returns a Closed refusal after Close. Its
// only other errors are io.EOF, with the usual io.ReaderAt meaning, and a
// ReadFailure refusal; no system error is passed through.
func (s *Snapshot) ReadAt(p []byte, off int64) (int, error) {
	if s == nil {
		return 0, refuse(Closed)
	}
	s.mu.Lock()
	f := s.f
	s.mu.Unlock()
	if f == nil {
		return 0, refuse(Closed)
	}
	n, err := io.NewSectionReader(f, 0, s.size).ReadAt(p, off)
	if err != nil && err != io.EOF {
		return n, refuse(ReadFailure)
	}
	return n, err
}

// Close releases the sealed bytes. It is idempotent. If the kernel reports an
// error closing the descriptor it returns a CloseFailure refusal and does not
// retain the descriptor, so a second Close returns nil.
func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	if err != nil {
		return refuse(CloseFailure)
	}
	return nil
}
