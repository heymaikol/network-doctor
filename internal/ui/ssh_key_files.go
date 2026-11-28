package ui

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The picker considers only private-key file headers. It reads at most the first
// 64 bytes of each file and never displays or stores any part of a private key.
var privateKeyHeaders = [][]byte{
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
}

const maxSSHKeyScanEntries = 4096

// scanSSHPrivateKeys lists candidate private keys beneath sshDir, including
// subdirectories. Files and directories reached through symlinks are ignored.
// An unreadable or non-key file is not offered as a credential. The bound
// refuses an abnormally large tree instead of silently omitting some keys.
func scanSSHPrivateKeys(ctx context.Context, sshDir string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(sshDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	var keys []string
	visited := 0
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > maxSSHKeyScanEntries {
			return errors.New("the SSH directory has too many entries to list safely")
		}
		if !d.Type().IsRegular() || strings.HasSuffix(path, ".pub") {
			return nil
		}
		// A regular entry can be replaced with a FIFO between the directory
		// listing and the open. The Unix opener is nonblocking for that case.
		// All opens remain rooted in ~/.ssh if the entry changes to a symlink.
		f, err := openSSHKeyCandidate(root, path)
		if err != nil {
			return nil
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			return nil
		}
		var head [64]byte
		n, _ := f.Read(head[:])
		_ = f.Close()
		for _, prefix := range privateKeyHeaders {
			if bytes.HasPrefix(head[:n], prefix) {
				keys = append(keys, filepath.Join(sshDir, filepath.FromSlash(path)))
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func userSSHPrivateKeys(ctx context.Context) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return scanSSHPrivateKeys(ctx, filepath.Join(home, ".ssh"))
}

// shortSSHKeyPath names a key for the chooser without displaying its full home
// directory. The full absolute path remains in the attempt sent to Verify.
func shortSSHKeyPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(filepath.Join(home, ".ssh"), path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return "~/.ssh/" + filepath.ToSlash(rel)
}
