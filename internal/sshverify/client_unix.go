//go:build unix

package sshverify

import (
	"errors"
	"os"
	"path/filepath"
)

// checkClientPermissions refuses an ssh client, or the directory holding it,
// that a user other than the owner can write. Permission bits mean this only
// on Unix; other platforms have no such check, see client_other.go.
func checkClientPermissions(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		info, err := os.Stat(p)
		if err != nil {
			return errors.New("the ssh client could not be checked")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("the ssh client or its directory is writable by other users: " + p)
		}
	}
	return nil
}
