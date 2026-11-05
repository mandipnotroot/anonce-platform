// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

const maxMasterKeyFileSize = 4096

var errMasterKeyFile = errors.New("invalid master key file")

func readMasterKey(path string) ([]byte, error) {
	// Linux deployment uses O_NOFOLLOW to reject a final-component symlink
	// atomically. O_NONBLOCK prevents a FIFO from blocking before fstat.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errMasterKeyFile
	}
	f := os.NewFile(uintptr(fd), "master key")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errMasterKeyFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return nil, errMasterKeyFile
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMasterKeyFileSize+1))
	if err != nil || len(b) > maxMasterKeyFileSize {
		return nil, errMasterKeyFile
	}
	master, err := protocol.Decode(strings.TrimSpace(string(b)), 32)
	if err != nil {
		return nil, errMasterKeyFile
	}
	return master, nil
}
