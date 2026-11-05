// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func masterKeyFixture(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadMasterKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	t.Run("owner only", func(t *testing.T) {
		for _, mode := range []os.FileMode{0400, 0600} {
			path := masterKeyFixture(t, "\n"+encoded+"\n", mode)
			got, err := readMasterKey(path)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("readMasterKey: unexpected result, error %v", err)
			}
		}
	})
	for _, tc := range []struct {
		name     string
		contents string
		mode     os.FileMode
	}{
		{"group readable", encoded, 0640},
		{"world readable", encoded, 0604},
		{"group executable", encoded, 0610},
		{"world writable", encoded, 0602},
		{"oversized", encoded + strings.Repeat(" ", maxMasterKeyFileSize), 0600},
		{"invalid encoding", "not a key", 0600},
		{"wrong length", base64.RawURLEncoding.EncodeToString(key[:31]), 0600},
		{"empty", "", 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertMasterKeyRejected(t, masterKeyFixture(t, tc.contents, tc.mode))
		})
	}
	t.Run("directory", func(t *testing.T) {
		assertMasterKeyRejected(t, t.TempDir())
	})
	t.Run("symlink", func(t *testing.T) {
		target := masterKeyFixture(t, encoded, 0600)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		assertMasterKeyRejected(t, link)
	})
	t.Run("missing", func(t *testing.T) {
		assertMasterKeyRejected(t, filepath.Join(t.TempDir(), "missing"))
	})
	t.Run("wrong owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing a synthetic fixture owner requires root; no privilege escalation attempted")
		}
		path := masterKeyFixture(t, encoded, 0600)
		if err := os.Chown(path, 65534, -1); err != nil {
			t.Skipf("cannot change synthetic fixture owner: %v", err)
		}
		assertMasterKeyRejected(t, path)
	})
}

func assertMasterKeyRejected(t *testing.T, path string) {
	t.Helper()
	key, err := readMasterKey(path)
	if err != errMasterKeyFile || key != nil {
		t.Fatalf("expected generic master key failure, got error %v", err)
	}
}
