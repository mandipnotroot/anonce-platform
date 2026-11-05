// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func receiptTrustServer() *Server {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	return &Server{deployment: make([]byte, 32), receipt: key, receiptID: protocol.Hash(key.Public().(ed25519.PublicKey))}
}

func TestReceiptTrustCurrentOnlyConfig(t *testing.T) {
	s := receiptTrustServer()
	if err := s.initReceiptTrust(); err != nil {
		t.Fatal(err)
	}
	if s.receiptTrust.V != 1 {
		t.Fatalf("trust version=%d want 1", s.receiptTrust.V)
	}
	if err := s.receiptTrust.Validate(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/public/config", nil))
	var config map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || string(config["v"]) != "2" || config["receipt_public_key"] != nil {
		t.Fatalf("invalid config: %s", w.Body.Bytes())
	}
	var keys []protocol.ReceiptTrustKey
	if err := json.Unmarshal(config["receipt_keys"], &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != s.receiptTrust.ReceiptKeys[0] {
		t.Fatal("wrong current keyring")
	}
}

func TestReceiptTrustFile(t *testing.T) {
	base := receiptTrustServer()
	if err := base.initReceiptTrust(); err != nil {
		t.Fatal(err)
	}
	historical := ed25519.NewKeyFromSeed(bytesOf(1, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	valid := base.receiptTrust
	valid.ReceiptKeys = append(valid.ReceiptKeys, protocol.ReceiptTrustKey{ReceiptKeyID: protocol.B64(protocol.Hash(historical)), ReceiptPublicKey: protocol.B64(historical)})
	encode := func(v protocol.ReceiptTrust) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	wrongDeployment := valid
	wrongDeployment.DeploymentID = protocol.B64(bytesOf(1, 32))
	wrongCurrent := valid
	wrongCurrent.ReceiptKeyID = valid.ReceiptKeys[1].ReceiptKeyID
	wrongVersion := valid
	wrongVersion.V = 2
	for _, tc := range []struct {
		name      string
		data      []byte
		mode      os.FileMode
		wantError bool
	}{
		{"historical", encode(valid), 0600, false},
		{"deployment", encode(wrongDeployment), 0600, true},
		{"current", encode(wrongCurrent), 0600, true},
		{"unknown", []byte(`{"v":1,"unknown":true}`), 0600, true},
		{"version", encode(wrongVersion), 0600, true},
		{"oversized", make([]byte, maxReceiptTrustSize+1), 0600, true},
		{"writable", encode(valid), 0666, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := receiptTrustServer()
			s.cfg.ReceiptTrustFile = filepath.Join(t.TempDir(), "trust.json")
			if err := os.WriteFile(s.cfg.ReceiptTrustFile, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(s.cfg.ReceiptTrustFile, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := s.initReceiptTrust(); (err != nil) != tc.wantError {
				t.Fatalf("initReceiptTrust error=%v wantError=%v", err, tc.wantError)
			}
			if !tc.wantError && len(s.receiptTrust.ReceiptKeys) != 2 {
				t.Fatal("historical key missing")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		s := receiptTrustServer()
		s.cfg.ReceiptTrustFile = filepath.Join(t.TempDir(), "missing")
		if s.initReceiptTrust() == nil {
			t.Fatal("accepted missing file")
		}
	})
	t.Run("directory", func(t *testing.T) {
		s := receiptTrustServer()
		s.cfg.ReceiptTrustFile = t.TempDir()
		if s.initReceiptTrust() == nil {
			t.Fatal("accepted directory")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		s := receiptTrustServer()
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, encode(valid), 0600); err != nil {
			t.Fatal(err)
		}
		s.cfg.ReceiptTrustFile = filepath.Join(dir, "trust.json")
		if err := os.Symlink(target, s.cfg.ReceiptTrustFile); err != nil {
			t.Fatal(err)
		}
		if s.initReceiptTrust() == nil {
			t.Fatal("accepted symlink")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		s := receiptTrustServer()
		s.cfg.ReceiptTrustFile = filepath.Join(t.TempDir(), "trust.fifo")
		if err := syscall.Mkfifo(s.cfg.ReceiptTrustFile, 0600); err != nil {
			t.Fatal(err)
		}
		if s.initReceiptTrust() == nil {
			t.Fatal("accepted FIFO")
		}
	})
}

func bytesOf(value byte, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = value
	}
	return b
}
