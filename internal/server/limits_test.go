// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func TestLimitsBeforeIO(t *testing.T) {
	l := protocol.Defaults()
	l.MaxQuestions++
	if _, err := New(t.Context(), Config{Limits: l}); err == nil || err.Error() != "max_questions must be between 1 and 500" {
		t.Fatalf("validation before origin/key/database IO: %v", err)
	}
}

func TestPublicLimits(t *testing.T) {
	l := protocol.Defaults()
	l.MaxQuestions = 12
	s := &Server{cfg: Config{Limits: l}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/public/config", nil))
	var got struct {
		Limits map[string]int `json:"limits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(got.Limits) != 10 || got.Limits["max_questions"] != 12 || got.Limits["pending_padding_bytes"] != 1048576 {
		t.Fatalf("public limits: %d %s", w.Code, w.Body.Bytes())
	}
}

func TestConfiguredContentBoundary(t *testing.T) {
	l := protocol.Defaults()
	l.MaxReviewBytes = 1024
	l.MaxDescriptionBytes = 1
	for _, size := range []int{1040, 1041} {
		c := fakeContent()
		c.Ciphertext = protocol.B64(make([]byte, size))
		if c.validWithLimits(l) != (size == 1040) {
			t.Fatalf("size %d", size)
		}
	}
}

func TestPaddedVaultBoundary(t *testing.T) {
	for _, size := range []int{protocol.PendingPaddingBytes + 16, protocol.PendingPaddingBytes + 17} {
		o := fakeObject()
		o.Ciphertext = protocol.B64(make([]byte, size))
		if o.valid(0) != (size == protocol.PendingPaddingBytes+16) {
			t.Fatalf("vault ciphertext size %d", size)
		}
	}
}

func TestPublicBodyBoundary(t *testing.T) {
	for _, size := range []int{protocol.AnonymousRequestBytes, protocol.AnonymousRequestBytes + 1} {
		s := &Server{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/anon/receipts/lookup", bytes.NewReader(bytes.Repeat([]byte(" "), size)))
		r.Header.Set("Content-Type", "application/json")
		s.Handler().ServeHTTP(w, r)
		if size > protocol.AnonymousRequestBytes && w.Code != 413 {
			t.Fatalf("oversized: %d %s", w.Code, w.Body.Bytes())
		}
		if size == protocol.AnonymousRequestBytes && w.Code == 413 {
			t.Fatal("maximum rejected")
		}
	}
}
