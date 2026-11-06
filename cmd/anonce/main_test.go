// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShutdownHTTPClosesActiveConnectionsOnDeadline(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	defer h.Close()
	defer close(release)

	requestDone := make(chan error, 1)
	go func() {
		response, err := h.Client().Get(h.URL)
		if err == nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}

	// An expired deadline makes the shutdown failure deterministic without sleeping.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := shutdownHTTP(ctx, h.Config); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("forced close did not cancel the active request")
	}
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("active request unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forced close did not terminate the client request")
	}
}

func TestShutdownHTTPGraceful(t *testing.T) {
	h := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownHTTP(ctx, h.Config); err != nil {
		t.Fatalf("shutdown error = %v", err)
	}
}
