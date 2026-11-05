// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"github.com/mandipnotroot/anonce-platform/internal/server"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		log.Print("anonce failed: ", e)
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, e := server.New(ctx, server.Config{DatabaseURL: os.Getenv("DATABASE_URL"), AnonymousURL: os.Getenv("ANON_DATABASE_URL"), Origin: os.Getenv("ANONCE_ORIGIN"), KeyFile: os.Getenv("ANONCE_KEY_FILE"), WebDir: os.Getenv("ANONCE_WEB_DIR"), SourceURL: os.Getenv("ANONCE_SOURCE_URL"), ReceiptTrustFile: os.Getenv("ANONCE_RECEIPT_TRUST_FILE")})
	if e != nil {
		return e
	}
	defer s.Close()
	addr := os.Getenv("ANONCE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	h := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- h.ListenAndServe() }()
	select {
	case e = <-done:
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return h.Shutdown(c)
	}
}
