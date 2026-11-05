// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"math/big"
	"time"
)

func (s *Server) crypt(label string, b []byte, open bool) ([]byte, error) {
	k, e := hkdf.Key(sha256.New, s.master, s.deployment, "anonce/server/"+label, 32)
	if e != nil {
		return nil, e
	}
	a, e := chacha20poly1305.New(k)
	if e != nil {
		return nil, e
	}
	aad := protocol.E("server-key", s.deployment, []byte(label))
	if open {
		if len(b) < a.NonceSize() {
			return nil, errors.New("invalid encrypted key")
		}
		return a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], aad)
	}
	n := protocol.Random(a.NonceSize())
	return a.Seal(n, n, b, aad), nil
}
func (s *Server) initKeys(ctx context.Context) error {
	tx, e := s.member.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(728619470121)"); e != nil {
		return e
	}
	load := func(name string, gen func() ([]byte, error)) ([]byte, error) {
		var b []byte
		e := tx.QueryRow(ctx, "SELECT value FROM member.settings WHERE name=$1", name).Scan(&b)
		if e == nil {
			return b, nil
		}
		b, e = gen()
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, "INSERT INTO member.settings VALUES($1,$2)", name, b)
		return b, e
	}
	s.deployment, e = load("deployment", func() ([]byte, error) { return protocol.Random(32), nil })
	if e != nil {
		return e
	}
	for _, v := range []struct {
		name string
		dst  *ed25519.PrivateKey
	}{{"ca", &s.ca}, {"receipt", &s.receipt}} {
		b, e := load(v.name, func() ([]byte, error) {
			_, k, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return nil, e
			}
			return s.crypt(v.name, k, false)
		})
		if e != nil {
			return e
		}
		b, e = s.crypt(v.name, b, true)
		if e != nil || len(b) != ed25519.PrivateKeySize {
			return errors.New("cannot decrypt signing key")
		}
		*v.dst = ed25519.PrivateKey(b)
	}
	s.caDER, e = load("ca-certificate", func() ([]byte, error) {
		t := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(protocol.Random(16)), Subject: pkix.Name{CommonName: "Anonce membership CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		return x509.CreateCertificate(rand.Reader, t, t, s.ca.Public(), s.ca)
	})
	if e != nil {
		return e
	}
	s.receiptID = protocol.Hash(s.receipt.Public().(ed25519.PublicKey))
	return tx.Commit(ctx)
}
func pemCert(b []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
}
