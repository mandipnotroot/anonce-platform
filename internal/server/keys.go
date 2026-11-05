// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
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
	"io"
	"math/big"
	"os"
	"syscall"
	"time"
)

const maxReceiptTrustSize = 1024 * 1024

func (s *Server) initReceiptTrust() error {
	pub := s.receipt.Public().(ed25519.PublicKey)
	trust := protocol.ReceiptTrust{V: 1, DeploymentID: protocol.B64(s.deployment), ReceiptKeyID: protocol.B64(s.receiptID), ReceiptKeys: []protocol.ReceiptTrustKey{{ReceiptKeyID: protocol.B64(s.receiptID), ReceiptPublicKey: protocol.B64(pub)}}}
	if s.cfg.ReceiptTrustFile != "" {
		fd, err := syscall.Open(s.cfg.ReceiptTrustFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), s.cfg.ReceiptTrustFile)
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > maxReceiptTrustSize {
			return errors.New("receipt trust file must be a bounded regular file without group or world write access")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
			return errors.New("receipt trust file must be owned by root or the service user")
		}
		b, err := io.ReadAll(io.LimitReader(f, maxReceiptTrustSize+1))
		if err != nil {
			return err
		}
		if len(b) > maxReceiptTrustSize {
			return errors.New("receipt trust file too large")
		}
		trust, err = protocol.ParseReceiptTrust(b)
		if err != nil {
			return err
		}
	}
	if err := trust.Validate(); err != nil {
		return err
	}
	current, err := trust.CurrentPublicKey()
	if err != nil {
		return err
	}
	if trust.DeploymentID != protocol.B64(s.deployment) || trust.ReceiptKeyID != protocol.B64(s.receiptID) || !bytes.Equal(current, pub) {
		return errors.New("receipt trust does not match initialized deployment and signing key")
	}
	s.receiptTrust = trust
	return nil
}

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
