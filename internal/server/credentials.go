// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"encoding/json"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http"
	"strings"
)

func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	action := map[string]string{"password": "password-change", "recovery": "recovery-rotate", "reset": "credential-reset"}[kind]
	// Distinct payload types keep unknown-field rejection meaningful per operation.
	var req, expected, password, recovery, salt string
	var kd kdf
	var pw, rw wrapper
	var writes []vaultWrite
	var x *verified
	var e error
	switch kind {
	case "password":
		var p struct {
			Request  string  `json:"request_id"`
			Expected string  `json:"expected_epoch"`
			KDF      kdf     `json:"password_kdf"`
			Password string  `json:"password_auth_public_key"`
			Wrap     wrapper `json:"password_wrap"`
		}
		x, e = s.verify(r, action, &p, false)
		req, expected, password, kd, pw = p.Request, p.Expected, p.Password, p.KDF, p.Wrap
	case "recovery":
		var p struct {
			Request  string  `json:"request_id"`
			Expected string  `json:"expected_epoch"`
			Salt     string  `json:"recovery_salt"`
			Recovery string  `json:"recovery_auth_public_key"`
			Wrap     wrapper `json:"recovery_wrap"`
		}
		x, e = s.verify(r, action, &p, false)
		req, expected, recovery, salt, rw = p.Request, p.Expected, p.Recovery, p.Salt, p.Wrap
	case "reset":
		var p struct {
			Request  string       `json:"request_id"`
			Expected string       `json:"expected_epoch"`
			KDF      kdf          `json:"password_kdf"`
			Password string       `json:"password_auth_public_key"`
			PW       wrapper      `json:"password_wrap"`
			Salt     string       `json:"recovery_salt"`
			Recovery string       `json:"recovery_auth_public_key"`
			RW       wrapper      `json:"recovery_wrap"`
			Writes   []vaultWrite `json:"vault_writes"`
		}
		x, e = s.verify(r, action, &p, false)
		req, expected, password, recovery, salt, kd, pw, rw, writes = p.Request, p.Expected, p.Password, p.Recovery, p.Salt, p.KDF, p.PW, p.RW, p.Writes
	}
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = protocol.Decode(req, 16); e != nil {
		fail(w, bad("invalid_request_id"))
		return
	}
	epoch, e := decimal(expected)
	if e != nil || epoch != x.Session.Epoch {
		fail(w, problem{409, "epoch_conflict"})
		return
	}
	oldKey, oldSig := x.Session.Password, x.Proof.Password
	if kind == "reset" {
		oldKey, oldSig = x.Session.Recovery, x.Proof.Recovery
	}
	if !checkSig(oldKey, oldSig, x.Transcript) {
		fail(w, problem{403, "invalid_proof"})
		return
	}
	var pk, rk []byte
	if kind != "recovery" {
		pk, e = protocol.Decode(password, 32)
		if e != nil || !kd.valid() || !pw.valid() || !checkSig(pk, x.Proof.NewPassword, x.Transcript) {
			fail(w, bad("invalid_new_password"))
			return
		}
	}
	if kind != "password" {
		rk, e = protocol.Decode(recovery, 32)
		_, se := protocol.Decode(salt, 32)
		if e != nil || se != nil || !rw.valid() || !checkSig(rk, x.Proof.NewRecovery, x.Transcript) {
			fail(w, bad("invalid_new_recovery"))
			return
		}
	}
	tx, e := s.member.Begin(r.Context())
	if e != nil {
		fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	if e = consumeChallenge(r, tx, x); e != nil {
		fail(w, e)
		return
	}
	var current int64
	var wraps map[string]any
	if e = tx.QueryRow(r.Context(), "SELECT epoch,vault FROM member.accounts WHERE id=$1 FOR UPDATE", x.Session.Account).Scan(&current, &wraps); e != nil {
		fail(w, e)
		return
	}
	if current != epoch {
		fail(w, problem{409, "epoch_conflict"})
		return
	}
	if kind != "recovery" {
		wraps["password_wrap"] = pw
		b, _ := json.Marshal(kd)
		_, e = tx.Exec(r.Context(), "UPDATE member.accounts SET password_public=$2,password_kdf=$3 WHERE id=$1", x.Session.Account, pk, b)
	}
	if e == nil && kind != "password" {
		wraps["recovery_wrap"] = rw
		_, e = tx.Exec(r.Context(), "UPDATE member.accounts SET recovery_public=$2,recovery_salt=$3 WHERE id=$1", x.Session.Account, rk, salt)
	}
	if e == nil {
		for _, v := range writes {
			if e = saveObject(r, tx, x.Session.Account, v); e != nil {
				break
			}
		}
	}
	if e == nil {
		b, _ := json.Marshal(wraps)
		_, e = tx.Exec(r.Context(), "UPDATE member.accounts SET epoch=epoch+1,vault=$2 WHERE id=$1", x.Session.Account, b)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "DELETE FROM member.sessions WHERE account_id=$1", x.Session.Account)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "DELETE FROM member.challenges WHERE account_id=$1", x.Session.Account)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, map[string]string{"credential_epoch": format(epoch + 1)})
}
