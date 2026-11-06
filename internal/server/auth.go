// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"io"
	"net/http"
	"strconv"
	"time"
)

const cookieName = "__Secure-anonce_session"

func ioBody(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }

type session struct {
	Account, Scope, CSRF, Email          string
	Epoch                                int64
	Hash, Password, Recovery, Membership []byte
}

func (s *Server) session(r *http.Request) (*session, error) {
	c, e := r.Cookie(cookieName)
	if e != nil {
		return nil, problem{401, "unauthenticated"}
	}
	b, e := protocol.Decode(c.Value, 32)
	if e != nil {
		return nil, problem{401, "unauthenticated"}
	}
	a := &session{Hash: protocol.Hash(b)}
	e = s.member.QueryRow(r.Context(), "SELECT a.id,s.scope,s.csrf,a.email,a.epoch,a.password_public,a.recovery_public,a.membership_public FROM member.sessions s JOIN member.accounts a ON a.id=s.account_id AND a.epoch=s.epoch WHERE s.id_hash=$1 AND s.expires_at>now()", a.Hash).Scan(&a.Account, &a.Scope, &a.CSRF, &a.Email, &a.Epoch, &a.Password, &a.Recovery, &a.Membership)
	if e != nil {
		return nil, problem{401, "unauthenticated"}
	}
	return a, nil
}
func sessionView(a *session) map[string]any {
	return map[string]any{"account_id": a.Account, "scope": a.Scope, "credential_epoch": strconv.FormatInt(a.Epoch, 10), "csrf_token": a.CSRF, "email": a.Email}
}

type proof struct {
	Challenge   string `json:"challenge_id"`
	Password    string `json:"password_sig,omitempty"`
	Recovery    string `json:"recovery_sig,omitempty"`
	Membership  string `json:"membership_sig,omitempty"`
	NewPassword string `json:"new_password_sig,omitempty"`
	NewRecovery string `json:"new_recovery_sig,omitempty"`
}
type envelope struct {
	Payload string `json:"payload"`
	Proof   proof  `json:"proof"`
}
type verified struct {
	Payload    []byte
	Proof      proof
	Transcript []byte
	Session    *session
	Account    string
	Epoch      int64
}

func (s *Server) verify(r *http.Request, action string, v any, pre bool) (*verified, error) {
	var env envelope
	if e := body(r, &env); e != nil {
		return nil, e
	}
	b, e := protocol.Decode(env.Payload, -1)
	if e != nil || len(b) > 1536*1024 {
		return nil, bad("invalid_payload")
	}
	if e = protocol.StrictJSON(b, v); e != nil {
		return nil, bad("invalid_payload")
	}
	x := &verified{Payload: b, Proof: env.Proof}
	if !pre {
		x.Session, e = s.session(r)
		if e != nil {
			return nil, e
		}
		if r.Header.Get("X-CSRF-Token") != x.Session.CSRF {
			return nil, problem{403, "csrf_required"}
		}
		if x.Session.Scope == "recovery" && action != "vault-write" && action != "credential-reset" {
			return nil, problem{403, "recovery_scope"}
		}
	}
	var account, storedAction string
	var epoch, expires int64
	var hash, nonce, sessionHash []byte
	// Consumption is transactional with the protected write, never during proof verification.
	e = s.member.QueryRow(r.Context(), "SELECT account_id,action,epoch,payload_hash,nonce,expires,session_hash FROM member.challenges WHERE id=$1", env.Proof.Challenge).Scan(&account, &storedAction, &epoch, &hash, &nonce, &expires, &sessionHash)
	if e != nil || storedAction != action || expires < time.Now().Unix() || !bytes.Equal(hash, protocol.Hash(b)) {
		return nil, problem{403, "invalid_challenge"}
	}
	if !pre && (account != x.Session.Account || epoch != x.Session.Epoch || !bytes.Equal(sessionHash, x.Session.Hash)) {
		return nil, problem{403, "invalid_challenge"}
	}
	aid, e := protocol.Decode(account, 16)
	if e != nil {
		return nil, bad("invalid_account")
	}
	cid, e := protocol.Decode(env.Proof.Challenge, 16)
	if e != nil {
		return nil, bad("invalid_challenge")
	}
	x.Transcript = protocol.E("challenge", s.deployment, []byte(s.cfg.Origin), aid, cid, []byte(action), protocol.U64(uint64(epoch)), hash, nonce, protocol.U64(uint64(expires)))
	x.Account, x.Epoch = account, epoch
	if !pre && action != "password-change" && action != "recovery-rotate" && action != "credential-reset" {
		key, signature := x.Session.Membership, x.Proof.Membership
		if x.Session.Scope == "recovery" {
			key, signature = x.Session.Recovery, x.Proof.Recovery
		}
		if !checkSig(key, signature, x.Transcript) {
			return nil, problem{403, "invalid_proof"}
		}
	}
	return x, nil
}
func checkSig(key []byte, sig string, msg []byte) bool {
	b, e := protocol.Decode(sig, 64)
	return e == nil && len(key) == 32 && ed25519.Verify(ed25519.PublicKey(key), msg, b)
}

type kdf struct {
	V           int    `json:"v"`
	Salt        string `json:"salt"`
	Memory      int    `json:"memory_kib"`
	Iterations  int    `json:"iterations"`
	Parallelism int    `json:"parallelism"`
	Length      int    `json:"length"`
}

func (k kdf) valid() bool {
	_, e := protocol.Decode(k.Salt, 16)
	return e == nil && k.V == 19 && k.Memory == 65536 && k.Iterations == 3 && k.Parallelism == 1 && k.Length == 32
}

type wrapper struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (v wrapper) valid() bool {
	_, a := protocol.Decode(v.ID, 16)
	_, b := protocol.Decode(v.Nonce, 12)
	c, e := protocol.Decode(v.Ciphertext, -1)
	return v.V == 1 && a == nil && b == nil && e == nil && len(c) >= 16 && len(c) <= 1024
}

type object struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Revision   string `json:"revision"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (v object) valid(expected int64) bool {
	_, a := protocol.Decode(v.ID, 16)
	_, b := protocol.Decode(v.Nonce, 12)
	c, e := protocol.Decode(v.Ciphertext, -1)
	return v.V == 1 && a == nil && b == nil && e == nil && len(c) >= 16 && len(c) <= 1048576 && v.Revision == strconv.FormatInt(expected+1, 10)
}
func decimal(s string) (int64, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != s {
		return 0, bad("invalid_decimal")
	}
	return n, nil
}

type vaultWrite struct {
	Expected string `json:"expected_revision"`
	Object   object `json:"object"`
}

func saveObject(r *http.Request, tx pgx.Tx, account string, v vaultWrite) error {
	n, e := decimal(v.Expected)
	if e != nil || !v.Object.valid(n) {
		return bad("invalid_vault_object")
	}
	b, _ := json.Marshal(v.Object)
	if n == 0 {
		_, e = tx.Exec(r.Context(), "INSERT INTO member.vault_objects VALUES($1,$2,1,$3)", account, v.Object.ID, b)
		return e
	}
	tag, e := tx.Exec(r.Context(), "UPDATE member.vault_objects SET revision=revision+1,object=$1 WHERE account_id=$2 AND id=$3 AND revision=$4", b, account, v.Object.ID, n)
	if e == nil && tag.RowsAffected() != 1 {
		return problem{409, "revision_conflict"}
	}
	return e
}
func (s *Server) authRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/member/auth/params", s.params)
	m.HandleFunc("POST /api/member/challenges", s.challenge)
	m.HandleFunc("POST /api/member/register", s.register)
	m.HandleFunc("POST /api/member/session", s.login)
	m.HandleFunc("DELETE /api/member/session", s.logout)
	m.HandleFunc("GET /api/member/me", s.me)
	m.HandleFunc("GET /api/member/vault", s.vault)
	m.HandleFunc("PUT /api/member/vault/objects/{id}", s.putObject)
	for _, kind := range []string{"password", "recovery", "reset"} {
		m.HandleFunc("POST /api/member/credentials/"+kind, s.credentials)
	}
}
func (s *Server) params(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Email string `json:"email"`
	}
	if e := body(r, &p); e != nil {
		fail(w, e)
		return
	}
	email, e := normalizeEmail(p.Email)
	if e != nil {
		fail(w, e)
		return
	}
	var id, salt string
	var epoch int64
	var kd json.RawMessage
	if e := s.member.QueryRow(r.Context(), "SELECT id,epoch,password_kdf,recovery_salt FROM member.accounts WHERE email=$1", email).Scan(&id, &epoch, &kd, &salt); e != nil {
		fail(w, problem{404, "not_found"})
		return
	}
	write(w, 200, map[string]any{"account_id": id, "credential_epoch": strconv.FormatInt(epoch, 10), "password_kdf": kd, "recovery_salt": salt})
}
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Account string `json:"account_id"`
		Action  string `json:"action"`
		Hash    string `json:"payload_hash"`
	}
	if e := body(r, &p); e != nil {
		fail(w, e)
		return
	}
	if _, e := protocol.Decode(p.Account, 16); e != nil {
		fail(w, bad("invalid_account"))
		return
	}
	h, e := protocol.Decode(p.Hash, 32)
	if e != nil {
		fail(w, bad("invalid_hash"))
		return
	}
	pre := p.Action == "register" || p.Action == "login-password" || p.Action == "login-recovery"
	var epoch int64
	var sessionHash []byte
	if !pre {
		a, e := s.session(r)
		if e != nil {
			fail(w, e)
			return
		}
		if a.Account != p.Account || r.Header.Get("X-CSRF-Token") != a.CSRF {
			fail(w, problem{403, "forbidden"})
			return
		}
		epoch, sessionHash = a.Epoch, a.Hash
	} else if p.Action != "register" {
		if e = s.member.QueryRow(r.Context(), "SELECT epoch FROM member.accounts WHERE id=$1", p.Account).Scan(&epoch); e != nil {
			fail(w, problem{404, "not_found"})
			return
		}
	}
	if len(p.Action) > 64 {
		fail(w, bad("invalid_action"))
		return
	}
	id, nonce, expires := protocol.ID(), protocol.Random(32), time.Now().Add(5*time.Minute).Unix()
	_, e = s.member.Exec(r.Context(), "INSERT INTO member.challenges(id,account_id,action,epoch,payload_hash,nonce,expires,session_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", id, p.Account, p.Action, epoch, h, nonce, expires, sessionHash)
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, map[string]string{"challenge_id": id, "account_id": p.Account, "action": p.Action, "payload_hash": p.Hash, "nonce": protocol.B64(nonce), "credential_epoch": strconv.FormatInt(epoch, 10), "expires_at": strconv.FormatInt(expires, 10)})
}

type registration struct {
	Request             string   `json:"request_id"`
	Account             string   `json:"account_id"`
	Email               string   `json:"email"`
	KDF                 kdf      `json:"password_kdf"`
	Password            string   `json:"password_auth_public_key"`
	RecoverySalt        string   `json:"recovery_salt"`
	Recovery            string   `json:"recovery_auth_public_key"`
	PasswordWrap        wrapper  `json:"password_wrap"`
	RecoveryWrap        wrapper  `json:"recovery_wrap"`
	Membership          string   `json:"membership_public_key"`
	Encryption          string   `json:"encryption_public_key"`
	EncryptionSignature string   `json:"encryption_key_signature"`
	Objects             []object `json:"vault_objects"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var p registration
	x, e := s.verify(r, "register", &p, true)
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = protocol.Decode(p.Request, 16); e != nil || len(p.Objects) > 32 {
		fail(w, bad("invalid_registration"))
		return
	}
	email, emailErr := normalizeEmail(p.Email)
	p.Email = email
	pw, a := protocol.Decode(p.Password, 32)
	re, b := protocol.Decode(p.Recovery, 32)
	mp, c := protocol.Decode(p.Membership, 32)
	ep, bindingErr := s.registrationEncryption(p, mp)
	if bindingErr != nil {
		fail(w, bindingErr)
		return
	}
	_, d := protocol.Decode(p.RecoverySalt, 32)
	_, f := protocol.Decode(p.Account, 16)
	if a != nil || b != nil || c != nil || d != nil || f != nil || !p.KDF.valid() || !p.PasswordWrap.valid() || !p.RecoveryWrap.valid() || emailErr != nil || !checkSig(pw, x.Proof.Password, x.Transcript) || !checkSig(re, x.Proof.Recovery, x.Transcript) || !checkSig(mp, x.Proof.Membership, x.Transcript) {
		fail(w, bad("invalid_registration"))
		return
	}
	if x.Account != p.Account || x.Epoch != 0 {
		fail(w, bad("account_mismatch"))
		return
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
	kd, _ := json.Marshal(p.KDF)
	wraps, _ := json.Marshal(map[string]any{"password_wrap": p.PasswordWrap, "recovery_wrap": p.RecoveryWrap})
	_, e = tx.Exec(r.Context(), "INSERT INTO member.accounts(id,email,password_public,recovery_public,membership_public,password_kdf,recovery_salt,vault,encryption_public,encryption_key_signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", p.Account, p.Email, pw, re, mp, kd, p.RecoverySalt, wraps, ep, mustDecode(p.EncryptionSignature))
	if e == nil {
		for _, o := range p.Objects {
			if e = saveObject(r, tx, p.Account, vaultWrite{"0", o}); e != nil {
				break
			}
		}
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 201, map[string]string{"account_id": p.Account, "credential_epoch": "1"})
}
func mustDecode(s string) []byte { b, _ := protocol.Decode(s, -1); return b }

// The account field is the third length-prefixed field in the challenge transcript.
func (x *verified) TranscriptAccount(s *Server) []byte {
	offset := 7 + 2 + len("challenge") + 2
	for i := 0; i < 2; i++ {
		n := int(x.Transcript[offset])<<24 | int(x.Transcript[offset+1])<<16 | int(x.Transcript[offset+2])<<8 | int(x.Transcript[offset+3])
		offset += 4 + n
	}
	return x.Transcript[offset+4 : offset+20]
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var env envelope
	if e := body(r, &env); e != nil {
		fail(w, e)
		return
	}
	b, e := protocol.Decode(env.Payload, -1)
	if e != nil {
		fail(w, bad("invalid_payload"))
		return
	}
	var p struct {
		Request string `json:"request_id"`
		Account string `json:"account_id"`
		Method  string `json:"method"`
	}
	if e = protocol.StrictJSON(b, &p); e != nil || (p.Method != "login-password" && p.Method != "login-recovery") {
		fail(w, bad("invalid_login"))
		return
	}
	raw, _ := json.Marshal(env)
	r.Body = ioBody(raw)
	x, e := s.verify(r, p.Method, &p, true)
	if e != nil {
		fail(w, e)
		return
	}
	a := &session{Account: p.Account}
	if e = s.member.QueryRow(r.Context(), "SELECT epoch,password_public,recovery_public,email FROM member.accounts WHERE id=$1", p.Account).Scan(&a.Epoch, &a.Password, &a.Recovery, &a.Email); e != nil {
		fail(w, problem{401, "invalid_credentials"})
		return
	}
	key, sig := a.Password, x.Proof.Password
	a.Scope = "full"
	if p.Method == "login-recovery" {
		key, sig = a.Recovery, x.Proof.Recovery
		a.Scope = "recovery"
	}
	if x.Account != p.Account || x.Epoch != a.Epoch || !checkSig(key, sig, x.Transcript) {
		fail(w, problem{401, "invalid_credentials"})
		return
	}
	token := protocol.Random(32)
	a.CSRF = protocol.B64(protocol.Random(32))
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
	_, e = tx.Exec(r.Context(), "INSERT INTO member.sessions VALUES($1,$2,$3,$4,$5,$6)", protocol.Hash(token), a.Account, a.Scope, a.Epoch, a.CSRF, time.Now().Add(12*time.Hour))
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: protocol.B64(token), Path: "/api/member", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	write(w, 200, sessionView(a))
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	v := sessionView(a)
	v["memberships"] = s.memberships(r, a.Account)
	write(w, 200, v)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	if r.Header.Get("X-CSRF-Token") != a.CSRF {
		fail(w, problem{403, "csrf_required"})
		return
	}
	tx, e := s.member.Begin(r.Context())
	if e != nil {
		fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	var locked string
	if e = tx.QueryRow(r.Context(), "SELECT id FROM member.accounts WHERE id=$1 FOR UPDATE", a.Account).Scan(&locked); e != nil {
		fail(w, e)
		return
	}
	_, e = tx.Exec(r.Context(), "DELETE FROM member.sessions WHERE id_hash=$1", a.Hash)
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/api/member", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	write(w, 200, map[string]bool{"ok": true})
}
func (s *Server) vault(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	var wraps map[string]any
	var kd json.RawMessage
	var salt string
	var encryption, binding []byte
	if e = s.member.QueryRow(r.Context(), "SELECT vault,password_kdf,recovery_salt,encryption_public,encryption_key_signature FROM member.accounts WHERE id=$1", a.Account).Scan(&wraps, &kd, &salt, &encryption, &binding); e != nil {
		fail(w, e)
		return
	}
	rows, e := s.member.Query(r.Context(), "SELECT object FROM member.vault_objects WHERE account_id=$1 ORDER BY id", a.Account)
	if e != nil {
		fail(w, e)
		return
	}
	defer rows.Close()
	objects := []json.RawMessage{}
	for rows.Next() {
		var o json.RawMessage
		if e = rows.Scan(&o); e != nil {
			fail(w, e)
			return
		}
		objects = append(objects, o)
	}
	wraps["objects"], wraps["password_kdf"], wraps["recovery_salt"] = objects, kd, salt
	wraps["encryption_public_key"], wraps["encryption_key_signature"] = protocol.B64(encryption), protocol.B64(binding)
	write(w, 200, wraps)
}
func (s *Server) putObject(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request  string `json:"request_id"`
		Expected string `json:"expected_revision"`
		Object   object `json:"object"`
	}
	x, e := s.verify(r, "vault-write", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	if p.Object.ID != r.PathValue("id") {
		fail(w, bad("object_mismatch"))
		return
	}
	tx, e := s.member.Begin(r.Context())
	if e != nil {
		fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	old, e := operation(r, tx, x, p.Request)
	if e != nil {
		fail(w, e)
		return
	}
	if old != nil {
		write(w, 200, old)
		return
	}
	if e = saveObject(r, tx, x.Session.Account, vaultWrite{p.Expected, p.Object}); e == nil {
		e = cache(r, tx, x, p.Request, p.Object)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, p.Object)
}
