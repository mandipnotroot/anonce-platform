// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"github.com/mandipnotroot/anonce-platform/db"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestIntegrationChallengeAtomicityAndEpoch(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	ctx := context.Background()
	// Vault CAS failure happens after transactional consumption, so rollback must restore the challenge.
	o := fakeObject()
	o.Revision = "3"
	p := map[string]any{"request_id": protocol.ID(), "expected_revision": "2", "object": o}
	env := signed(t, s, h, u, "vault-write", p, false)
	path := "/api/member/vault/objects/" + o.ID
	result(t, request(h, "PUT", path, env, u), 409)
	var used bool
	if e := s.member.QueryRow(ctx, "SELECT used FROM member.challenges WHERE id=$1", env.Proof.Challenge).Scan(&used); e != nil || used {
		t.Fatalf("rollback consumed challenge %v %v", used, e)
	}
	b, _ := json.Marshal(o)
	if _, e := s.member.Exec(ctx, "INSERT INTO member.vault_objects VALUES($1,$2,2,$3)", u.id, o.ID, b); e != nil {
		t.Fatal(e)
	}
	result(t, request(h, "PUT", path, env, u), 200)
	result(t, request(h, "PUT", path, env, u), 200)
	// Concurrent exact mutation retries are one atomic write plus cached result.
	orgEnv := signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Concurrent"}, false)
	responses := make([]*httptest.ResponseRecorder, 8)
	var wg sync.WaitGroup
	for i := range responses {
		wg.Go(func() { responses[i] = request(h, "POST", "/api/member/orgs", orgEnv, u) })
	}
	wg.Wait()
	var id string
	created := 0
	for _, w := range responses {
		if w.Code == 201 {
			created++
		} else if w.Code != 200 {
			t.Fatalf("concurrent mutation %d %s", w.Code, w.Body.String())
		}
		var v map[string]any
		json.Unmarshal(w.Body.Bytes(), &v)
		if id != "" && v["id"] != id {
			t.Fatal("duplicate org")
		}
		id = v["id"].(string)
	}
	if created != 1 {
		t.Fatalf("created %d", created)
	}
	// A stale login challenge cannot be upgraded to the account's newer epoch.
	login := map[string]string{"request_id": protocol.ID(), "account_id": u.id, "method": "login-password"}
	old := signed(t, s, h, u, "login-password", login, true)
	if _, e := s.member.Exec(ctx, "UPDATE member.accounts SET epoch=epoch+1 WHERE id=$1", u.id); e != nil {
		t.Fatal(e)
	}
	result(t, request(h, "POST", "/api/member/session", old, nil), 401)
	result(t, request(h, "GET", "/api/member/me", nil, u), 401)
	loginUser(t, s, h, u, "login-password")
	loginEnv := signed(t, s, h, u, "login-password", login, true)
	responses = make([]*httptest.ResponseRecorder, 2)
	for i := range responses {
		wg.Go(func() { responses[i] = request(h, "POST", "/api/member/session", loginEnv, nil) })
	}
	wg.Wait()
	ok := 0
	for _, w := range responses {
		if w.Code == 200 {
			ok++
		} else if w.Code != 409 {
			t.Fatalf("login replay %d %s", w.Code, w.Body.String())
		}
	}
	if ok != 1 {
		t.Fatalf("login minted %d", ok)
	}
	// Migration reruns are no-ops and preserve deployment/key/account state.
	before := protocol.B64(s.deployment)
	for range 2 {
		if e := db.Migrate(ctx, s.member); e != nil {
			t.Fatal(e)
		}
	}
	var dep []byte
	if e := s.member.QueryRow(ctx, "SELECT value FROM member.settings WHERE name='deployment'").Scan(&dep); e != nil || protocol.B64(dep) != before {
		t.Fatal("migration lost deployment")
	}
	result(t, request(h, "GET", "/api/member/me", nil, u), 200)
}
func expiredCert(t *testing.T, s *Server, org, id string, pub ed25519.PublicKey) string {
	t.Helper()
	b, e := s.cert(org, id, pub)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(mustDecode(b))
	if e != nil {
		t.Fatal(e)
	}
	c.NotBefore = time.Now().Add(-2 * time.Hour)
	c.NotAfter = time.Now().Add(-time.Hour)
	parent, _ := x509.ParseCertificate(s.caDER)
	raw, e := x509.CreateCertificate(rand.Reader, c, parent, pub, s.ca)
	if e != nil {
		t.Fatal(e)
	}
	return protocol.B64(raw)
}
func TestIntegrationCertificateAndRevocation(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	ctx := context.Background()
	orgEnv := signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Certificate test"}, false)
	orgResult := result(t, request(h, "POST", "/api/member/orgs", orgEnv, u), 201)
	org, member := orgResult["id"].(string), orgResult["membership_id"].(string)
	cert := expiredCert(t, s, org, member, u.member.Public().(ed25519.PublicKey))
	if s.validCertificate(cert, u.member.Public().(ed25519.PublicKey), org, member) {
		t.Fatal("expired leaf authorized")
	}
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", cert, member); e != nil {
		t.Fatal(e)
	}
	renew := signed(t, s, h, u, "certificate-renew", map[string]string{"request_id": protocol.ID()}, false)
	v := result(t, request(h, "POST", "/api/member/orgs/"+org+"/certificate/renew", renew, u), 200)
	if !s.validCertificate(v["certificate"].(string), u.member.Public().(ed25519.PublicKey), org, member) {
		t.Fatal("renew invalid")
	}
	expires, e := decimal(v["expires_at"].(string))
	if e != nil || expires <= time.Now().Add(24*time.Hour).Unix() {
		t.Fatal("renew expiry metadata", v)
	}
	current := result(t, request(h, "GET", "/api/member/orgs/"+org+"/certificate", nil, u), 200)
	if current["expires_at"] != v["expires_at"] {
		t.Fatal("GET certificate expiry mismatch")
	}
	retry := result(t, request(h, "POST", "/api/member/orgs/"+org+"/certificate/renew", renew, u), 200)
	if retry["certificate"] != v["certificate"] {
		t.Fatal("renew retry changed")
	}
	// Last approved owner cannot revoke self.
	revoke := signed(t, s, h, u, "member-revoke", map[string]string{"request_id": protocol.ID()}, false)
	result(t, request(h, "POST", "/api/member/orgs/"+org+"/members/"+member+"/revoke", revoke, u), 409)
	// Pending membership remains unauthorized until owner approval; any approved member can create a review.
	invited := newUser(t, s, h)
	invite := signed(t, s, h, u, "invite-create", map[string]string{"request_id": protocol.ID(), "role": "respondent", "expires_at": format(time.Now().Add(time.Hour).Unix())}, false)
	token := result(t, request(h, "POST", "/api/member/orgs/"+org+"/invites", invite, u), 201)["token"].(string)
	accept := signed(t, s, h, invited, "invite-accept", map[string]string{"request_id": protocol.ID(), "invite_token": token}, false)
	m := result(t, request(h, "POST", "/api/member/invites/accept", accept, invited), 201)["id"].(string)
	create := signed(t, s, h, invited, "review-create", fakeReviewCreate(2), false)
	path := "/api/member/orgs/" + org + "/reviews"
	result(t, request(h, "POST", path, create, invited), 403)
	approve := signed(t, s, h, u, "member-approve", map[string]string{"request_id": protocol.ID()}, false)
	result(t, request(h, "POST", "/api/member/orgs/"+org+"/members/"+m+"/approve", approve, u), 200)
	result(t, request(h, "POST", path, create, invited), 201)
	admitted := signed(t, s, h, invited, "review-create", fakeReviewCreate(1), false)
	revoke = signed(t, s, h, u, "member-revoke", map[string]string{"request_id": protocol.ID()}, false)
	result(t, request(h, "POST", "/api/member/orgs/"+org+"/members/"+m+"/revoke", revoke, u), 200)
	result(t, request(h, "POST", path, admitted, invited), 403)
}
func transcript(t *testing.T, s *Server, env envelope) []byte {
	t.Helper()
	var account, action string
	var epoch, expires int64
	var hash, nonce []byte
	if e := s.member.QueryRow(context.Background(), "SELECT account_id,action,epoch,payload_hash,nonce,expires FROM member.challenges WHERE id=$1", env.Proof.Challenge).Scan(&account, &action, &epoch, &hash, &nonce, &expires); e != nil {
		t.Fatal(e)
	}
	return protocol.E("challenge", s.deployment, []byte(s.cfg.Origin), mustDecode(account), mustDecode(env.Proof.Challenge), []byte(action), protocol.U64(uint64(epoch)), hash, nonce, protocol.U64(uint64(expires)))
}
func TestIntegrationCredentialChangesLogoutAndLargeVault(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	// A full-size pending encrypted object comfortably carries an exact 256KiB response.
	large := fakeObject()
	large.Ciphertext = protocol.B64(protocol.Random(1024 * 1024))
	env := signed(t, s, h, u, "vault-write", map[string]any{"request_id": protocol.ID(), "expected_revision": "0", "object": large}, false)
	result(t, request(h, "PUT", "/api/member/vault/objects/"+large.ID, env, u), 200)
	staleWrite := signed(t, s, h, u, "vault-write", map[string]any{"request_id": protocol.ID(), "expected_revision": "0", "object": fakeObject()}, false)
	login := map[string]string{"request_id": protocol.ID(), "account_id": u.id, "method": "login-password"}
	oldLogin := signed(t, s, h, u, "login-password", login, true)
	_, newPW, _ := ed25519.GenerateKey(rand.Reader)
	kd := kdf{19, protocol.B64(protocol.Random(16)), 65536, 3, 1, 32}
	change := map[string]any{"request_id": protocol.ID(), "expected_epoch": "1", "password_kdf": kd, "password_auth_public_key": protocol.B64(newPW.Public().(ed25519.PublicKey)), "password_wrap": fakeWrapper()}
	env = signed(t, s, h, u, "password-change", change, false)
	env.Proof.NewPassword = protocol.B64(ed25519.Sign(newPW, transcript(t, s, env)))
	result(t, request(h, "POST", "/api/member/credentials/password", env, u), 200)
	result(t, request(h, "GET", "/api/member/me", nil, u), 401)
	result(t, request(h, "POST", "/api/member/session", oldLogin, nil), 403)
	result(t, request(h, "PUT", "/api/member/vault/objects/"+fakeObject().ID, staleWrite, u), 401)
	u.pw = newPW
	loginUser(t, s, h, u, "login-password")
	_, newRecovery, _ := ed25519.GenerateKey(rand.Reader)
	rotate := map[string]any{"request_id": protocol.ID(), "expected_epoch": "2", "recovery_salt": protocol.B64(protocol.Random(32)), "recovery_auth_public_key": protocol.B64(newRecovery.Public().(ed25519.PublicKey)), "recovery_wrap": fakeWrapper()}
	env = signed(t, s, h, u, "recovery-rotate", rotate, false)
	env.Proof.NewRecovery = protocol.B64(ed25519.Sign(newRecovery, transcript(t, s, env)))
	result(t, request(h, "POST", "/api/member/credentials/recovery", env, u), 200)
	u.re = newRecovery
	loginUser(t, s, h, u, "login-recovery")
	_, resetPW, _ := ed25519.GenerateKey(rand.Reader)
	_, resetRE, _ := ed25519.GenerateKey(rand.Reader)
	reset := map[string]any{"request_id": protocol.ID(), "expected_epoch": "3", "password_kdf": kd, "password_auth_public_key": protocol.B64(resetPW.Public().(ed25519.PublicKey)), "password_wrap": fakeWrapper(), "recovery_salt": protocol.B64(protocol.Random(32)), "recovery_auth_public_key": protocol.B64(resetRE.Public().(ed25519.PublicKey)), "recovery_wrap": fakeWrapper(), "vault_writes": []vaultWrite{{"0", fakeObject()}}}
	env = signed(t, s, h, u, "credential-reset", reset, false)
	msg := transcript(t, s, env)
	env.Proof.NewPassword = protocol.B64(ed25519.Sign(resetPW, msg))
	env.Proof.NewRecovery = protocol.B64(ed25519.Sign(resetRE, msg))
	result(t, request(h, "POST", "/api/member/credentials/reset", env, u), 200)
	u.pw, u.re = resetPW, resetRE
	loginUser(t, s, h, u, "login-password")
	me := result(t, request(h, "GET", "/api/member/me", nil, u), 200)
	if me["credential_epoch"] != "4" {
		t.Fatal(me)
	}
	pending := fakeObject()
	env = signed(t, s, h, u, "vault-write", map[string]any{"request_id": protocol.ID(), "expected_revision": "0", "object": pending}, false)
	result(t, request(h, "DELETE", "/api/member/session", nil, u), 200)
	result(t, request(h, "PUT", "/api/member/vault/objects/"+pending.ID, env, u), 401)
}
