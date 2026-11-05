// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

type testUser struct {
	id             string
	pw, re, member ed25519.PrivateKey
	cookie, csrf   string
}

func request(h http.Handler, method, path string, v any, u *testUser) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Origin", "https://anonce.test")
	r.Header.Set("Content-Type", "application/json")
	if u != nil {
		r.Header.Set("Cookie", cookieName+"="+u.cookie)
		r.Header.Set("X-CSRF-Token", u.csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func result(t *testing.T, w *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d want %d: %s", w.Code, status, w.Body.String())
	}
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func signed(t *testing.T, s *Server, h http.Handler, u *testUser, action string, p any, pre bool) envelope {
	t.Helper()
	b, _ := json.Marshal(p)
	who := u
	if pre {
		who = nil
	}
	c := result(t, request(h, "POST", "/api/member/challenges", map[string]string{"account_id": u.id, "action": action, "payload_hash": protocol.B64(protocol.Hash(b))}, who), 200)
	epoch, _ := strconv.ParseUint(c["credential_epoch"].(string), 10, 64)
	expires, _ := strconv.ParseUint(c["expires_at"].(string), 10, 64)
	msg := protocol.E("challenge", s.deployment, []byte(s.cfg.Origin), mustDecode(u.id), mustDecode(c["challenge_id"].(string)), []byte(action), protocol.U64(epoch), protocol.Hash(b), mustDecode(c["nonce"].(string)), protocol.U64(expires))
	pfs := proof{Challenge: c["challenge_id"].(string), Password: protocol.B64(ed25519.Sign(u.pw, msg)), Recovery: protocol.B64(ed25519.Sign(u.re, msg)), Membership: protocol.B64(ed25519.Sign(u.member, msg))}
	return envelope{protocol.B64(b), pfs}
}
func fakeWrapper() wrapper {
	return wrapper{1, protocol.ID(), protocol.B64(protocol.Random(12)), protocol.B64(protocol.Random(48))}
}
func fakeObject() object {
	return object{1, protocol.ID(), "1", protocol.B64(protocol.Random(12)), protocol.B64(protocol.Random(48))}
}
func newUser(t *testing.T, s *Server, h http.Handler) *testUser {
	t.Helper()
	_, pw, _ := ed25519.GenerateKey(rand.Reader)
	_, re, _ := ed25519.GenerateKey(rand.Reader)
	_, mp, _ := ed25519.GenerateKey(rand.Reader)
	u := &testUser{id: protocol.ID(), pw: pw, re: re, member: mp}
	p := registration{Request: protocol.ID(), Account: u.id, Email: "user-" + u.id + "@example.test", KDF: kdf{19, protocol.B64(protocol.Random(16)), 65536, 3, 1, 32}, Password: protocol.B64(pw.Public().(ed25519.PublicKey)), RecoverySalt: protocol.B64(protocol.Random(32)), Recovery: protocol.B64(re.Public().(ed25519.PublicKey)), PasswordWrap: fakeWrapper(), RecoveryWrap: fakeWrapper(), Membership: protocol.B64(mp.Public().(ed25519.PublicKey)), Objects: []object{fakeObject()}}
	env := signed(t, s, h, u, "register", p, true)
	result(t, request(h, "POST", "/api/member/register", env, nil), 201)
	loginUser(t, s, h, u, "login-password")
	return u
}
func loginUser(t *testing.T, s *Server, h http.Handler, u *testUser, method string) {
	p := map[string]string{"request_id": protocol.ID(), "account_id": u.id, "method": method}
	env := signed(t, s, h, u, method, p, true)
	w := request(h, "POST", "/api/member/session", env, nil)
	v := result(t, w, 200)
	u.cookie = w.Result().Cookies()[0].Value
	u.csrf = v["csrf_token"].(string)
}
func testServer(t *testing.T) *Server {
	t.Helper()
	url := os.Getenv("ANONCE_TEST_DATABASE_URL")
	anon := os.Getenv("ANONCE_TEST_ANON_DATABASE_URL")
	if url == "" || anon == "" {
		t.Skip("disposable PostgreSQL URLs not configured")
	}
	key := filepath.Join(t.TempDir(), "master")
	if e := os.WriteFile(key, []byte(protocol.B64(protocol.Hash([]byte("anonce disposable integration master fixture only")))), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(context.Background(), Config{DatabaseURL: url, AnonymousURL: anon, Origin: "https://anonce.test", KeyFile: key, WebDir: t.TempDir(), SourceURL: "https://github.com/mandipnotroot/anonce-platform"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func TestIntegrationWholeFlowConcurrent(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	ctx := t.Context()
	// Isolation is enforced by PostgreSQL, not merely handler routing.
	if _, e := s.anonymous.Exec(ctx, "SELECT * FROM member.accounts"); e == nil {
		t.Fatal("anonymous read accounts")
	}
	if _, e := s.anonymous.Exec(ctx, "UPDATE anon.reviews SET accepted_count=100"); e == nil {
		t.Fatal("anonymous mutate reviews")
	}
	orgEnv := signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Test organization"}, false)
	org := result(t, request(h, "POST", "/api/member/orgs", orgEnv, u), 201)["id"].(string)
	// Exact mutation retry is cached; changed/reused challenge cannot create again.
	result(t, request(h, "POST", "/api/member/orgs", orgEnv, u), 200)
	path := "/api/member/orgs/" + org + "/reviews"
	env := signed(t, s, h, u, "review-create", fakeReviewCreate(1), false)
	v := result(t, request(h, "POST", path, env, u), 201)
	id := v["id"].(string)
	result(t, request(h, "POST", path, env, u), 200)
	var vaultCount int
	if e := s.member.QueryRow(ctx, "SELECT count(*) FROM member.vault_objects WHERE account_id=$1 AND id=$2", u.id, id).Scan(&vaultCount); e != nil || vaultCount != 1 {
		t.Fatalf("create did not atomically save review keys: %d, %v", vaultCount, e)
	}
	// A conflicting vault write must roll back the review and operation cache.
	conflict := fakeReviewCreate(1)
	conflictID := conflict["review_id"].(string)
	if _, e := s.member.Exec(ctx, "INSERT INTO member.vault_objects VALUES($1,$2,1,$3)", u.id, conflictID, []byte(`{}`)); e != nil {
		t.Fatal(e)
	}
	conflictEnv := signed(t, s, h, u, "review-create", conflict, false)
	if got := request(h, "POST", path, conflictEnv, u); got.Code < 400 {
		t.Fatal("accepted conflicting vault insertion")
	}
	var rolledBack bool
	if e := s.member.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM member.reviews WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM member.operations WHERE account_id=$2 AND request_id=$3)", conflictID, u.id, conflict["request_id"]).Scan(&rolledBack); e != nil || !rolledBack {
		t.Fatalf("partial create committed: %v", e)
	}
	if _, e := s.member.Exec(ctx, "DELETE FROM member.vault_objects WHERE account_id=$1 AND id=$2", u.id, conflictID); e != nil {
		t.Fatal(e)
	}
	result(t, request(h, "POST", path, conflictEnv, u), 201)
	deletePath := "/api/member/reviews/" + conflictID
	deleteEnv := signed(t, s, h, u, "review-delete", revisionRequest{protocol.ID(), "1"}, false)
	result(t, request(h, "DELETE", deletePath, deleteEnv, u), 200)
	if e := s.member.QueryRow(ctx, "SELECT count(*) FROM member.vault_objects WHERE account_id=$1 AND id=$2", u.id, conflictID).Scan(&vaultCount); e != nil || vaultCount != 0 {
		t.Fatalf("draft deletion retained vault object: %d, %v", vaultCount, e)
	}
	path = "/api/member/reviews/" + id
	content := fakeContent()
	update := map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "encrypted_content": content, "max_responses": 1, "opens_at": nil, "closes_at": nil}
	env = signed(t, s, h, u, "review-update", update, false)
	v = result(t, request(h, "PUT", path, env, u), 200)
	result(t, request(h, "PUT", path, env, u), 200)
	stale := signed(t, s, h, u, "review-update", map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "encrypted_content": fakeContent(), "max_responses": 1, "opens_at": nil, "closes_at": nil}, false)
	result(t, request(h, "PUT", path, stale, u), 409)
	cert := result(t, request(h, "GET", "/api/member/orgs/"+org+"/certificate", nil, u), 200)
	d := descriptor{V: 3, Deployment: protocol.B64(s.deployment), Review: id, Org: org, Membership: cert["membership_id"].(string), Certificate: cert["certificate"].(string), Content: content, Recipient: protocol.B64(protocol.Random(32)), Issuer: v["issuer_key_id"].(string), Public: v["issuer_public_key"].(string)}
	desc, _ := json.Marshal(d)
	publish := map[string]any{"request_id": protocol.ID(), "expected_revision": "2", "descriptor": protocol.B64(desc), "descriptor_signature": protocol.B64(ed25519.Sign(u.member, protocol.E("review-descriptor", desc)))}
	// A correctly signed descriptor cannot substitute a different encrypted envelope.
	mismatch := d
	mismatch.Content = fakeContent()
	mismatchBytes, _ := json.Marshal(mismatch)
	mismatchPayload := map[string]any{"request_id": protocol.ID(), "expected_revision": "2", "descriptor": protocol.B64(mismatchBytes), "descriptor_signature": protocol.B64(ed25519.Sign(u.member, protocol.E("review-descriptor", mismatchBytes)))}
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, u, "review-publish", mismatchPayload, false), u), 400)
	// An otherwise exact, genuinely CA-signed but expired leaf cannot publish.
	expired := expiredCert(t, s, org, d.Membership, u.member.Public().(ed25519.PublicKey))
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", expired, d.Membership); e != nil {
		t.Fatal(e)
	}
	badD := d
	badD.Certificate = expired
	badBytes, _ := json.Marshal(badD)
	badPublish := map[string]any{"request_id": protocol.ID(), "expected_revision": "2", "descriptor": protocol.B64(badBytes), "descriptor_signature": protocol.B64(ed25519.Sign(u.member, protocol.E("review-descriptor", badBytes)))}
	badEnv := signed(t, s, h, u, "review-publish", badPublish, false)
	result(t, request(h, "POST", path+"/publish", badEnv, u), 400)
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", d.Certificate, d.Membership); e != nil {
		t.Fatal(e)
	}
	env = signed(t, s, h, u, "review-publish", publish, false)
	result(t, request(h, "POST", path+"/publish", env, u), 200)
	result(t, request(h, "POST", path+"/publish", env, u), 200)
	pub, e := x509.ParsePKIXPublicKey(mustDecode(d.Public))
	if e != nil {
		t.Fatal(e)
	}
	client, e := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pub.(*rsa.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	serial := protocol.Random(32)
	msg := protocol.E("authorization", s.deployment, mustDecode(id), protocol.Hash(desc), mustDecode(d.Issuer), serial)
	prepared, e := client.Prepare(rand.Reader, msg)
	if e != nil {
		t.Fatal(e)
	}
	blinded, state, e := client.Blind(rand.Reader, prepared)
	if e != nil {
		t.Fatal(e)
	}
	// Two independently signed quota requests race; precisely one reserves a slot.
	type issuance struct {
		env     envelope
		request string
	}
	requests := make([]issuance, 2)
	for i := range requests {
		req := protocol.ID()
		p := map[string]any{"request_id": req, "issuer_key_id": d.Issuer, "blinded_message": protocol.B64(blinded), "pending_state": vaultWrite{"0", fakeObject()}}
		requests[i] = issuance{signed(t, s, h, u, "issue", p, false), req}
	}
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", expired, d.Membership); e != nil {
		t.Fatal(e)
	}
	result(t, request(h, "POST", path+"/issuances", requests[0].env, u), 403)
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", d.Certificate, d.Membership); e != nil {
		t.Fatal(e)
	}
	responses := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range responses {
		wg.Go(func() { responses[i] = request(h, "POST", path+"/issuances", requests[i].env, u) })
	}
	wg.Wait()
	success := -1
	for i, w := range responses {
		if w.Code == 200 {
			if success != -1 {
				t.Fatal("quota overrun")
			}
			success = i
		} else if w.Code != 409 {
			t.Fatalf("issue %d: %s", w.Code, w.Body.String())
		}
	}
	if success < 0 {
		t.Fatal("no issue succeeded")
	}
	issued := result(t, responses[success], 200)
	retry := result(t, request(h, "POST", path+"/issuances", requests[success].env, u), 200)
	if issued["blind_signature"] != retry["blind_signature"] {
		t.Fatal("issuance retry changed")
	}
	assertAccepted := func(stage string, want int64) {
		t.Helper()
		var accepted, persisted int64
		if e := s.anonymous.QueryRow(ctx, "SELECT accepted_count,(SELECT count(*) FROM anon.submissions WHERE review_id=$1) FROM anon.reviews WHERE id=$1", id).Scan(&accepted, &persisted); e != nil {
			t.Fatal(e)
		}
		if accepted != want || persisted != want {
			t.Fatalf("%s: accepted_count=%d persisted=%d want both %d", stage, accepted, persisted, want)
		}
		review := result(t, request(h, "GET", path, nil, u), 200)
		if review["accepted_count"] != strconv.FormatInt(want, 10) {
			t.Fatalf("%s: member accepted_count=%v want %d", stage, review["accepted_count"], want)
		}
	}
	assertAccepted("issuance and issuance retry", 0)
	sig, e := client.Finalize(state, mustDecode(issued["blind_signature"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	sub := submission{id, d.Issuer, protocol.B64(prepared), protocol.B64(sig), protocol.B64(protocol.Random(32)), protocol.B64(protocol.Random(64))}
	for _, field := range []string{"enc", "ciphertext", "signature"} {
		invalid := sub
		switch field {
		case "enc":
			invalid.Enc = protocol.B64(protocol.Random(31))
		case "ciphertext":
			invalid.Ciphertext = protocol.B64(protocol.Random(15))
		case "signature":
			badSignature := bytes.Clone(sig)
			badSignature[0] ^= 1
			invalid.Signature = protocol.B64(badSignature)
		}
		result(t, request(h, "POST", "/api/anon/submissions", invalid, nil), 400)
		assertAccepted("invalid "+field, 0)
	}
	// Exercise the restricted role's atomic write, then discard both changes.
	tx, e := s.anonymous.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	rid, kid := mustDecode(id), mustDecode(d.Issuer)
	enc, ciphertext := mustDecode(sub.Enc), mustDecode(sub.Ciphertext)
	tokenHash := protocol.Hash(protocol.E("token", rid, kid, serial))
	submissionHash := protocol.Hash(protocol.E("submission", rid, kid, prepared, sig, enc, ciphertext))
	var rolledBackReceipt json.RawMessage
	if e := tx.QueryRow(ctx, "SELECT anon.accept_submission($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, d.Issuer, tokenHash, submissionHash, prepared, sig, enc, ciphertext, json.RawMessage(`{"rollback_fixture":true}`)).Scan(&rolledBackReceipt); e != nil {
		t.Fatal(e)
	}
	var pendingAccepted, pendingRows int64
	if e := tx.QueryRow(ctx, "SELECT accepted_count,(SELECT count(*) FROM anon.submissions WHERE review_id=$1) FROM anon.reviews WHERE id=$1", id).Scan(&pendingAccepted, &pendingRows); e != nil {
		t.Fatal(e)
	}
	if pendingAccepted != 1 || pendingRows != 1 {
		t.Fatalf("pending transaction: accepted_count=%d persisted=%d want both 1", pendingAccepted, pendingRows)
	}
	assertAccepted("uncommitted submission is invisible", 0)
	if e := tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	assertAccepted("rolled back submission", 0)
	// The same valid token remains usable after rollback, even under retries.
	responses = make([]*httptest.ResponseRecorder, 12)
	for i := range responses {
		wg.Go(func() { responses[i] = request(h, "POST", "/api/anon/submissions", sub, nil) })
	}
	wg.Wait()
	var receipt string
	var storedReceipt protocol.Receipt
	var descriptorHash []byte
	if e := s.anonymous.QueryRow(ctx, "SELECT descriptor_hash FROM anon.reviews WHERE id=$1", id).Scan(&descriptorHash); e != nil {
		t.Fatal(e)
	}
	responseHash, e := protocol.ResponseHash(s.deployment, rid, descriptorHash, kid, enc, ciphertext)
	if e != nil {
		t.Fatal(e)
	}
	receiptPublicKey, e := s.receiptTrust.CurrentPublicKey()
	if e != nil {
		t.Fatal(e)
	}
	expectedReceipt := protocol.ReceiptContext{DeploymentID: protocol.B64(s.deployment), ReviewID: id, DescriptorHash: protocol.B64(descriptorHash), IssuerKeyID: d.Issuer, ResponseHash: protocol.B64(responseHash)}
	for _, w := range responses {
		parsed, err := protocol.ParseReceipt(w.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.VerifyReceipt(parsed, receiptPublicKey, expectedReceipt); err != nil {
			t.Fatal(err)
		}
		if receipt != "" && storedReceipt != parsed {
			t.Fatal("signed receipt changed under concurrent retry")
		}
		storedReceipt = parsed
		v := result(t, w, 200)
		if receipt != "" && receipt != v["receipt_id"] {
			t.Fatal("receipt changed")
		}
		receipt = v["receipt_id"].(string)
	}
	assertAccepted("concurrent identical submissions after rollback", 1)
	v = result(t, request(h, "GET", path, nil, u), 200)
	if v["accepted_count"] != "1" || v["issued_count"] != "1" {
		t.Fatalf("counters: %v", v)
	}
	closeEnv := signed(t, s, h, u, "review-close", revisionRequest{protocol.ID(), "3"}, false)
	result(t, request(h, "POST", path+"/close", closeEnv, u), 200)
	result(t, request(h, "POST", "/api/anon/submissions", sub, nil), 200)
	assertAccepted("exact submission retry after close", 1)
	sub.Ciphertext = protocol.B64(protocol.Random(64))
	result(t, request(h, "POST", "/api/anon/submissions", sub, nil), 409)
	assertAccepted("conflicting replay", 1)
	lookup := map[string]string{"review_id": id, "issuer_key_id": d.Issuer, "serial": protocol.B64(serial)}
	lookupResponse := request(h, "POST", "/api/anon/receipts/lookup", lookup, nil)
	lookupReceipt, e := protocol.ParseReceipt(lookupResponse.Body.Bytes())
	if e != nil || lookupReceipt != storedReceipt {
		t.Fatalf("lookup receipt changed: %v", e)
	}
	result(t, lookupResponse, 200)
	result(t, request(h, "POST", "/api/anon/receipts/lookup", lookup, u), 400)
	if _, e := s.member.Exec(ctx, "UPDATE member.memberships SET certificate=$1 WHERE id=$2", expired, d.Membership); e != nil {
		t.Fatal(e)
	}
	rows := result(t, request(h, "GET", path+"/submissions", nil, u), 200)
	if len(rows["items"].([]any)) != 1 {
		t.Fatal("missing response")
	}
	item := rows["items"].([]any)[0].(map[string]any)
	if len(item) != 4 || item["enc"] != protocol.B64(enc) || item["ciphertext"] != protocol.B64(ciphertext) {
		t.Fatal("reviewer output changed or exposed authorization fields")
	}
	listedJSON, e := json.Marshal(item["receipt"])
	if e != nil {
		t.Fatal(e)
	}
	listedReceipt, e := protocol.ParseReceipt(listedJSON)
	if e != nil || listedReceipt != storedReceipt {
		t.Fatalf("reviewer receipt changed: %v", e)
	}
	// Recovery sessions cannot create organizations but can read the encrypted vault.
	loginUser(t, s, h, u, "login-recovery")
	result(t, request(h, "GET", "/api/member/vault", nil, u), 200)
	result(t, request(h, "GET", "/api/member/orgs", nil, u), 403)
}
