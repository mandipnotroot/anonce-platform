// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func format(n int64) string { return strconv.FormatInt(n, 10) }
func (s *Server) memberships(r *http.Request, account string) []map[string]any {
	items := []map[string]any{}
	rows, e := s.member.Query(r.Context(), "SELECT m.id,m.org_id,o.name,m.role,m.state,COALESCE(m.certificate,'') FROM member.memberships m JOIN member.orgs o ON o.id=m.org_id WHERE account_id=$1 ORDER BY m.id", account)
	if e != nil {
		return items
	}
	defer rows.Close()
	for rows.Next() {
		var id, org, name, role, status, cert string
		if rows.Scan(&id, &org, &name, &role, &status, &cert) == nil {
			items = append(items, map[string]any{"id": id, "membership_id": id, "org_id": org, "name": name, "role": role, "status": status, "state": status, "certificate": cert})
		}
	}
	return items
}
func (s *Server) orgRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/member/orgs", func(w http.ResponseWriter, r *http.Request) {
		a, e := s.session(r)
		if e != nil {
			fail(w, e)
			return
		}
		if a.Scope != "full" {
			fail(w, problem{403, "recovery_scope"})
			return
		}
		write(w, 200, map[string]any{"items": s.memberships(r, a.Account), "next": nil})
	})
	m.HandleFunc("POST /api/member/orgs", s.createOrg)
	m.HandleFunc("GET /api/member/orgs/{org}/members", s.listMembers)
	m.HandleFunc("POST /api/member/orgs/{org}/invites", s.invite)
	m.HandleFunc("POST /api/member/invites/accept", s.acceptInvite)
	m.HandleFunc("POST /api/member/orgs/{org}/members/{member}/approve", s.approve)
	m.HandleFunc("POST /api/member/orgs/{org}/members/{member}/revoke", s.revoke)
	m.HandleFunc("GET /api/member/orgs/{org}/certificate", s.certificate)
	m.HandleFunc("POST /api/member/orgs/{org}/certificate/renew", s.renew)
}
func (s *Server) cert(org, member string, pub []byte) (string, error) {
	parent, e := x509.ParseCertificate(s.caDER)
	if e != nil {
		return "", e
	}
	uri, e := url.Parse("urn:anonce:deployment:" + protocol.B64(s.deployment) + ":org:" + org + ":member:" + member)
	if e != nil {
		return "", e
	}
	now := time.Now()
	until := now.AddDate(0, 3, 0)
	if until.After(parent.NotAfter) {
		until = parent.NotAfter
	}
	t := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(protocol.Random(16)), Subject: pkix.Name{CommonName: "Anonce member"}, NotBefore: now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: false, URIs: []*url.URL{uri}}
	b, e := x509.CreateCertificate(rand.Reader, t, parent, ed25519.PublicKey(pub), s.ca)
	return protocol.B64(b), e
}

// operation serializes retries for an account. Authorization must be checked before this helper.
func operation(r *http.Request, tx pgx.Tx, x *verified, request string) (json.RawMessage, error) {
	if _, e := protocol.Decode(request, 16); e != nil {
		return nil, bad("invalid_request_id")
	}
	var epoch int64
	if e := tx.QueryRow(r.Context(), "SELECT epoch FROM member.accounts WHERE id=$1 FOR UPDATE", x.Session.Account).Scan(&epoch); e != nil {
		return nil, e
	}
	if epoch != x.Session.Epoch {
		return nil, problem{401, "session_revoked"}
	}
	if e := transactionAuthorization(r, tx, x); e != nil {
		return nil, e
	}
	var hash []byte
	var result json.RawMessage
	e := tx.QueryRow(r.Context(), "SELECT payload_hash,result FROM member.operations WHERE account_id=$1 AND request_id=$2", x.Session.Account, request).Scan(&hash, &result)
	if e == pgx.ErrNoRows {
		return nil, consumeChallenge(r, tx, x)
	}
	if e != nil {
		return nil, e
	}
	if !equal(hash, operationHash(r, x)) {
		return nil, problem{409, "request_conflict"}
	}
	return result, nil
}
func cache(r *http.Request, tx pgx.Tx, x *verified, request string, result any) error {
	b, _ := json.Marshal(result)
	_, e := tx.Exec(r.Context(), "INSERT INTO member.operations VALUES($1,$2,$3,$4)", x.Session.Account, request, operationHash(r, x), b)
	return e
}
func operationHash(r *http.Request, x *verified) []byte {
	return protocol.Hash(protocol.E("operation", []byte(r.Method), []byte(r.URL.Path), x.Payload))
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string `json:"request_id"`
		Name    string `json:"name"`
	}
	x, e := s.verify(r, "org-create", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	if len(p.Name) < 1 || len(p.Name) > 200 {
		fail(w, bad("invalid_name"))
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
	org, id := protocol.ID(), protocol.ID()
	cert, e := s.cert(org, id, x.Session.Membership)
	if e != nil {
		fail(w, e)
		return
	}
	_, e = tx.Exec(r.Context(), "INSERT INTO member.orgs VALUES($1,$2)", org, p.Name)
	if e == nil {
		_, e = tx.Exec(r.Context(), "INSERT INTO member.memberships VALUES($1,$2,$3,'owner','approved',$4)", id, org, x.Session.Account, cert)
	}
	result := map[string]string{"id": org, "org_id": org, "name": p.Name, "membership_id": id, "certificate": cert, "role": "owner", "status": "approved"}
	if e == nil {
		e = cache(r, tx, x, p.Request, result)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 201, result)
}
func (s *Server) membership(r *http.Request, a *session, org string, owner bool) (string, error) {
	if a.Scope != "full" {
		return "", problem{403, "recovery_scope"}
	}
	var id, role string
	e := s.member.QueryRow(r.Context(), "SELECT id,role FROM member.memberships WHERE org_id=$1 AND account_id=$2 AND state='approved'", org, a.Account).Scan(&id, &role)
	if e != nil || owner && role != "owner" {
		return "", problem{403, "forbidden"}
	}
	return id, nil
}
func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = s.membership(r, a, r.PathValue("org"), true); e != nil {
		fail(w, e)
		return
	}
	rows, e := s.member.Query(r.Context(), "SELECT id,account_id,role,state,COALESCE(certificate,'') FROM member.memberships WHERE org_id=$1 ORDER BY id LIMIT 100", r.PathValue("org"))
	if e != nil {
		fail(w, e)
		return
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var id, account, role, state, cert string
		if e = rows.Scan(&id, &account, &role, &state, &cert); e != nil {
			fail(w, e)
			return
		}
		items = append(items, map[string]string{"id": id, "account_id": account, "role": role, "status": state, "state": state, "certificate": cert})
	}
	write(w, 200, map[string]any{"items": items, "next": nil})
}
func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string `json:"request_id"`
		Role    string `json:"role"`
		Expires string `json:"expires_at"`
	}
	x, e := s.verify(r, "invite-create", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = s.membership(r, x.Session, r.PathValue("org"), true); e != nil {
		fail(w, e)
		return
	}
	expiry, e := decimal(p.Expires)
	if e != nil || (p.Role != "respondent" && p.Role != "reviewer") || expiry <= time.Now().Unix() || expiry > time.Now().Add(30*24*time.Hour).Unix() {
		fail(w, bad("invalid_invite"))
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
	token := protocol.Random(32)
	_, e = tx.Exec(r.Context(), "INSERT INTO member.invites(id_hash,org_id,expires_at,role) VALUES($1,$2,$3,$4)", protocol.Hash(token), r.PathValue("org"), time.Unix(expiry, 0), p.Role)
	result := map[string]string{"token": protocol.B64(token), "expires_at": p.Expires}
	if e == nil {
		e = cache(r, tx, x, p.Request, result)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 201, result)
}
func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string `json:"request_id"`
		Token   string `json:"invite_token"`
	}
	x, e := s.verify(r, "invite-accept", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	token, e := protocol.Decode(p.Token, 32)
	if e != nil {
		fail(w, bad("invalid_invite"))
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
	var org, role string
	e = tx.QueryRow(r.Context(), "DELETE FROM member.invites WHERE id_hash=$1 AND expires_at>now() RETURNING org_id,role", protocol.Hash(token)).Scan(&org, &role)
	if e != nil {
		fail(w, problem{410, "expired_invite"})
		return
	}
	id := protocol.ID()
	_, e = tx.Exec(r.Context(), "INSERT INTO member.memberships VALUES($1,$2,$3,$4,'pending',NULL)", id, org, x.Session.Account, role)
	result := map[string]string{"id": id, "membership_id": id, "org_id": org, "status": "pending"}
	if e == nil {
		e = cache(r, tx, x, p.Request, result)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 201, result)
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) { s.changeMember(w, r, false) }
func (s *Server) revoke(w http.ResponseWriter, r *http.Request)  { s.changeMember(w, r, true) }
func (s *Server) changeMember(w http.ResponseWriter, r *http.Request, revoke bool) {
	var p struct {
		Request string `json:"request_id"`
	}
	action := "member-approve"
	if revoke {
		action = "member-revoke"
	}
	x, e := s.verify(r, action, &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	org := r.PathValue("org")
	if _, e = s.membership(r, x.Session, org, true); e != nil {
		fail(w, e)
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
	var role, state string
	var pub []byte
	e = tx.QueryRow(r.Context(), "SELECT m.role,m.state,a.membership_public FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id WHERE m.id=$1 AND m.org_id=$2 FOR UPDATE OF m", r.PathValue("member"), org).Scan(&role, &state, &pub)
	if e != nil {
		fail(w, problem{404, "not_found"})
		return
	}
	target := "approved"
	var cert string
	if revoke {
		target = "revoked"
		if role == "owner" && state == "approved" {
			var count int
			if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM member.memberships WHERE org_id=$1 AND role='owner' AND state='approved'", org).Scan(&count); e != nil {
				fail(w, e)
				return
			}
			if count <= 1 {
				fail(w, problem{409, "last_owner"})
				return
			}
		}
	} else {
		if state != "pending" {
			fail(w, problem{409, "not_pending"})
			return
		}
		cert, e = s.cert(org, r.PathValue("member"), pub)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "UPDATE member.memberships SET state=$1,certificate=$2 WHERE id=$3", target, cert, r.PathValue("member"))
	}
	result := map[string]string{"id": r.PathValue("member"), "status": target, "certificate": cert}
	if e == nil {
		e = cache(r, tx, x, p.Request, result)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, result)
}
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	id, e := s.membership(r, a, r.PathValue("org"), false)
	if e != nil {
		fail(w, e)
		return
	}
	var cert string
	if e = s.member.QueryRow(r.Context(), "SELECT certificate FROM member.memberships WHERE id=$1", id).Scan(&cert); e != nil {
		fail(w, e)
		return
	}
	write(w, 200, map[string]string{"membership_id": id, "certificate": cert, "ca_certificate": protocol.B64(s.caDER), "expires_at": certificateExpiry(cert)})
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string `json:"request_id"`
	}
	x, e := s.verify(r, "certificate-renew", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	id, e := s.membership(r, x.Session, r.PathValue("org"), false)
	if e != nil {
		fail(w, e)
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
	cert, e := s.cert(r.PathValue("org"), id, x.Session.Membership)
	if e == nil {
		_, e = tx.Exec(r.Context(), "UPDATE member.memberships SET certificate=$1 WHERE id=$2 AND state='approved'", cert, id)
	}
	result := map[string]string{"membership_id": id, "certificate": cert, "ca_certificate": protocol.B64(s.caDER), "expires_at": certificateExpiry(cert)}
	if e == nil {
		e = cache(r, tx, x, p.Request, result)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, result)
}
func certificateExpiry(cert string) string {
	b, e := protocol.Decode(cert, -1)
	if e != nil {
		return "0"
	}
	c, e := x509.ParseCertificate(b)
	if e != nil {
		return "0"
	}
	return format(c.NotAfter.Unix())
}
func transactionAuthorization(r *http.Request, tx pgx.Tx, x *verified) error {
	if x.Session == nil {
		return nil
	}
	var valid bool
	if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM member.sessions WHERE id_hash=$1 AND epoch=$2 AND expires_at>now())", x.Session.Hash, x.Epoch).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return problem{401, "session_revoked"}
	}
	org := r.PathValue("org")
	if org == "" && r.PathValue("id") != "" && strings.Contains(r.URL.Path, "/reviews/") {
		if e := tx.QueryRow(r.Context(), "SELECT org_id FROM member.reviews WHERE id=$1", r.PathValue("id")).Scan(&org); e != nil {
			return problem{404, "not_found"}
		}
	}
	if org == "" {
		return nil
	}
	// Serialize organization mutations before membership/resource locks. This
	// deliberately favors a simple auditable lock order over per-org throughput.
	var locked string
	if e := tx.QueryRow(r.Context(), "SELECT id FROM member.orgs WHERE id=$1 FOR UPDATE", org).Scan(&locked); e != nil {
		return problem{404, "not_found"}
	}
	var role, state string
	if e := tx.QueryRow(r.Context(), "SELECT role,state FROM member.memberships WHERE account_id=$1 AND org_id=$2 FOR SHARE", x.Session.Account, org).Scan(&role, &state); e != nil {
		return problem{403, "forbidden"}
	}
	owner := strings.Contains(r.URL.Path, "/invites") || strings.Contains(r.URL.Path, "/members/")
	if state != "approved" || (owner && role != "owner") {
		return problem{403, "forbidden"}
	}
	return nil
}
