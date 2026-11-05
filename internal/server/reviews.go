// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http"
	"time"
)

type choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type question struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Required bool     `json:"required"`
	Choices  []choice `json:"choices"`
}
type draft struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Questions   []question `json:"questions"`
}
type review struct {
	ID, Org, Account, Membership, Issuer, State string
	Draft                                       draft
	Revision, Max, Issued, Accepted             int64
	Opens, Closes                               *int64
	Private, Public, Descriptor, Signature      []byte
}

const reviewColumns = "r.id,r.org_id,r.account_id,r.membership_id,r.issuer_key_id,r.state,r.draft,r.revision,r.max_responses,r.opens_at,r.closes_at,r.issued_count,r.issuer_private,r.issuer_public,r.descriptor,r.descriptor_signature,COALESCE((SELECT accepted_count FROM anon.reviews a WHERE a.id=r.id),0)"

func scanReview(row pgx.Row) (*review, error) {
	v := new(review)
	e := row.Scan(&v.ID, &v.Org, &v.Account, &v.Membership, &v.Issuer, &v.State, &v.Draft, &v.Revision, &v.Max, &v.Opens, &v.Closes, &v.Issued, &v.Private, &v.Public, &v.Descriptor, &v.Signature, &v.Accepted)
	return v, e
}
func (v *review) view() map[string]any {
	return map[string]any{"id": v.ID, "org_id": v.Org, "creator_account_id": v.Account, "reviewer_account_id": v.Account, "reviewer_membership_id": v.Membership, "title": v.Draft.Title, "description": v.Draft.Description, "questions": v.Draft.Questions, "max_responses": v.Max, "opens_at": nullableFormat(v.Opens), "closes_at": nullableFormat(v.Closes), "state": v.State, "revision": format(v.Revision), "issuer_public_key": protocol.B64(v.Public), "issuer_key_id": v.Issuer, "descriptor": protocol.B64(v.Descriptor), "descriptor_signature": protocol.B64(v.Signature), "issued_count": format(v.Issued), "accepted_count": format(v.Accepted)}
}
func (s *Server) reviewRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/member/orgs/{org}/reviews", s.listReviews)
	m.HandleFunc("POST /api/member/orgs/{org}/reviews", s.createReview)
	m.HandleFunc("GET /api/member/reviews/{id}", s.getReview)
	m.HandleFunc("PUT /api/member/reviews/{id}", s.updateReview)
	m.HandleFunc("DELETE /api/member/reviews/{id}", s.deleteReview)
	m.HandleFunc("POST /api/member/reviews/{id}/publish", s.publish)
	m.HandleFunc("POST /api/member/reviews/{id}/close", s.closeReview)
	m.HandleFunc("POST /api/member/reviews/{id}/issuances", s.issue)
	m.HandleFunc("GET /api/member/reviews/{id}/issuances/{request}", s.getIssuance)
	m.HandleFunc("GET /api/member/reviews/{id}/submissions", s.submissions)
}
func (s *Server) loadReview(r *http.Request, a *session, creator bool) (*review, error) {
	v, e := scanReview(s.member.QueryRow(r.Context(), "SELECT "+reviewColumns+" FROM member.reviews r WHERE r.id=$1", r.PathValue("id")))
	if e != nil {
		return nil, problem{404, "not_found"}
	}
	if _, e = s.membership(r, a, v.Org, false); e != nil {
		return nil, e
	}
	if (creator || v.State == "draft") && v.Account != a.Account {
		return nil, problem{403, "forbidden"}
	}
	return v, nil
}
func (s *Server) getReview(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, a, false)
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, v.view())
}
func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = s.membership(r, a, r.PathValue("org"), false); e != nil {
		fail(w, e)
		return
	}
	rows, e := s.member.Query(r.Context(), "SELECT "+reviewColumns+" FROM member.reviews r WHERE r.org_id=$1 AND (r.state<>'draft' OR r.account_id=$2) AND r.id>$3 ORDER BY r.id LIMIT 51", r.PathValue("org"), a.Account, r.URL.Query().Get("after"))
	if e != nil {
		fail(w, e)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	var next any
	for rows.Next() {
		v, e := scanReview(rows)
		if e != nil {
			fail(w, e)
			return
		}
		if len(items) == 50 {
			next = items[49]["id"]
			break
		}
		items = append(items, v.view())
	}
	write(w, 200, map[string]any{"items": items, "next": next})
}
func (s *Server) createReview(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string `json:"request_id"`
		Title   string `json:"title"`
		Max     int64  `json:"max_responses"`
	}
	x, e := s.verify(r, "review-create", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	member, e := s.membership(r, x.Session, r.PathValue("org"), false)
	if e != nil {
		fail(w, e)
		return
	}
	if p.Max == 0 {
		p.Max = 1
	}
	if p.Max < 1 || p.Max > 100 || len(p.Title) < 1 || len(p.Title) > 300 {
		fail(w, bad("invalid_review"))
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
	key, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		fail(w, e)
		return
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		fail(w, e)
		return
	}
	id := protocol.ID()
	priv, e := s.crypt("issuer/"+id, x509.MarshalPKCS1PrivateKey(key), false)
	if e != nil {
		fail(w, e)
		return
	}
	v := &review{ID: id, Org: r.PathValue("org"), Account: x.Session.Account, Membership: member, Issuer: protocol.B64(protocol.Hash(pub)), State: "draft", Draft: draft{p.Title, "", []question{}}, Revision: 1, Max: p.Max, Public: pub}
	b, _ := json.Marshal(v.Draft)
	_, e = tx.Exec(r.Context(), "INSERT INTO member.reviews(id,org_id,account_id,membership_id,draft,issuer_private,issuer_public,issuer_key_id,max_responses,opens_at,closes_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", id, v.Org, v.Account, member, b, priv, pub, v.Issuer, p.Max, v.Opens, v.Closes)
	if e == nil {
		e = cache(r, tx, x, p.Request, v.view())
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 201, v.view())
}
func validDraft(d draft) bool {
	if len(d.Title) < 1 || len(d.Title) > 300 || len(d.Description) > 10000 || len(d.Questions) < 1 || len(d.Questions) > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, q := range d.Questions {
		if q.ID == "" || len(q.ID) > 100 || seen[q.ID] || len(q.Label) < 1 || len(q.Label) > 2000 {
			return false
		}
		seen[q.ID] = true
		if q.Type != "text" && q.Type != "single" && q.Type != "multiple" {
			return false
		}
		if q.Type == "text" && len(q.Choices) != 0 {
			return false
		}
		if q.Type != "text" && (len(q.Choices) < 2 || len(q.Choices) > 100) {
			return false
		}
		cs := map[string]bool{}
		for _, c := range q.Choices {
			if c.ID == "" || len(c.ID) > 100 || cs[c.ID] || len(c.Label) < 1 || len(c.Label) > 1000 {
				return false
			}
			cs[c.ID] = true
		}
	}
	return true
}
func (s *Server) updateReview(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request     string     `json:"request_id"`
		Expected    string     `json:"expected_revision"`
		Title       string     `json:"title"`
		Description string     `json:"description"`
		Questions   []question `json:"questions"`
		Max         int64      `json:"max_responses"`
		Opens       *string    `json:"opens_at"`
		Closes      *string    `json:"closes_at"`
	}
	x, e := s.verify(r, "review-update", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, x.Session, true)
	if e != nil {
		fail(w, e)
		return
	}
	rev, e := decimal(p.Expected)
	opens, oe := nullableDecimal(p.Opens)
	closes, ce := nullableDecimal(p.Closes)
	d := draft{p.Title, p.Description, p.Questions}
	if e != nil || oe != nil || ce != nil || (closes != nil && opens != nil && *closes <= *opens) || p.Max < 1 || p.Max > 100 || !validDraft(d) {
		fail(w, bad("invalid_review"))
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
	b, _ := json.Marshal(d)
	tag, e := tx.Exec(r.Context(), "UPDATE member.reviews SET draft=$1,max_responses=$2,opens_at=$3,closes_at=$4,revision=revision+1 WHERE id=$5 AND revision=$6 AND state='draft'", b, p.Max, opens, closes, v.ID, rev)
	if e == nil && tag.RowsAffected() != 1 {
		e = problem{409, "revision_conflict"}
	}
	v.Draft, v.Max, v.Opens, v.Closes, v.Revision = d, p.Max, opens, closes, rev+1
	if e == nil {
		e = cache(r, tx, x, p.Request, v.view())
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, v.view())
}

type revisionRequest struct {
	Request  string `json:"request_id"`
	Expected string `json:"expected_revision"`
}

func (s *Server) deleteReview(w http.ResponseWriter, r *http.Request) { s.reviewState(w, r, true) }
func (s *Server) closeReview(w http.ResponseWriter, r *http.Request)  { s.reviewState(w, r, false) }
func (s *Server) reviewState(w http.ResponseWriter, r *http.Request, del bool) {
	action := "review-close"
	if del {
		action = "review-delete"
	}
	var p revisionRequest
	x, e := s.verify(r, action, &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, x.Session, true)
	if e != nil {
		fail(w, e)
		return
	}
	rev, e := decimal(p.Expected)
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
	var tag interface{ RowsAffected() int64 }
	if del {
		tag, e = tx.Exec(r.Context(), "DELETE FROM member.reviews WHERE id=$1 AND revision=$2 AND state='draft'", v.ID, rev)
	} else {
		tag, e = tx.Exec(r.Context(), "UPDATE member.reviews SET state='closed',revision=revision+1 WHERE id=$1 AND revision=$2 AND state='published'", v.ID, rev)
		if e == nil {
			_, e = tx.Exec(r.Context(), "UPDATE anon.reviews SET state='closed' WHERE id=$1", v.ID)
		}
	}
	if e == nil && tag.RowsAffected() != 1 {
		e = problem{409, "revision_conflict"}
	}
	result := map[string]any{"id": v.ID, "state": "closed", "revision": format(rev + 1), "deleted": del}
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

type descriptor struct {
	V           int        `json:"v"`
	Deployment  string     `json:"deployment_id"`
	Review      string     `json:"review_id"`
	Org         string     `json:"org_id"`
	Account     string     `json:"reviewer_account_id"`
	Membership  string     `json:"reviewer_membership_id"`
	Certificate string     `json:"reviewer_certificate"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Questions   []question `json:"questions"`
	Recipient   string     `json:"recipient_public_key"`
	Issuer      string     `json:"issuer_key_id"`
	Public      string     `json:"issuer_public_key"`
	Max         int64      `json:"max_responses"`
	Opens       *string    `json:"opens_at"`
	Closes      *string    `json:"closes_at"`
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request    string     `json:"request_id"`
		Expected   string     `json:"expected_revision"`
		Descriptor string     `json:"descriptor"`
		Signature  string     `json:"descriptor_signature"`
		Vault      vaultWrite `json:"vault_write"`
	}
	x, e := s.verify(r, "review-publish", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, x.Session, true)
	if e != nil {
		fail(w, e)
		return
	}
	rev, e := decimal(p.Expected)
	if e != nil {
		fail(w, e)
		return
	}
	b, e := protocol.Decode(p.Descriptor, -1)
	if e != nil {
		fail(w, bad("invalid_descriptor"))
		return
	}
	var d descriptor
	if e = protocol.StrictJSON(b, &d); e != nil {
		fail(w, bad("invalid_descriptor"))
		return
	}
	var cert string
	if e = s.member.QueryRow(r.Context(), "SELECT certificate FROM member.memberships WHERE id=$1 AND state='approved'", v.Membership).Scan(&cert); e != nil {
		fail(w, problem{403, "forbidden"})
		return
	}
	db, _ := json.Marshal(v.Draft)
	incoming, _ := json.Marshal(draft{d.Title, d.Description, d.Questions})
	_, recipientErr := protocol.Decode(d.Recipient, 32)
	sig, se := protocol.Decode(p.Signature, 64)
	if d.V != 1 || d.Deployment != protocol.B64(s.deployment) || d.Review != v.ID || d.Org != v.Org || d.Account != v.Account || d.Membership != v.Membership || d.Certificate != cert || !equal(db, incoming) || d.Public != protocol.B64(v.Public) || d.Issuer != v.Issuer || d.Max != v.Max || !sameNullable(d.Opens, v.Opens) || !sameNullable(d.Closes, v.Closes) || recipientErr != nil || se != nil || !s.validCertificate(cert, x.Session.Membership, v.Org, v.Membership) || !validDraft(v.Draft) || !checkSig(x.Session.Membership, p.Signature, protocol.E("review-descriptor", b)) {
		fail(w, bad("descriptor_mismatch"))
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
	tag, e := tx.Exec(r.Context(), "UPDATE member.reviews SET state='published',revision=revision+1,descriptor=$1,descriptor_signature=$2 WHERE id=$3 AND revision=$4 AND state='draft'", b, sig, v.ID, rev)
	if e == nil && tag.RowsAffected() != 1 {
		e = problem{409, "revision_conflict"}
	}
	if e == nil {
		e = saveObject(r, tx, x.Session.Account, p.Vault)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "INSERT INTO anon.reviews(id,issuer_key_id,issuer_public,descriptor,descriptor_hash,descriptor_signature,state,opens_at,closes_at) VALUES($1,$2,$3,$4,$5,$6,'published',$7,$8)", v.ID, v.Issuer, v.Public, b, protocol.Hash(b), sig, v.Opens, v.Closes)
	}
	v.State, v.Revision, v.Descriptor, v.Signature = "published", rev+1, b, sig
	if e == nil {
		e = cache(r, tx, x, p.Request, v.view())
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, v.view())
}
func (s *Server) issue(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request string     `json:"request_id"`
		Issuer  string     `json:"issuer_key_id"`
		Blinded string     `json:"blinded_message"`
		Pending vaultWrite `json:"pending_state"`
	}
	x, e := s.verify(r, "issue", &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	if _, e = protocol.Decode(p.Request, 16); e != nil {
		fail(w, bad("invalid_request"))
		return
	}
	blind, e := protocol.Decode(p.Blinded, 384)
	if e != nil {
		fail(w, bad("invalid_blinded_message"))
		return
	}
	v, e := s.loadReview(r, x.Session, false)
	if e != nil {
		fail(w, e)
		return
	}
	member, e := s.membership(r, x.Session, v.Org, false)
	if e != nil {
		fail(w, e)
		return
	}
	if p.Issuer != v.Issuer {
		fail(w, bad("issuer_mismatch"))
		return
	}
	tx, e := s.member.Begin(r.Context())
	if e != nil {
		fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	var state string
	var epoch int64
	if e = tx.QueryRow(r.Context(), "SELECT epoch FROM member.accounts WHERE id=$1 FOR UPDATE", x.Account).Scan(&epoch); e != nil {
		fail(w, e)
		return
	}
	if epoch != x.Epoch {
		fail(w, problem{401, "session_revoked"})
		return
	}
	if e = transactionAuthorization(r, tx, x); e != nil {
		fail(w, e)
		return
	}
	var opens, closes *int64
	var max int64
	if e = tx.QueryRow(r.Context(), "SELECT state,opens_at,closes_at,max_responses FROM member.reviews WHERE id=$1 FOR UPDATE", v.ID).Scan(&state, &opens, &closes, &max); e != nil {
		fail(w, e)
		return
	}
	var active, cert string
	if e = tx.QueryRow(r.Context(), "SELECT state,COALESCE(certificate,'') FROM member.memberships WHERE id=$1 FOR SHARE", member).Scan(&active, &cert); e != nil || active != "approved" || !s.validCertificate(cert, x.Session.Membership, v.Org, member) {
		fail(w, problem{403, "invalid_membership"})
		return
	}
	var oldHash, signature []byte
	var pending json.RawMessage
	e = tx.QueryRow(r.Context(), "SELECT request_hash,blind_signature,pending_object FROM member.issuances WHERE review_id=$1 AND membership_id=$2 AND request_id=$3", v.ID, member, p.Request).Scan(&oldHash, &signature, &pending)
	if e == nil {
		if !equal(oldHash, protocol.Hash(x.Payload)) {
			fail(w, problem{409, "request_conflict"})
			return
		}
		write(w, 200, map[string]any{"request_id": p.Request, "blind_signature": protocol.B64(signature), "pending_state": pending})
		return
	}
	if e != pgx.ErrNoRows {
		fail(w, e)
		return
	}
	if e = consumeChallenge(r, tx, x); e != nil {
		fail(w, e)
		return
	}
	now := time.Now().Unix()
	if state != "published" || (opens != nil && now < *opens) || (closes != nil && now >= *closes) {
		fail(w, problem{410, "closed"})
		return
	}
	var count int64
	if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM member.issuances WHERE review_id=$1 AND membership_id=$2", v.ID, member).Scan(&count); e != nil {
		fail(w, e)
		return
	}
	if count >= max {
		fail(w, problem{409, "quota_exhausted"})
		return
	}
	priv, e := s.crypt("issuer/"+v.ID, v.Private, true)
	if e != nil {
		fail(w, e)
		return
	}
	key, e := x509.ParsePKCS1PrivateKey(priv)
	if e != nil {
		fail(w, e)
		return
	}
	signature, e = blindrsa.NewSigner(key).BlindSign(blind)
	if e != nil {
		fail(w, bad("invalid_blinded_message"))
		return
	}
	if e = saveObject(r, tx, x.Session.Account, p.Pending); e == nil {
		pending, _ = json.Marshal(p.Pending.Object)
		_, e = tx.Exec(r.Context(), "INSERT INTO member.issuances VALUES($1,$2,$3,$4,$5,$6,$7)", v.ID, member, p.Request, protocol.Hash(x.Payload), signature, pending, count+1)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "UPDATE member.reviews SET issued_count=issued_count+1 WHERE id=$1", v.ID)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, map[string]any{"request_id": p.Request, "blind_signature": protocol.B64(signature), "pending_state": pending})
}
func (s *Server) validCertificate(cert string, pub []byte, org, member string) bool {
	b, e := protocol.Decode(cert, -1)
	if e != nil {
		return false
	}
	c, e := x509.ParseCertificate(b)
	if e != nil {
		return false
	}
	raw, ok := c.PublicKey.(ed25519.PublicKey)
	parent, e := x509.ParseCertificate(s.caDER)
	if e != nil {
		return false
	}
	if c.CheckSignatureFrom(parent) != nil || time.Now().Before(parent.NotBefore) || time.Now().After(parent.NotAfter) || len(c.URIs) != 1 || c.URIs[0].String() != "urn:anonce:deployment:"+protocol.B64(s.deployment)+":org:"+org+":member:"+member {
		return false
	}
	return ok && equal(raw, pub) && !c.IsCA && c.KeyUsage&x509.KeyUsageDigitalSignature != 0 && time.Now().Before(c.NotAfter) && time.Now().After(c.NotBefore)
}
func (s *Server) getIssuance(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, a, false)
	if e != nil {
		fail(w, e)
		return
	}
	member, e := s.membership(r, a, v.Org, false)
	if e != nil {
		fail(w, e)
		return
	}
	var sig []byte
	var pending json.RawMessage
	e = s.member.QueryRow(r.Context(), "SELECT blind_signature,pending_object FROM member.issuances WHERE review_id=$1 AND membership_id=$2 AND request_id=$3", v.ID, member, r.PathValue("request")).Scan(&sig, &pending)
	if e != nil {
		fail(w, problem{404, "not_found"})
		return
	}
	write(w, 200, map[string]any{"request_id": r.PathValue("request"), "blind_signature": protocol.B64(sig), "pending_state": pending})
}
func (s *Server) submissions(w http.ResponseWriter, r *http.Request) {
	a, e := s.session(r)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := s.loadReview(r, a, true)
	if e != nil {
		fail(w, e)
		return
	}
	rows, e := s.member.Query(r.Context(), "SELECT enc,ciphertext,receipt FROM anon.submissions WHERE review_id=$1 AND receipt->>'receipt_id'>$2 ORDER BY receipt->>'receipt_id' LIMIT 51", v.ID, r.URL.Query().Get("after"))
	if e != nil {
		fail(w, e)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	var next any
	for rows.Next() {
		var enc, ct []byte
		var receipt map[string]any
		if e = rows.Scan(&enc, &ct, &receipt); e != nil {
			fail(w, e)
			return
		}
		if len(items) == 50 {
			next = items[49]["id"]
			break
		}
		items = append(items, map[string]any{"id": receipt["receipt_id"], "enc": protocol.B64(enc), "ciphertext": protocol.B64(ct), "receipt": receipt})
	}
	write(w, 200, map[string]any{"items": items, "next": next})
}

func nullableFormat(n *int64) any {
	if n == nil {
		return nil
	}
	return format(*n)
}
func nullableDecimal(s *string) (*int64, error) {
	if s == nil {
		return nil, nil
	}
	n, e := decimal(*s)
	return &n, e
}
func sameNullable(s *string, n *int64) bool {
	if s == nil || n == nil {
		return s == nil && n == nil
	}
	return *s == format(*n)
}
