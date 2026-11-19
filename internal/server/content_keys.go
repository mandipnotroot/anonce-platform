// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func usableX25519(raw []byte) bool {
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	_, err = private.ECDH(public)
	return err == nil
}

func (s *Server) registrationEncryption(p registration, membership []byte) ([]byte, error) {
	public, err := protocol.Decode(p.Encryption, 32)
	account, accountErr := protocol.Decode(p.Account, 16)
	if err != nil || accountErr != nil || !usableX25519(public) || equal(public, membership) || !checkSig(membership, p.EncryptionSignature, protocol.E("member-encryption-key", s.deployment, account, membership, public, protocol.U64(1))) {
		return nil, bad("invalid_registration")
	}
	return public, nil
}

type contentKeyEnvelope struct {
	V          int    `json:"v"`
	Membership string `json:"membership_id"`
	Key        string `json:"encryption_key_id"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
}

// Bound the snapshot side before joining identity keys, including when planner
// statistics have not yet caught up with a newly frozen large roster.
const frozenRecipientPageSQL = `WITH page AS MATERIALIZED (
 SELECT membership_id FROM member.publication_recipients
 WHERE publication_id=$1 AND membership_id>$2 COLLATE "C" ORDER BY membership_id LIMIT 101
)
SELECT p.membership_id,p.account_id,p.certificate,a.encryption_public,a.encryption_key_signature
FROM page b CROSS JOIN LATERAL (
 SELECT membership_id,account_id,certificate FROM member.publication_recipients
 WHERE publication_id=$1 AND membership_id=b.membership_id OFFSET 0
) p CROSS JOIN LATERAL (
 SELECT encryption_public,encryption_key_signature FROM member.accounts WHERE id=p.account_id OFFSET 0
) a ORDER BY p.membership_id`

func (v contentKeyEnvelope) valid() bool {
	_, a := protocol.Decode(v.Membership, 16)
	_, b := protocol.Decode(v.Key, 32)
	enc, c := protocol.Decode(v.Enc, 32)
	_, d := protocol.Decode(v.Ciphertext, 48)
	return v.V == 1 && a == nil && b == nil && c == nil && d == nil && usableX25519(enc)
}

func (s *Server) contentRecipients(w http.ResponseWriter, r *http.Request) {
	a, err := s.session(r)
	if err != nil {
		fail(w, err)
		return
	}
	v, err := s.loadReview(r, a, true)
	if err != nil {
		fail(w, err)
		return
	}
	after := r.URL.Query().Get("after")
	if after != "" {
		if _, err = protocol.Decode(after, 16); err != nil {
			fail(w, bad("invalid_cursor"))
			return
		}
	}
	publication := r.URL.Query().Get("publication_id")
	if _, err = protocol.Decode(publication, 16); err != nil {
		fail(w, bad("invalid_publication"))
		return
	}
	var valid bool
	err = s.member.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM member.review_publications WHERE review_id=$1 AND id=$2 AND revision=$3 AND expires_at>now())", v.ID, publication, v.Revision).Scan(&valid)
	if err != nil {
		fail(w, err)
		return
	}
	if !valid || v.State != "draft" {
		fail(w, problem{409, "publication_conflict"})
		return
	}
	rows, err := s.member.Query(r.Context(), frozenRecipientPageSQL, publication, after)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	var next any
	for rows.Next() {
		var id, account, cert string
		var public, signature []byte
		if err = rows.Scan(&id, &account, &cert, &public, &signature); err != nil {
			fail(w, err)
			return
		}
		if len(items) == 100 {
			next = items[99]["membership_id"]
			break
		}
		items = append(items, map[string]any{"membership_id": id, "account_id": account, "certificate": cert, "encryption_public_key": protocol.B64(public), "encryption_key_signature": protocol.B64(signature)})
	}
	if err = rows.Err(); err != nil {
		fail(w, err)
		return
	}
	write(w, 200, map[string]any{"items": items, "next": next})
}

func (s *Server) reviewView(r *http.Request, v *review, account string) (map[string]any, error) {
	result := v.view(account)
	if v.State == "draft" {
		return result, nil
	}
	var id string
	var key, enc, ciphertext []byte
	err := s.member.QueryRow(r.Context(), "SELECT k.membership_id,k.encryption_key_id,k.enc,k.ciphertext FROM member.review_content_keys k JOIN member.memberships m ON m.id=k.membership_id WHERE k.review_id=$1 AND m.account_id=$2 AND m.org_id=$3 AND m.state='approved'", v.ID, account, v.Org).Scan(&id, &key, &enc, &ciphertext)
	if err == pgx.ErrNoRows {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	result["content_key_envelope"] = contentKeyEnvelope{1, id, protocol.B64(key), protocol.B64(enc), protocol.B64(ciphertext)}
	return result, nil
}
