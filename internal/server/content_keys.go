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

func (v contentKeyEnvelope) valid() bool {
	_, a := protocol.Decode(v.Membership, 16)
	_, b := protocol.Decode(v.Key, 32)
	enc, c := protocol.Decode(v.Enc, 32)
	_, d := protocol.Decode(v.Ciphertext, 48)
	return v.V == 1 && a == nil && b == nil && c == nil && d == nil && usableX25519(enc)
}

func saveContentKeys(r *http.Request, tx pgx.Tx, v *review, envelopes []contentKeyEnvelope) error {
	rows, err := tx.Query(r.Context(), "SELECT m.id,a.encryption_public FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id WHERE m.org_id=$1 AND m.state='approved'", v.Org)
	if err != nil {
		return err
	}
	roster := map[string]string{}
	for rows.Next() {
		var id string
		var public []byte
		if err = rows.Scan(&id, &public); err != nil {
			rows.Close()
			return err
		}
		roster[id] = protocol.B64(protocol.Hash(public))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(roster) != len(envelopes) {
		return problem{409, "recipient_set_conflict"}
	}
	for _, envelope := range envelopes {
		if !envelope.valid() {
			return bad("invalid_content_key_envelope")
		}
		if key, ok := roster[envelope.Membership]; !ok || key != envelope.Key {
			return problem{409, "recipient_set_conflict"}
		}
		delete(roster, envelope.Membership)
	}
	for _, envelope := range envelopes {
		_, err = tx.Exec(r.Context(), "INSERT INTO member.review_content_keys(review_id,membership_id,encryption_key_id,enc,ciphertext) VALUES($1,$2,$3,$4,$5)", v.ID, envelope.Membership, mustDecode(envelope.Key), mustDecode(envelope.Enc), mustDecode(envelope.Ciphertext))
		if err != nil {
			return err
		}
	}
	return nil
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
	rows, err := s.member.Query(r.Context(), `SELECT m.id,m.account_id,m.certificate,a.encryption_public,a.encryption_key_signature FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id WHERE m.org_id=$1 AND m.state='approved' AND m.id COLLATE "C">$2 COLLATE "C" ORDER BY m.id COLLATE "C" LIMIT 101`, v.Org, after)
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
