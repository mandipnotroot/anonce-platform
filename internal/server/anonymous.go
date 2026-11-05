// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) publicReview(w http.ResponseWriter, r *http.Request) {
	var state string
	var desc, sig []byte
	if e := s.anonymous.QueryRow(r.Context(), "SELECT state,descriptor,descriptor_signature FROM anon.reviews WHERE id=$1", r.PathValue("id")).Scan(&state, &desc, &sig); e != nil {
		fail(w, problem{404, "not_found"})
		return
	}
	write(w, 200, map[string]string{"state": state, "descriptor": protocol.B64(desc), "descriptor_signature": protocol.B64(sig)})
}

type submission struct {
	Review     string `json:"review_id"`
	Issuer     string `json:"issuer_key_id"`
	Prepared   string `json:"prepared_message"`
	Signature  string `json:"signature"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	var p submission
	if e := body(r, &p); e != nil {
		fail(w, e)
		return
	}
	if _, e := protocol.Decode(p.Review, 16); e != nil {
		fail(w, bad("invalid_review"))
		return
	}
	rid, _ := protocol.Decode(p.Review, 16)
	kid, e := protocol.Decode(p.Issuer, 32)
	if e != nil {
		fail(w, bad("invalid_issuer"))
		return
	}
	prepared, e := protocol.Decode(p.Prepared, -1)
	if e != nil || len(prepared) > 1024 {
		fail(w, bad("invalid_message"))
		return
	}
	sig, e := protocol.Decode(p.Signature, 384)
	if e != nil {
		fail(w, bad("invalid_signature"))
		return
	}
	enc, e := protocol.Decode(p.Enc, 32)
	if e != nil {
		fail(w, bad("invalid_enc"))
		return
	}
	ct, e := protocol.Decode(p.Ciphertext, -1)
	if e != nil || len(ct) < 16 || len(ct) > 262144 {
		fail(w, bad("invalid_ciphertext"))
		return
	}
	var pub, dh []byte
	var issuer string
	if e = s.anonymous.QueryRow(r.Context(), "SELECT issuer_public,descriptor_hash,issuer_key_id FROM anon.reviews WHERE id=$1", p.Review).Scan(&pub, &dh, &issuer); e != nil {
		fail(w, problem{404, "not_found"})
		return
	}
	key, e := x509.ParsePKIXPublicKey(pub)
	if e != nil {
		fail(w, e)
		return
	}
	pk, ok := key.(*rsa.PublicKey)
	if !ok || pk.N.BitLen() != 3072 || issuer != p.Issuer {
		fail(w, bad("invalid_issuer"))
		return
	}
	prefix := protocol.E("authorization", s.deployment, rid, dh, kid, make([]byte, 32))
	if len(prepared) != 32+len(prefix) {
		fail(w, bad("invalid_authorization"))
		return
	}
	serial := prepared[len(prepared)-32:]
	expected := protocol.E("authorization", s.deployment, rid, dh, kid, serial)
	if !bytes.Equal(prepared[32:], expected) {
		fail(w, bad("invalid_authorization"))
		return
	}
	v, e := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, pk)
	if e != nil {
		fail(w, e)
		return
	}
	if e = v.Verify(prepared, sig); e != nil {
		fail(w, bad("invalid_signature"))
		return
	}
	th := protocol.Hash(protocol.E("token", rid, kid, serial))
	sh := protocol.Hash(protocol.E("submission", rid, kid, prepared, sig, enc, ct))
	receiptID := protocol.Random(16)
	now := uint64(time.Now().Unix())
	signature := ed25519.Sign(s.receipt, protocol.E("receipt", s.deployment, receiptID, rid, kid, th, sh, protocol.U64(now), s.receiptID))
	receipt := map[string]any{"v": 1, "receipt_id": protocol.B64(receiptID), "review_id": p.Review, "issuer_key_id": p.Issuer, "token_hash": protocol.B64(th), "submission_hash": protocol.B64(sh), "accepted_at": strconv.FormatUint(now, 10), "receipt_key_id": protocol.B64(s.receiptID), "signature": protocol.B64(signature)}
	b, _ := json.Marshal(receipt)
	var result json.RawMessage
	e = s.anonymous.QueryRow(r.Context(), "SELECT anon.accept_submission($1,$2,$3,$4,$5,$6,$7,$8,$9)", p.Review, p.Issuer, th, sh, prepared, sig, enc, ct, b).Scan(&result)
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, result)
}
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Review string `json:"review_id"`
		Issuer string `json:"issuer_key_id"`
		Serial string `json:"serial"`
	}
	if e := body(r, &p); e != nil {
		fail(w, e)
		return
	}
	rid, e := protocol.Decode(p.Review, 16)
	if e != nil {
		fail(w, bad("invalid_review"))
		return
	}
	kid, e := protocol.Decode(p.Issuer, 32)
	if e != nil {
		fail(w, bad("invalid_issuer"))
		return
	}
	serial, e := protocol.Decode(p.Serial, 32)
	if e != nil {
		fail(w, bad("invalid_serial"))
		return
	}
	th := protocol.Hash(protocol.E("token", rid, kid, serial))
	var result json.RawMessage
	e = s.anonymous.QueryRow(r.Context(), "SELECT receipt FROM anon.submissions WHERE review_id=$1 AND issuer_key_id=$2 AND token_hash=$3", p.Review, p.Issuer, th).Scan(&result)
	if e == pgx.ErrNoRows {
		fail(w, problem{404, "not_found"})
		return
	}
	if e != nil {
		fail(w, e)
		return
	}
	write(w, 200, result)
}
