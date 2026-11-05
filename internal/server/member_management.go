// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http"
)

func authorizeTarget(r *http.Request, tx pgx.Tx, x *verified, target string, appointment bool) error {
	var actor string
	if e := tx.QueryRow(r.Context(), "SELECT role FROM member.memberships WHERE org_id=$1 AND account_id=$2 AND state='approved'", r.PathValue("org"), x.Session.Account).Scan(&actor); e != nil {
		return problem{403, "forbidden"}
	}
	if target == "owner" && appointment || actor != "owner" && (actor != "admin" || target == "admin" || target == "owner" || appointment) {
		return problem{403, "forbidden"}
	}
	return nil
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request)  { s.manageMember(w, r, false) }
func (s *Server) memberRole(w http.ResponseWriter, r *http.Request) { s.manageMember(w, r, true) }

func (s *Server) manageMember(w http.ResponseWriter, r *http.Request, appointment bool) {
	var p struct {
		Request string `json:"request_id"`
		Email   string `json:"email,omitempty"`
		Role    string `json:"role"`
	}
	action := "member-add"
	if appointment {
		action = "member-role"
	}
	x, e := s.verify(r, action, &p, false)
	if e != nil {
		fail(w, e)
		return
	}
	if p.Role != "admin" && p.Role != "reviewer" && p.Role != "respondent" {
		fail(w, bad("invalid_role"))
		return
	}
	if appointment && p.Email != "" {
		fail(w, bad("invalid_payload"))
		return
	}
	if !appointment {
		p.Email, e = normalizeEmail(p.Email)
		if e != nil {
			fail(w, e)
			return
		}
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
	if e = authorizeTarget(r, tx, x, p.Role, appointment); e != nil {
		fail(w, e)
		return
	}
	if old != nil {
		write(w, 200, old)
		return
	}
	org, id := r.PathValue("org"), r.PathValue("member")
	var account, email, role, state, cert string
	var pub []byte
	if appointment {
		e = tx.QueryRow(r.Context(), "SELECT m.account_id,a.email,m.role,m.state,COALESCE(m.certificate,'') FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id WHERE m.org_id=$1 AND m.id=$2 FOR UPDATE OF m", org, id).Scan(&account, &email, &role, &state, &cert)
		if e != nil {
			fail(w, problem{404, "not_found"})
			return
		}
		if e = authorizeTarget(r, tx, x, role, true); e != nil {
			fail(w, e)
			return
		}
		if state != "approved" {
			fail(w, problem{409, "not_approved"})
			return
		}
		_, e = tx.Exec(r.Context(), "UPDATE member.memberships SET role=$1 WHERE id=$2", p.Role, id)
	} else {
		e = tx.QueryRow(r.Context(), "SELECT id,email,membership_public FROM member.accounts WHERE email=$1", p.Email).Scan(&account, &email, &pub)
		if e == pgx.ErrNoRows {
			fail(w, problem{404, "account_not_found"})
			return
		}
		if e != nil {
			fail(w, e)
			return
		}
		e = tx.QueryRow(r.Context(), "SELECT id,role,state FROM member.memberships WHERE org_id=$1 AND account_id=$2 FOR UPDATE", org, account).Scan(&id, &role, &state)
		if e != nil && e != pgx.ErrNoRows {
			fail(w, e)
			return
		}
		if e == nil {
			if role == "owner" {
				fail(w, problem{403, "forbidden"})
				return
			}
			if state != "revoked" {
				fail(w, problem{409, "already_member"})
				return
			}
			if e = authorizeTarget(r, tx, x, role, false); e != nil {
				fail(w, e)
				return
			}
		} else {
			id = protocol.ID()
		}
		cert, e = s.cert(org, id, pub)
		if e != nil {
			fail(w, e)
			return
		}
		var tag pgconn.CommandTag
		if state == "revoked" {
			tag, e = tx.Exec(r.Context(), "UPDATE member.memberships SET role=$1,state='approved',certificate=$2 WHERE id=$3 AND state='revoked'", p.Role, cert, id)
		} else {
			tag, e = tx.Exec(r.Context(), "INSERT INTO member.memberships(id,org_id,account_id,role,state,certificate) VALUES($1,$2,$3,$4,'approved',$5) ON CONFLICT(org_id,account_id) DO NOTHING", id, org, account, p.Role, cert)
		}
		if e == nil && tag.RowsAffected() != 1 {
			e = problem{409, "already_member"}
		}
	}
	result := map[string]string{"id": id, "account_id": account, "email": email, "role": p.Role, "state": "approved", "status": "approved", "certificate": cert}
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
	status := 201
	if appointment {
		status = 200
	}
	write(w, status, result)
}
