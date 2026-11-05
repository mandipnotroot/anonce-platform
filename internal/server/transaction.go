// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"github.com/jackc/pgx/v5"
	"net/http"
)

func consumeChallenge(r *http.Request, tx pgx.Tx, x *verified) error {
	if x.Epoch > 0 {
		var epoch int64
		if e := tx.QueryRow(r.Context(), "SELECT epoch FROM member.accounts WHERE id=$1 FOR UPDATE", x.Account).Scan(&epoch); e != nil {
			return e
		}
		if epoch != x.Epoch {
			return problem{401, "session_revoked"}
		}
	}
	if x.Session != nil {
		var valid bool
		if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM member.sessions WHERE id_hash=$1 AND account_id=$2 AND epoch=$3 AND expires_at>now())", x.Session.Hash, x.Account, x.Epoch).Scan(&valid); e != nil {
			return e
		}
		if !valid {
			return problem{401, "session_revoked"}
		}
	}
	tag, e := tx.Exec(r.Context(), "UPDATE member.challenges SET used=true WHERE id=$1 AND NOT used AND expires>=extract(epoch FROM clock_timestamp())::bigint", x.Proof.Challenge)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return problem{409, "challenge_used"}
	}
	return nil
}
