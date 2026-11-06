-- SPDX-License-Identifier: AGPL-3.0-only
CREATE SCHEMA IF NOT EXISTS member;
CREATE SCHEMA IF NOT EXISTS anon;
CREATE TABLE member.settings (name text PRIMARY KEY, value bytea NOT NULL);
CREATE TABLE member.accounts (
 id text PRIMARY KEY, email text UNIQUE NOT NULL CHECK(octet_length(email)<=254 AND email=lower(btrim(email))), password_public bytea NOT NULL, recovery_public bytea NOT NULL,
 membership_public bytea NOT NULL, encryption_public bytea NOT NULL CHECK(octet_length(encryption_public)=32), encryption_key_signature bytea NOT NULL CHECK(octet_length(encryption_key_signature)=64), password_kdf jsonb NOT NULL, recovery_salt text NOT NULL,
 vault jsonb NOT NULL, epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0)
);
CREATE TABLE member.sessions (id_hash bytea PRIMARY KEY, account_id text NOT NULL REFERENCES member.accounts(id), scope text NOT NULL CHECK(scope IN ('full','recovery')), epoch bigint NOT NULL, csrf text NOT NULL, expires_at timestamptz NOT NULL);
CREATE FUNCTION member.immutable_account_keys() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.membership_public IS DISTINCT FROM OLD.membership_public OR NEW.encryption_public IS DISTINCT FROM OLD.encryption_public OR NEW.encryption_key_signature IS DISTINCT FROM OLD.encryption_key_signature THEN
  RAISE EXCEPTION 'account identity keys are immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_account_keys BEFORE UPDATE ON member.accounts FOR EACH ROW EXECUTE FUNCTION member.immutable_account_keys();
CREATE TABLE member.challenges (id text PRIMARY KEY, account_id text NOT NULL, action text NOT NULL, epoch bigint NOT NULL, payload_hash bytea NOT NULL, nonce bytea NOT NULL, expires bigint NOT NULL, session_hash bytea);
CREATE TABLE member.vault_objects (account_id text REFERENCES member.accounts(id), id text NOT NULL, revision bigint NOT NULL, object jsonb NOT NULL, PRIMARY KEY(account_id,id));
CREATE TABLE member.orgs (id text PRIMARY KEY, name text NOT NULL);
CREATE TABLE member.memberships (id text PRIMARY KEY, org_id text REFERENCES member.orgs(id), account_id text REFERENCES member.accounts(id), role text NOT NULL CHECK(role IN ('owner','admin','reviewer','respondent')), state text NOT NULL CHECK(state IN ('pending','approved','revoked')), certificate text, UNIQUE(org_id,account_id));
CREATE TABLE member.invites (id_hash bytea PRIMARY KEY, org_id text REFERENCES member.orgs(id), expires_at timestamptz NOT NULL);
CREATE TABLE member.reviews (id text PRIMARY KEY, org_id text REFERENCES member.orgs(id), account_id text REFERENCES member.accounts(id), membership_id text REFERENCES member.memberships(id), encrypted_content jsonb NOT NULL, issuer_private bytea NOT NULL, issuer_public bytea NOT NULL, issuer_key_id text NOT NULL, state text NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','published','closed')), revision bigint NOT NULL DEFAULT 1, max_responses integer NOT NULL CHECK(max_responses BETWEEN 1 AND 100), opens_at bigint, closes_at bigint, descriptor bytea, descriptor_signature bytea, issued_count bigint NOT NULL DEFAULT 0);
CREATE TABLE member.operations(account_id text NOT NULL REFERENCES member.accounts(id), request_id text NOT NULL, payload_hash bytea NOT NULL, result jsonb NOT NULL, PRIMARY KEY(account_id,request_id));
CREATE TABLE member.review_content_keys (review_id text NOT NULL REFERENCES member.reviews(id), membership_id text NOT NULL REFERENCES member.memberships(id), encryption_key_id bytea NOT NULL CHECK(octet_length(encryption_key_id)=32), enc bytea NOT NULL CHECK(octet_length(enc)=32), ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)=48), PRIMARY KEY(review_id,membership_id));
CREATE TABLE member.issuances (review_id text REFERENCES member.reviews(id), membership_id text REFERENCES member.memberships(id), request_id text NOT NULL, request_hash bytea NOT NULL, blind_signature bytea NOT NULL, pending_object jsonb NOT NULL, slot integer NOT NULL CHECK(slot>0), PRIMARY KEY(review_id,membership_id,request_id), UNIQUE(review_id,membership_id,slot));
CREATE TABLE anon.reviews (id text PRIMARY KEY, issuer_key_id text NOT NULL, issuer_public bytea NOT NULL, descriptor bytea NOT NULL, descriptor_hash bytea NOT NULL, descriptor_signature bytea NOT NULL, state text NOT NULL CHECK(state IN ('published','closed')), opens_at bigint, closes_at bigint, accepted_count bigint NOT NULL DEFAULT 0);
CREATE TABLE anon.submissions (review_id text NOT NULL REFERENCES anon.reviews(id), issuer_key_id text NOT NULL, token_hash bytea NOT NULL, submission_hash bytea NOT NULL, prepared_message bytea NOT NULL, signature bytea NOT NULL, enc bytea NOT NULL CHECK(octet_length(enc)=32), ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 16 AND 262144), receipt jsonb NOT NULL, PRIMARY KEY(review_id,issuer_key_id,token_hash));
REVOKE ALL ON SCHEMA member FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA member FROM PUBLIC;
REVOKE ALL ON SCHEMA anon FROM PUBLIC;
-- The restricted role can inspect only published cryptographic context and execute a
-- bounded atomic write. It cannot mutate reviews or read member-side data.
GRANT USAGE ON SCHEMA anon TO anonce_anon;
GRANT SELECT ON anon.reviews TO anonce_anon;
GRANT SELECT ON anon.submissions TO anonce_anon;
CREATE FUNCTION anon.accept_submission(p_review text,p_issuer text,p_token bytea,p_hash bytea,p_prepared bytea,p_signature bytea,p_enc bytea,p_ciphertext bytea,p_receipt jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,anon AS $$
DECLARE r anon.reviews; old anon.submissions; now_epoch bigint;
BEGIN
 SELECT * INTO r FROM anon.reviews WHERE id=p_review FOR UPDATE;
 IF NOT FOUND OR r.issuer_key_id<>p_issuer THEN RAISE EXCEPTION 'review not found' USING ERRCODE='P0002'; END IF;
 SELECT * INTO old FROM anon.submissions WHERE review_id=p_review AND issuer_key_id=p_issuer AND token_hash=p_token;
 IF FOUND THEN
   IF old.submission_hash=p_hash THEN RETURN old.receipt; END IF;
   RAISE EXCEPTION 'token spent' USING ERRCODE='23505';
 END IF;
 now_epoch:=extract(epoch FROM clock_timestamp())::bigint;
 IF r.state<>'published' OR (r.opens_at IS NOT NULL AND now_epoch<r.opens_at) OR (r.closes_at IS NOT NULL AND now_epoch>=r.closes_at) THEN RAISE EXCEPTION 'review closed' USING ERRCODE='55000'; END IF;
 IF octet_length(p_token)<>32 OR octet_length(p_hash)<>32 OR octet_length(p_prepared)>1024 OR octet_length(p_signature)<>384 OR octet_length(p_receipt::text)>4096 THEN RAISE EXCEPTION 'invalid submission'; END IF;
 INSERT INTO anon.submissions VALUES(p_review,p_issuer,p_token,p_hash,p_prepared,p_signature,p_enc,p_ciphertext,p_receipt);
 UPDATE anon.reviews SET accepted_count=accepted_count+1 WHERE id=p_review;
 RETURN p_receipt;
END $$;
REVOKE ALL ON FUNCTION anon.accept_submission(text,text,bytea,bytea,bytea,bytea,bytea,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION anon.accept_submission(text,text,bytea,bytea,bytea,bytea,bytea,bytea,jsonb) TO anonce_anon;
