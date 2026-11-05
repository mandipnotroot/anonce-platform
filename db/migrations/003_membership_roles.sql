-- SPDX-License-Identifier: AGPL-3.0-only
ALTER TABLE member.memberships DROP CONSTRAINT memberships_role_check;
UPDATE member.memberships SET role='respondent' WHERE role='member';
ALTER TABLE member.memberships ADD CONSTRAINT memberships_role_check CHECK(role IN ('owner','reviewer','respondent'));
ALTER TABLE member.invites ADD COLUMN role text NOT NULL DEFAULT 'respondent' CHECK(role IN ('reviewer','respondent'));
