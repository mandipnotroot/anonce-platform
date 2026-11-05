-- SPDX-License-Identifier: AGPL-3.0-only
ALTER TABLE member.invites ADD COLUMN role text NOT NULL DEFAULT 'respondent' CHECK(role IN ('reviewer','respondent'));
