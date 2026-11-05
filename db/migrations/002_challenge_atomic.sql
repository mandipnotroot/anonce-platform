-- SPDX-License-Identifier: AGPL-3.0-only
ALTER TABLE member.challenges ADD COLUMN used boolean NOT NULL DEFAULT false;
