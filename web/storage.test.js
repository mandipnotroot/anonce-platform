// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {putEncrypted} from './storage.js';
test('plaintext cannot enter encrypted record store',()=>{
  assert.throws(()=>putEncrypted('key',{seed:'secret'}),/Only encrypted/);
});
