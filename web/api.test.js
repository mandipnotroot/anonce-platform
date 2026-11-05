// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {request,setCSRF,toWire} from './api.js';
test('anonymous transport cannot carry session or CSRF',async()=>{
  setCSRF('secret');let options;
  globalThis.fetch=async(path,o)=>{options=o;return {ok:true,status:200,json:async()=>({ok:true})};};
  await request('/api/anon/submissions',{method:'POST',body:{x:1},anonymous:true});
  assert.equal(options.credentials,'omit');assert.equal(options.headers['X-CSRF-Token'],undefined);
  assert.equal(options.redirect,'error');assert.equal(options.referrerPolicy,'no-referrer');
});
test('member mutations carry CSRF and binary wire encodes',async()=>{
  let options;globalThis.fetch=async(path,o)=>{options=o;return {ok:true,status:204};};
  await request('/api/member/session',{method:'DELETE'});
  assert.equal(options.credentials,'same-origin');assert.equal(options.headers['X-CSRF-Token'],'secret');
  assert.equal(options.headers['Content-Type'],'application/json');
  assert.deepEqual(toWire({data:new Uint8Array([255])}),{data:'_w'});
});
test('network and remote errors never echo sensitive messages',async()=>{
  globalThis.fetch=async()=>{throw Error('private');};
  await assert.rejects(request('/api/member/me'),e=>e.code==='NETWORK_ERROR'&&!e.message.includes('private'));
  globalThis.fetch=async()=>({status:403,ok:false,json:async()=>({error:{code:'FORBIDDEN',message:'private'}})});
  await assert.rejects(request('/api/member/me'),e=>e.code==='FORBIDDEN'&&!e.message.includes('private'));
});
