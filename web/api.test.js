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
test('remote error envelopes give safe specific context and HTTP fallback',async()=>{
  for (const payload of [
    {error:{code:'FORBIDDEN',message:'private'}},
    {error:{code:{detail:'secret'},message:{detail:'secret'}}},
    {code:{detail:'secret'}},
  ]) {
    globalThis.fetch=async()=>({status:403,ok:false,json:async()=>payload});
    await assert.rejects(request('/api/member/me'),e=>typeof e.message==='string'&&!e.message.includes('[object Object]')&&!e.message.includes('secret'));
  }
  globalThis.fetch=async()=>({status:429,ok:false,json:async()=>({error:{code:'RATE_LIMITED'}})});
  await assert.rejects(request('/api/member/me'),e=>e.message==='Too many attempts. Wait a moment, then try again.');
  globalThis.fetch=async()=>({status:401,ok:false,json:async()=>({error:{code:'invalid_credentials'}})});
  await assert.rejects(request('/api/member/me'),e=>e.message==='Login or password is incorrect.');
  for (const [status,message] of [[400,/Check the information/],[403,/do not have permission/],[409,/changed or conflicts/],[410,/expired or closed/],[429,/Too many attempts/],[503,/temporarily unavailable/]]) {
    globalThis.fetch=async()=>({status,ok:false,json:async()=>({error:{code:'unknown_code'}})});
    await assert.rejects(request('/api/member/me'),e=>message.test(e.message));
  }
  globalThis.fetch=async()=>({status:502,ok:false,json:async()=>({error:{message:{raw:'private'}}})});
  await assert.rejects(request('/api/member/me'),e=>e.message==='Service is temporarily unavailable. Try again shortly.');
  globalThis.fetch=async()=>({status:502,ok:false,json:async()=>{throw new Error('not JSON');}});
  await assert.rejects(request('/api/member/me'),e=>e.message.includes('temporarily unavailable')&&!e.message.includes('not JSON'));
});
