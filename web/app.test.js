// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import * as app from './app.js';
test('required service entry points are exported',()=>{
  for(const name of ['register','login','recover','getSession','logout','changePassword','rotateRecovery','publishReview','prepareResponse','submitResponse','lookupReceipt','listResponses','exportResponses']) assert.equal(typeof app[name],'function',name);
});
test('source link has a safe HTTPS fallback before initialization',()=>{
  assert.equal(app.getSourceURL(),'https://github.com/mandipnotroot/anonce-platform');
  assert.equal(new URL(app.getSourceURL()).protocol,'https:');
});
test('invalid export format fails before accessing secrets',async()=>{
  await assert.rejects(app.exportResponses({reviewId:'x',format:'html'}),e=>e.code==='INVALID_FORMAT');
});
test('review pagination transmits an encoded cursor',async()=>{
  let requested;
  globalThis.fetch=async(path)=>{requested=path;return {ok:true,status:200,json:async()=>({items:[],next:null})};};
  assert.deepEqual(await app.listReviews({orgId:'organization',after:'cursor/+?'}),{items:[],next:null});
  assert.equal(requested,'/api/member/orgs/organization/reviews?after=cursor%2F%2B%3F');
});
