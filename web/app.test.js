// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import * as app from './app.js';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

// Run the service with inert providers, without loading cryptographic dependencies.
async function service(overrides={}) {
  const source=(await readFile(new URL('./app.js',import.meta.url),'utf8'))
    .replace(/^import .*;$/gm,'').replace(/\bexport /g,'');
  const wire=value=>JSON.parse(JSON.stringify(value,(_,v)=>v instanceof Uint8Array?Buffer.from(v).toString('base64url'):v));
  class MockAPIError extends Error {constructor(code,message){super(message);this.code=code;}}
  const context=vm.createContext({Uint8Array,TextDecoder,Blob,URL,APIError:MockAPIError,
    jsonBytes:value=>new TextEncoder().encode(JSON.stringify(value)),toWire:wire,
    C:{fromBase64url:value=>new Uint8Array(Buffer.from(value,'base64url')),toBase64url:value=>Buffer.from(value).toString('base64url'),...overrides.C},
    request:overrides.request||(()=>{throw Error('Unexpected request');}),
    loadSealed:overrides.loadSealed,saveSealed:overrides.saveSealed|| (async()=>{}),
  });
  vm.runInContext(source+`;state={accountId:'YQ',masterKey:new Uint8Array(32)};
    globalThis.service={sealIssuancePending,finishPending,local,listResponses,exportResponses};
    globalThis.setSigned=value=>{signed=value;};`,context);
  return context;
}

test('issuance padding has fixed byte length, whitespace roundtrip, and fits request limits',async()=>{
  const sealed=[];
  const context=await service({C:{sealVaultObject:async options=>{sealed.push(options);return {ciphertext:Buffer.alloc(options.plaintext.length+16).toString('base64url')};}}});
  for(const length of [0,1,1024,262144]) {
    const pending={pendingId:'Yg',descriptor:Buffer.alloc(65536).toString('base64url'),encrypted:{ciphertext:Buffer.alloc(length).toString('base64url')},answer:'日本語'};
    const object=await context.service.sealIssuancePending(pending);
    const options=sealed.at(-1);
    assert.equal(options.plaintext.length,524288);
    assert.equal(options.revision,'1');
    assert.deepEqual(JSON.parse(new TextDecoder().decode(options.plaintext)),pending);
    assert.equal(options.plaintext.at(-1),32);
    assert.ok(Buffer.byteLength(object.ciphertext)<1048576);
    const payload=JSON.stringify({pending_state:{expected_revision:'0',object}});
    assert.ok(Buffer.byteLength(payload)<=1536*1024);
    assert.ok(Buffer.byteLength(JSON.stringify({payload:Buffer.from(payload).toString('base64url'),proof:{}}))<=2304*1024);
  }
  await assert.rejects(context.service.sealIssuancePending({pendingId:'Yg',value:'x'.repeat(524288)}),e=>e.code==='INVALID_RESPONSE'&&!e.message.includes('xxxxx'));
  assert.equal(sealed.length,4);
});

test('issuance retries and reload preserve the exact sealed payload',async()=>{
  let seals=0,saved;
  const payloads=[];
  const context=await service({C:{verifyDescriptor:async()=>({org_id:'org',issuer_key_id:'issuer'}),
    sealVaultObject:async()=>({id:'Yg',ciphertext:'sealed-'+(++seals)})},
    request:async()=>({}),saveSealed:async({value})=>{saved=JSON.parse(JSON.stringify(value));}});
  context.setSigned(async(_path,_action,payload)=>{payloads.push(JSON.stringify(payload));throw Error('retry');});
  const pending={pendingId:'Yg',reviewId:'Yw',requestId:'request',descriptor:'e30',descriptorSignature:'',authorization:{blindedMessage:'YQ'},encrypted:{ciphertext:'YQ'},revision:1};
  await assert.rejects(context.service.finishPending(pending),/retry/);
  await assert.rejects(context.service.finishPending(pending),/retry/);
  await assert.rejects(context.service.finishPending(saved),/retry/);
  assert.equal(seals,1);
  assert.equal(new Set(payloads).size,1);
});

test('remote recovery restores exact issuance bytes after JSONB key reordering',async()=>{
  const descriptor={org_id:'org',issuer_key_id:'issuer'};
  const pending={pendingId:'Yg',reviewId:'Yw',requestId:'request',
    descriptor:Buffer.from(JSON.stringify(descriptor)).toString('base64url'),descriptorSignature:'',
    authorization:{blindedMessage:'YQ'},encrypted:{ciphertext:'YQ'},revision:1};
  const object={v:1,id:'Yg',revision:'1',nonce:'bm9uY2U',ciphertext:'Y2lwaGVydGV4dA'};
  // PostgreSQL JSONB may return a different key order from the sealing provider.
  const remoteObject={id:object.id,v:object.v,nonce:object.nonce,ciphertext:object.ciphertext,revision:object.revision};
  const payloads=[];
  let seals=0;
  const context=await service({C:{verifyDescriptor:async()=>descriptor,
    sealVaultObject:async()=>{seals++;return object;},
    openVaultObject:async({object:received})=>{
      assert.equal(received,remoteObject);
      return new TextEncoder().encode(JSON.stringify(pending));
    }},loadSealed:async()=>undefined,
    request:async path=>path==='/api/member/vault'?{objects:[remoteObject]}:{}});
  context.setSigned(async(_path,_action,payload)=>{payloads.push(JSON.stringify(payload));throw Error('retry');});
  // The remote object contains the issuance-time pending plaintext, before issuancePayload exists.
  const original=JSON.parse(JSON.stringify(pending));
  await assert.rejects(context.service.finishPending(original),/retry/);
  const recovered=await context.service.local(pending.pendingId);
  await assert.rejects(context.service.finishPending(recovered),/retry/);
  assert.equal(seals,1,'remote recovery must not re-encrypt');
  assert.equal(payloads.length,2);
  assert.equal(payloads[1],payloads[0]);
  assert.deepEqual(JSON.parse(JSON.stringify(recovered.issuancePayload.pending_state.object)),object);
});

async function responseService({networkFailure=false,keyFailure=false,descriptorFailure=false}={}) {
  return service({C:{verifyDescriptor:async()=>{if(descriptorFailure)throw Error('descriptor');return {questions:[{id:'q',type:'text',choices:[]}]};},
    openVaultObject:async()=>{if(keyFailure)throw Error('key');return new TextEncoder().encode(JSON.stringify({kind:'recipient',reviewId:'Yw',privateKey:'YQ'}));},
    decryptResponse:async({ciphertext})=>{if(ciphertext[0]===2)throw Error('raw secret provider error');if(ciphertext[0]===3)return {answers:null};return {answers:{q:'good answer'}};}},
    request:async path=>{
      if(path.startsWith('/api/public/'))return {descriptor:'e30',descriptor_signature:''};
      if(path==='/api/member/vault')return {objects:[{}]};
      if(networkFailure)throw Error('network');
      return {items:[1,2,3].map(n=>({id:String(n),accepted_at:'today',enc:'YQ',ciphertext:Buffer.from([n]).toString('base64url')})),next:null};
    }});
}

test('mixed responses retain readable answers and report unreadable records in JSON and CSV',async()=>{
  const context=await responseService();
  const result=JSON.parse(JSON.stringify(await context.service.listResponses({reviewId:'Yw'})));
  assert.equal(result.items[0].status,'valid');
  assert.equal(result.items[0].answers[0].value,'good answer');
  for(const item of result.items.slice(1))assert.deepEqual(item,{id:item.id,acceptedAt:'today',status:'invalid',error:'RESPONSE_UNREADABLE',answers:[]});
  for(const format of ['json','csv']) {
    const exported=await context.service.exportResponses({reviewId:'Yw',format});
    const content=await exported.blob.text();
    assert.ok(content.includes('good answer'));
    assert.equal((content.match(/RESPONSE_UNREADABLE/g)||[]).length,2);
    assert.ok(!content.includes('raw secret'));
    if(format==='json')assert.equal(JSON.parse(content).length,3);
    else {assert.ok(content.startsWith('response_id,accepted_at,status,error,question_id,value'));assert.equal(content.split('\r\n').length,4);}
  }
});

test('response listing does not hide network, key, or descriptor failures',async()=>{
  for(const [option,message] of [['networkFailure','network'],['keyFailure','key'],['descriptorFailure','descriptor']]) {
    const context=await responseService({[option]:true});
    await assert.rejects(context.service.listResponses({reviewId:'Yw'}),new RegExp(message));
  }
});
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
