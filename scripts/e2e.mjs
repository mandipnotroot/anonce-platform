// SPDX-License-Identifier: AGPL-3.0-only
// Opt-in real-browser integration test; targets an already-running HTTPS service.
// Install Playwright in the test environment, not the production dependency set.
import assert from 'node:assert/strict';
const origin=process.env.ANONCE_E2E_ORIGIN;
if(!origin)throw new Error('Set ANONCE_E2E_ORIGIN to a disposable HTTPS deployment.');
if(!origin.startsWith('https://'))throw new Error('E2E requires HTTPS for Secure session cookies.');
const allowSelfSigned=process.env.ANONCE_E2E_ALLOW_SELF_SIGNED==='1';
if(allowSelfSigned&&!['localhost','127.0.0.1','[::1]'].includes(new URL(origin).hostname))throw new Error('Self-signed TLS bypass is restricted to loopback origins.');
const contextOptions={ignoreHTTPSErrors:allowSelfSigned};
const {chromium}=await import('playwright');
const browser=await chromium.launch({headless:true});
const observe=page=>page.on('response',async response=>{
  if(response.status()>=400&&new URL(response.url()).pathname.startsWith('/api/')) {
    const body=await response.json().catch(()=>null);
    console.error('API failure',response.request().method(),new URL(response.url()).pathname,response.status(),body?.error?.code||'non-JSON error');
  }
});
try {
  const page=await browser.newPage(contextOptions);
  observe(page);
  await page.goto(origin+'/#/register');
  const email=`e2e-${Date.now()}-${Math.random().toString(16).slice(2)}@example.net`;
  const password=crypto.randomUUID()+crypto.randomUUID();
  await page.getByLabel('Email address',{exact:true}).fill(email);
  await page.getByLabel('Password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Create account',exact:true}).click();
  await page.locator('#saved').waitFor();
  assert.equal(await page.locator('.word-grid .word').count(),12);
  const originalReviewerWords=await page.locator('.word-grid .word').evaluateAll(nodes=>nodes.map(node=>[...node.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join('').trim()));
  assert.equal(await page.locator('#continue').isDisabled(),true);
  await page.locator('#saved').check();await page.locator('#continue').click();
  await page.evaluate(async()=>{await (await import('/app.js')).createOrganization({name:'E2E encrypted workspace'});});
  await page.reload();
  assert.equal(await page.evaluate(async()=>Boolean(await (await import('/app.js')).getSession())),true,'device cache survives reload');
  await page.evaluate(async()=>{const app=await import('/app.js');const orgs=await app.listOrganizations();if(!orgs.items.length)throw Error('Organization missing');await app.logout();});
  await page.reload();
  await page.evaluate(async({email,password})=>{const app=await import('/app.js');await app.login({email,password});await app.changePassword({currentPassword:password,newPassword:password+'-rotated'});await app.logout();},{email,password});
  const reviewer=page;
  await reviewer.evaluate(async({email,password})=>{await (await import('/app.js')).login({email,password:password+'-rotated'});},{email,password});
  const orgId=await reviewer.evaluate(async()=>{const a=await import('/app.js');return (await a.listOrganizations()).items[0].id;});
  const token=await reviewer.evaluate(async orgId=>(await (await import('/app.js')).createInvite({orgId,role:'respondent',expiresAt:String(Math.floor(Date.now()/1000)+3600)})).token,orgId);
  const respondentContext=await browser.newContext(contextOptions), respondent=await respondentContext.newPage();await respondent.goto(origin);
  observe(respondent);
  const respondentEmail=email.replace('@','-respondent@');
  const words=await respondent.evaluate(async({email,password,token})=>{const a=await import('/app.js');const r=await a.register({email,password});await a.acceptInvite({token});return r.recoveryWords;},{email:respondentEmail,password,token});
  await reviewer.evaluate(async orgId=>{const a=await import('/app.js');for(const m of (await a.listMembers({orgId})).items)if(m.status==='pending'||m.state==='pending')await a.approveMember({orgId,memberId:m.id});},orgId);
  const reviewId=await reviewer.evaluate(async orgId=>{
    const a=await import('/app.js');let r=await a.createReview({orgId,title:'E2E anonymous feedback',maxResponses:2});
    r=await a.updateReview({reviewId:r.id,expectedRevision:r.revision,title:r.title,description:'Disposable integration review',maxResponses:2,opensAt:null,closesAt:null,
      questions:[{text:'Your thoughts?',type:'text',required:true,options:[]},{text:'Choose one',type:'single',required:true,options:['One','Two']},{text:'Choose several',type:'multiple',required:true,options:['Red','Blue']}]});
    await a.publishReview({reviewId:r.id,expectedRevision:r.revision});return r.id;
  },orgId);
  let issuanceCount=0;const sent=[];
  respondent.on('request',req=>{if(req.url().endsWith('/issuances')&&req.method()==='POST')issuanceCount++;});
  let dropped=false;
  await respondent.route('**/api/anon/submissions',async route=>{
    const req=route.request(),headers=await req.allHeaders();
    assert.equal(headers.cookie,undefined);assert.equal(headers.authorization,undefined);assert.equal(headers['x-csrf-token'],undefined);
    sent.push(req.postData());
    if(!dropped){dropped=true;const upstream=await route.fetch();assert.equal(upstream.ok(),true);await route.abort('failed');}
    else await route.continue();
  });
  // UI journey: open the published response page and submit all question types.
  await respondent.goto(origin+'/#respond/'+reviewId);
  await respondent.locator('#answer-0').fill('Private browser response');
  await respondent.getByLabel('One',{exact:true}).check();await respondent.getByLabel('Red',{exact:true}).check();
  await respondent.getByRole('button',{name:'Send response',exact:true}).click();
  await respondent.waitForFunction(()=>document.querySelector('#respond button[type=submit]')?.disabled===false);
  await respondent.waitForFunction(async()=>{const a=await import('/app.js');return (await a.listPendingResponses()).items.length>0;});
  const recoveredReceipt=await respondent.evaluate(async()=>{const a=await import('/app.js');const p=(await a.listPendingResponses()).items[0];return a.submitResponse({pendingId:p.pendingId});});
  assert.equal(recoveredReceipt.status,'accepted');assert.equal(issuanceCount,1);assert.equal(sent.length,2);assert.equal(sent[0],sent[1]);
  await reviewer.evaluate(async reviewId=>{const a=await import('/app.js');const result=await a.listResponses({reviewId});if(result.items[0].answers[0].value!=='Private browser response')throw Error('Plaintext mismatch');const exported=await a.exportResponses({reviewId,format:'csv'});if(!(await exported.blob.text()).includes('Private browser response'))throw Error('Export mismatch');},reviewId);
  const recoveryContext=await browser.newContext(contextOptions),recoveryPage=await recoveryContext.newPage();await recoveryPage.goto(origin);
  observe(recoveryPage);
  await recoveryPage.evaluate(async({email,words,newPassword})=>{const a=await import('/app.js');const r=await a.recover({email,words:words.join(' '),newPassword});if(r.recoveryWords.length!==12)throw Error('Fresh recovery phrase missing');},{email:respondentEmail,words,newPassword:password+'-recovered'});
  // Reviewer recovery must also preserve decryption of the old recipient key.
  await recoveryPage.evaluate(async({email,words,newPassword,reviewId})=>{const a=await import('/app.js');await a.logout();await a.recover({email,words:words.join(' '),newPassword});if(!(await a.listResponses({reviewId})).items.length)throw Error('Recovered reviewer cannot decrypt');},{email,words:originalReviewerWords,newPassword:password+'-recovered',reviewId});
  console.log('PASS: two-context membership, publish, UI response, lost-reply exact retry, receipt, plaintext/export, reload unlock and cross-device recovery');
} finally {await browser.close();}
