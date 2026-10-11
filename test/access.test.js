import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createApp, configuration } from '../server.js';
import { bandFromDob, bandAllows } from '../extension/lib/age.js';
import { verifyCredential } from '../extension/lib/credential.js';
import { siteForUrl, baselineRules, admissionRule } from '../extension/lib/policy.js';
import { ageLabelFromDob, dateFromOcr } from '../public/ocr.js';

const sites = JSON.parse(fs.readFileSync(new URL('../extension/site-ratings.json', import.meta.url)));
const day = new Date('2026-10-10T00:00:00Z');
for (const [dob, expected] of [
  ['2018-10-10','under13'], ['2013-10-11','under13'], ['2013-10-10','13to15'],
  ['2010-10-11','13to15'], ['2010-10-10','16to17'], ['2008-10-11','16to17'],
  ['2008-10-10','18plus'], ['2027-01-01',null], ['2025-02-29',null], ['not-a-date',null]
]) test('Birthday boundary: ' + dob, () => assert.equal(bandFromDob(dob, day), expected));
test('OCR detects DOB across common labels and US/European date formats',()=>{
  const today=new Date('2026-10-10T00:00:00Z');
  assert.equal(dateFromOcr('D0B: 04/12/1988\nISS 09/05/2022\nEXP 09/05/2028',today),'1988-04-12');
  assert.equal(dateFromOcr('DATE OF B1RTH\n04 12 1988',today),'1988-04-12');
  assert.equal(dateFromOcr('BIRTH DATE 23.01.1988',today),'1988-01-23');
  assert.equal(dateFromOcr('DOB: April 12, 1988',today),'1988-04-12');
});
test('OCR fallback ignores issue/expiry labels and selects the earliest plausible DOB',()=>{
  assert.equal(dateFromOcr('ISSUED 09/05/2022\nEXPIRES 09/05/2028\n07/14/1988',new Date('2026-10-10T00:00:00Z')),'1988-07-14');
  assert.equal(dateFromOcr('DOB 02/30/1988',new Date('2026-10-10T00:00:00Z')),'');
});
test('OCR result labels adulthood as an estimate, not verification',()=>{
  const today=new Date('2026-10-10T00:00:00Z');
  assert.equal(ageLabelFromDob('1990-01-01',today),'Adult (18+)');
  assert.equal(ageLabelFromDob('2013-10-10',today),'13–15');
  assert.equal(ageLabelFromDob('2020-01-01',today),'Under 13');
  assert.equal(ageLabelFromDob('not-a-date',today),'');
});
for (const [band, outcomes] of [
  ['under13',[false,false,false]], ['13to15',[true,false,false]],
  ['16to17',[true,true,false]], ['18plus',[true,true,true]]
]) test('Access matrix: ' + band, () => assert.deepEqual([13,16,18].map(min => bandAllows(band,min)),outcomes));
test('Domains match subdomains but reject lookalikes and URL credentials', () => {
  assert.equal(siteForUrl(sites,'https://old.reddit.com/r/test').id,'reddit');
  for (const url of ['https://reddit.com.attacker.net/', 'https://notreddit.com/', 'https://reddit.com@attacker.net/', 'https://user@reddit.com/', 'javascript:alert(1)']) assert.equal(siteForUrl(sites,url),null);
});
test('Navigation admission is limited to one exact URL and browser tab', () => {
  const target='https://example.org/path?a=1&b=two';
  const rule=admissionRule(7,target), match=new RegExp(rule.condition.regexFilter);
  assert.equal(match.test(target),true);
  assert.equal(match.test(target+'x'),false);
  assert.equal(match.test('https://example.org/another'),false);
  assert.deepEqual(rule.condition.tabIds,[7]);
});
test('Shipped static rules agree with the rating list', () => {
  const actual=JSON.parse(fs.readFileSync(new URL('../extension/rules.json',import.meta.url)));
  assert.deepEqual(actual,baselineRules(sites));
});
test('Every rated platform and alias has a canonical URL and Chrome permission', () => {
  const manifest=JSON.parse(fs.readFileSync(new URL('../extension/manifest.json',import.meta.url)));
  for (const site of sites) {
    assert.equal(siteForUrl(sites,site.url)?.id,site.id);
    for (const domain of site.domains) {
      assert.ok(manifest.host_permissions.includes('*://*.'+domain+'/*'),domain);
      assert.equal(siteForUrl(sites,'https://www.'+domain+'/')?.id,site.id);
    }
  }
  for (const name of ['youtube','instagram','tiktok','reddit','x']) assert.ok(sites.some(site=>site.id===name));
});

const issuer=crypto.generateKeyPairSync('ec',{namedCurve:'P-256'});
const device=crypto.generateKeyPairSync('ec',{namedCurve:'P-256'});
const stranger=crypto.generateKeyPairSync('ec',{namedCurve:'P-256'});
const pub=device.publicKey.export({format:'jwk'});
const uid='11111111-1111-4111-8111-111111111111';
const childUid='22222222-2222-4222-8222-222222222222';
const ocrUid='33333333-3333-4333-8333-333333333333';
let now=day.getTime(), dob='1990-01-01', profile=true, childProfile=false, ocrProfile=null, server, origin;
const config=configuration({SUPABASE_URL:'https://fixture.supabase.co',SUPABASE_ANON_KEY:'sb_publishable_test_fixture',ADMIN_TOKEN:'test-admin-token',DEMO_VERIFICATION:'true'});
const fakeSupabase=async (url,options) => {
  if (url.endsWith('/auth/v1/user')) {
    const id=options.headers.authorization==='Bearer authenticated-test-user'?uid:options.headers.authorization==='Bearer child-test-user'?childUid:options.headers.authorization==='Bearer ocr-test-user'?ocrUid:null;
    return new Response(JSON.stringify(id?{id}:{error:'no'}),{status:id?200:401});
  }
  if (url.endsWith('/rest/v1/rpc/profile_service_ready')) return new Response('true');
  if (url.endsWith('/rest/v1/rpc/set_child_profile')) {
    if (options.headers.authorization==='Bearer authenticated-test-user' && profile) {
      return new Response(JSON.stringify({message:'verified_profile_immutable'}),{status:400});
    }
    childProfile=options.headers.authorization==='Bearer child-test-user';
    return new Response('true');
  }
  if (url.endsWith('/rest/v1/rpc/save_ocr_birth_date')) {
    if (options.headers.authorization==='Bearer authenticated-test-user' && profile) {
      return new Response(JSON.stringify({message:'verified_profile_immutable'}),{status:400});
    }
    const input=JSON.parse(options.body);
    ocrProfile={id:ocrUid,birth_date:input.p_birth_date,verified_at:null,access_tier:'ocr_unverified'};
    return new Response('true');
  }
  if (url.includes('/rest/v1/profiles?') && options.method!=='POST') {
    assert.equal(options.headers.apikey,config.supabaseKey);
    if (url.includes('id=eq.'+ocrUid)) return new Response(JSON.stringify(ocrProfile?[ocrProfile]:[]));
    const child=url.includes('id=eq.'+childUid);
    const exists=child?childProfile:profile;
    return new Response(JSON.stringify(exists ? [{birth_date:child?null:dob,verified_at:child?null:'2026-10-01T12:00:00Z',access_tier:child?'child':'verified'}] : []));
  }
  throw new Error('Unexpected external request in isolated test.');
};
before(async () => {
  server=createApp({config,fetchImpl:fakeSupabase,issuerKey:issuer.privateKey,revokedFile:null,verificationFile:null,clock:()=>now});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  origin='http://127.0.0.1:'+server.address().port;
});
after(async()=>{await new Promise(resolve=>server.close(resolve));});
async function call(route,input,authenticated=false,admin=false) {
  const response=await fetch(origin+route,{method:input===undefined?'GET':'POST',headers:{'content-type':'application/json',...(authenticated?{authorization:'Bearer '+(typeof authenticated==='string'?authenticated:'authenticated-test-user')}:{ }),...(admin?{'x-admin-token':'test-admin-token'}:{})},body:input===undefined?undefined:JSON.stringify(input)});
  return {status:response.status,value:await response.json()};
}
async function enroll(birth='1990-01-01',authenticated=true) { if (birth) dob=birth; return (await call('/enroll',{pub},authenticated)).value; }
async function proof(credential,key=device) {
  const {value:{nonce}}=await call('/challenge');
  return {credential,nonce,signature:crypto.sign('sha256',Buffer.from(nonce),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')};
}
test('No account, no verified profile, and self-declared age all fail closed',async()=>{
  assert.equal((await call('/enroll',{pub})).status,401);
  profile=false; assert.equal((await call('/enroll',{pub},true)).status,403); profile=true;
  for (const addition of [{dob:'1990-01-01'},{band:'18plus'}]) assert.equal((await call('/enroll',{pub,...addition},true)).status,400);
});
test('No-ID choice receives an Under 13 pass and cannot replace an ID-verified profile',async()=>{
  assert.deepEqual((await call('/profile/child',{},'child-test-user')).value,{child:true,band:'under13'});
  assert.equal((await call('/verify/status',undefined,'child-test-user')).value.child,true);
  const credential=await enroll(undefined,'child-test-user');
  assert.equal(JSON.parse(credential.payload).band,'under13');
  assert.equal((await call('/profile/child',{},true)).status,409);
});
test('OCR DOB is stored as unverified and cannot issue an age pass',async()=>{
  assert.equal((await call('/profile/ocr',{dob:'2000-01-01'})).status,401);
  assert.equal((await call('/profile/ocr',{dob:'2000-02-30'},'ocr-test-user')).status,400);
  assert.equal((await call('/profile/ocr',{dob:'2000-01-01'},true)).status,409);
  const saved=await call('/profile/ocr',{dob:'2000-01-01'},'ocr-test-user');
  assert.deepEqual(saved.value,{saved:true,verified:false,access_tier:'ocr_unverified'});
  assert.equal(ocrProfile.birth_date,'2000-01-01');
  assert.equal(ocrProfile.verified_at,null);
  const status=await call('/verify/status',undefined,'ocr-test-user');
  assert.equal(status.value.verified,false);
  assert.equal(status.value.ocr_birth_date,'2000-01-01');
  assert.equal((await call('/enroll',{pub},'ocr-test-user')).status,403);
});
test('Demo verification is authenticated, explicitly simulated, and never verified',async()=>{
  assert.equal((await call('/demo/verify',{dob:'1990-01-01'})).status,401);
  const demo=await call('/demo/verify',{dob:'1990-01-01'},true);
  assert.deepEqual(demo.value,{demo:true,simulated_decision:'approved',band:'18plus',verified:false,age_pass_issued:false});
  assert.equal(ocrProfile?.verified_at,null);
  assert.equal(configuration({SUPABASE_URL:'https://fixture.supabase.co',SUPABASE_ANON_KEY:'sb_publishable_test_fixture',DEMO_VERIFICATION:'true',NODE_ENV:'production'}).demoVerification,false);
});
test('All four bands are derived from protected verified profiles',async()=>{
  for (const [birth,band] of [['2018-10-10','under13'],['2013-10-10','13to15'],['2010-10-10','16to17'],['2008-10-10','18plus']]) assert.equal(JSON.parse((await enroll(birth)).payload).band,band);
});
test('Real issuer signature interoperates with browser Web Crypto and excludes DOB/account',async()=>{
  const credential=await enroll();
  const parsed=await verifyCredential(credential,issuer.publicKey.export({format:'jwk'}),pub,now);
  assert.equal(parsed.band,'18plus');
  assert.equal(credential.payload.includes(dob),false);
  assert.equal(credential.payload.includes(uid),false);
  assert.equal((await call('/credential/check',await proof(credential))).status,200);
});
test('Replay, stolen-device credential, edited pass, expiry, and revocation are rejected',async()=>{
  const credential=await enroll(), captured=await proof(credential);
  assert.equal((await call('/credential/check',captured)).status,200);
  assert.equal((await call('/credential/check',captured)).status,401);
  assert.equal((await call('/credential/check',await proof(credential,stranger))).status,401);
  const edited={...credential,payload:credential.payload.replace('18plus','16to17')};
  assert.equal((await call('/credential/check',await proof(edited))).status,401);
  now+=3_600_000; assert.equal((await call('/credential/check',await proof(credential))).status,401); now=day.getTime();
  assert.equal((await call('/revoke',{id:JSON.parse(credential.payload).id})).status,403);
  assert.equal((await call('/revoke',{id:JSON.parse(credential.payload).id},false,true)).status,200);
  assert.equal((await call('/credential/check',await proof(credential))).status,401);
});
test('Legacy content endpoint still enforces 18+ and a fresh device proof',async()=>{
  assert.equal((await call('/content',await proof(await enroll('2013-10-10')))).status,403);
  assert.equal((await call('/content',await proof(await enroll()))).status,200);
});
test('Unconfigured automatic verification stays blocked; public config never returns server secrets',async()=>{
  const started=await call('/verify/start',{},true);
  assert.equal(started.status,503);
  assert.equal(started.value.code,'VERIFICATION_NOT_CONNECTED');
  const publicConfig=await call('/config');
  assert.equal(Object.hasOwn(publicConfig.value,'serviceKey'),false);
  assert.equal(JSON.stringify(publicConfig).includes(config.adminToken),false);
  assert.equal(publicConfig.value.profiles_available,true);
});
test('Homepage and guide are served from the same backend address',async()=>{
  const response=await fetch(origin+'/');
  assert.equal(response.status,200);
  const html=await response.text();
  assert.ok(html.includes('Same sites. Different age bands.'));
  assert.ok(html.includes('/client-config.js'));
  assert.ok(html.includes('db.auth.signUp({ email, password })'));
  assert.equal(html.includes('/auth/signup'),false);
  assert.ok(html.includes('email confirmation is enabled'));
  assert.ok(html.includes('id="chooseId"'));
  assert.ok(html.includes('id="chooseChild"'));
  assert.ok(html.includes("$('upgradeId').onclick = () => {"));
  assert.ok(html.includes("show('ocr');"));
  assert.ok(html.includes('Your account is set to Under 13.'));
  assert.ok(html.includes('Rated websites requiring age 13 or older stay blocked.'));
  assert.ok(html.includes('Open Supabase SQL Editor and run the latest schema.sql'));
  assert.ok(html.includes('The date is stored as unverified.'));
  assert.ok(html.includes('The current demo runs OCR in your browser.'));
  assert.ok(html.includes('A date saved from OCR is marked unverified'));
  assert.ok(html.includes('OCR and demo results do not issue a real pass.'));
  assert.equal(html.includes('Veriff checks your document and selfie.'),false);
  assert.ok(html.includes('window.Tesseract'));
  assert.ok(html.includes('id="ocrDob" type="text" readonly'));
  assert.ok(html.includes('>Save date</button>'));
  assert.ok(html.includes('OCR suggests an adult age, but does not authenticate the ID.'));
  assert.ok(html.includes('Verified (Demo) · simulated'));
  assert.ok(html.includes('renderOcrResult(status.ocr_birth_date, DEMO_VERIFICATION)'));
  assert.equal(html.includes('Supabase remains unverified'),false);
  assert.ok(html.includes('DEMO_VERIFICATION'));
  assert.ok(html.includes('/downloads/webcompass-extension.zip'));
  assert.ok(html.includes('id="downloadExtension"'));
  assert.ok(html.includes("$('downloadExtension').onclick = goToBrowserStep;"));
  assert.ok(html.includes("selectGuide('install');"));
  assert.ok(html.includes('View Chrome installation steps'));
  assert.equal((await fetch(origin+'/ocr.js')).status,200);
  assert.equal((await fetch(origin+'/restricted')).status,200);
});
test('Extension popup omits site inventory and key diagnostics',()=>{
  const html=fs.readFileSync(new URL('../extension/popup.html',import.meta.url),'utf8');
  const script=fs.readFileSync(new URL('../extension/popup.js',import.meta.url),'utf8');
  assert.equal(html.includes('Sites covered in this build'),false);
  assert.equal(html.includes('Connection and key checks'),false);
  assert.equal(html.includes('id="sites"'),false);
  assert.equal(script.includes("$('extract')"),false);
  assert.equal(script.includes("$('reset')"),false);
});
test('Extension download returns a ZIP archive with its Chrome manifest',async()=>{
  const response=await fetch(origin+'/downloads/webcompass-extension.zip');
  assert.equal(response.status,200);
  assert.match(response.headers.get('content-type'),/application\/zip/);
  const archive=Buffer.from(await response.arrayBuffer());
  assert.equal(archive.readUInt32LE(0),0x04034b50);
  assert.ok(archive.includes(Buffer.from('manifest.json')));
});
