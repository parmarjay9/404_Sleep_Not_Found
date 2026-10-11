import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createApp, configuration } from '../server.js';
import { verifyCredential } from '../extension/lib/credential.js';

// External services are isolated fixtures only in tests; runtime always calls the real APIs.
const uid = '11111111-1111-4111-8111-111111111111';
const otherUid = '22222222-2222-4222-8222-222222222222';
const sessionId = '33333333-3333-4333-8333-333333333333';
const issuer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const device = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicDevice = device.publicKey.export({ format: 'jwk' });
const liveSettings = {
  SUPABASE_URL: 'https://fixture.supabase.co', SUPABASE_ANON_KEY: 'sb_publishable_test_fixture',
  SUPABASE_SERVICE_KEY: 'isolated-test-supabase-secret', VERIFICATION_PROVIDER: 'veriff',
  VERIFF_API_KEY: 'isolated-test-veriff-key', VERIFF_SHARED_SECRET: 'isolated-test-veriff-secret',
  VERIFF_MODE: 'live', VERIFF_PRODUCT: 'document_selfie', VERIFF_ENGINE: 'full_auto'
};

async function fixture(t, settings = {}, verificationFile = null) {
  const config = configuration({ ...liveSettings, ...settings });
  const state = { now: Date.parse('2026-10-10T16:00:00Z'), profile: null, writes: [],
    reference: null, creates: 0, decisions: 0, deletes: 0, decision: null,
    badSignature: false, badUrl: false, deletionFails: false };
  const signature = raw => crypto.createHmac('sha256', config.veriffSecret).update(raw).digest('hex');
  const signed = (data, status = 200) => {
    const raw = JSON.stringify(data);
    return new Response(raw, { status, headers: { 'content-type': 'application/json',
      'x-auth-client': config.veriffKey, 'x-hmac-signature': state.badSignature ? '0'.repeat(64) : signature(raw) } });
  };
  const fetchImpl = async (url, options) => {
    if (url.endsWith('/auth/v1/user')) {
      const token = options.headers.authorization;
      return new Response(JSON.stringify(token === 'Bearer account' ? { id: uid } : token === 'Bearer other-account' ? { id: otherUid } : {}),
        { status: ['Bearer account', 'Bearer other-account'].includes(token) ? 200 : 401 });
    }
    if (url.includes('/rest/v1/profiles?')) return new Response(JSON.stringify(state.profile && url.includes('id=eq.' + uid) ? [state.profile] : []));
    if (url.endsWith('/rest/v1/profiles') && options.method === 'POST') {
      assert.equal(options.headers.apikey, config.serviceKey);
      const data = JSON.parse(options.body); state.writes.push(data); state.profile = data;
      return new Response(null, { status: 201 });
    }
    assert.equal(new URL(url).origin, 'https://stationapi.veriff.com');
    assert.equal(options.headers['x-auth-client'], config.veriffKey);
    assert.equal(options.redirect, 'error');
    if (options.method === 'POST' && url.endsWith('/v1/sessions')) {
      state.creates++;
      const input = JSON.parse(options.body);
      assert.deepEqual(Object.keys(input.verification).sort(), ['callback', 'vendorData']);
      assert.equal(options.body.includes(uid), false);
      state.reference = input.verification.vendorData;
      return signed({ status: 'success', verification: { id: sessionId, vendorData: state.reference,
        url: state.badUrl ? 'https://veriff.com.attacker.net/v/test' : 'https://magic.veriff.me/v/test-session' } });
    }
    assert.equal(options.headers['x-hmac-signature'], signature(sessionId));
    if (options.method === 'DELETE') {
      state.deletes++;
      return signed({ status: state.deletionFails ? 'fail' : 'success', verification: { id: sessionId } }, state.deletionFails ? 403 : 200);
    }
    if (url.endsWith('/v1/sessions/' + sessionId + '/decision')) {
      state.decisions++;
      return signed({ status: 'success', verification: state.decision });
    }
    throw new Error('Unexpected request in isolated verification test.');
  };
  let server, origin;
  const boot = async () => {
    server = createApp({ config, fetchImpl, issuerKey: issuer.privateKey, revokedFile: null,
      verificationFile, clock: () => state.now });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = 'http://127.0.0.1:' + server.address().port;
  };
  await boot();
  t.after(async () => { if (server.listening) await new Promise(resolve => server.close(resolve)); });
  const call = async (route, input, token = 'account', headers = {}) => {
    const response = await fetch(origin + route, { method: input === undefined ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers },
      body: input === undefined ? undefined : JSON.stringify(input) });
    return { status: response.status, value: await response.json() };
  };
  const approve = (dob = '2013-10-10', extra = {}) => {
    state.decision = { id: sessionId, vendorData: state.reference, status: 'approved', code: 9001,
      person: { dateOfBirth: dob, firstName: 'NOT STORED' },
      document: { type: 'PASSPORT', number: 'NOT STORED' },
      decisionTime: new Date(state.now).toISOString(), ...extra };
  };
  return { state, call, approve, signature, restart: async () => {
    await new Promise(resolve => server.close(resolve)); await boot();
  } };
}

test('Only configured live, automatic document-and-selfie integrations are enabled', async t => {
  for (const settings of [{ VERIFF_MODE: 'test' }, { VERIFF_PRODUCT: 'document_only' },
    { VERIFF_ENGINE: 'hybrid' }, { VERIFF_SHARED_SECRET: '' }]) {
    const { call, state } = await fixture(t, settings);
    assert.equal((await call('/verify/start', {})).status, 503);
    assert.equal((await call('/config')).value.verification_available, false);
    assert.equal(state.creates, 0);
  }
});
test('Starting verification requires an account and cannot accept a supplied age or approval flag', async t => {
  const { call, state } = await fixture(t);
  assert.equal((await call('/verify/start', {}, null)).status, 401);
  for (const input of [{ dob: '1990-01-01' }, { band: '18plus' }, { verified: true }]) {
    assert.equal((await call('/verify/start', input)).status, 400);
  }
  const first = await call('/verify/start', {}), second = await call('/verify/start', {});
  assert.equal(first.status, 200); assert.equal(first.value.url, second.value.url);
  assert.equal(state.creates, 1);
});
test('A pending decision and another account cannot activate an age pass', async t => {
  const { call, state } = await fixture(t);
  await call('/verify/start', {});
  assert.equal((await call('/verify/status')).value.verification_state, 'pending');
  assert.equal((await call('/verify/status', undefined, 'other-account')).value.verification_state, 'not_started');
  assert.equal((await call('/enroll', { pub: publicDevice })).status, 403);
  assert.equal(state.writes.length, 0);
});
test('An approved ID produces the correct signed band; renewal does not repeat ID verification', async t => {
  const { call, state, approve } = await fixture(t);
  await call('/verify/start', {}); approve();
  const status = await call('/verify/status');
  assert.equal(status.value.verified, true); assert.equal(status.value.band, '13to15');
  assert.deepEqual(Object.keys(state.writes[0]).sort(), ['access_tier', 'birth_date', 'id', 'verified_at']);
  assert.equal(state.writes[0].access_tier,'verified');
  const pass = (await call('/enroll', { pub: publicDevice })).value;
  const payload = await verifyCredential(pass, issuer.publicKey.export({ format: 'jwk' }), publicDevice, state.now);
  assert.equal(payload.band, '13to15');
  assert.equal(pass.payload.includes('2013-10-10'), false);
  state.now += 3_600_000;
  await assert.rejects(verifyCredential(pass, issuer.publicKey.export({ format: 'jwk' }), publicDevice, state.now));
  const renewed = (await call('/enroll', { pub: publicDevice })).value;
  assert.equal(JSON.parse(renewed.payload).band, '13to15');
  assert.equal(state.creates, 1); assert.equal(state.writes.length, 1); assert.equal(state.deletes, 1);
});
test('Rejected selfie/document checks and resubmission never create a verified profile', async t => {
  for (const [status, code] of [['declined', 9102], ['resubmission_requested', 9103]]) {
    const { call, state } = await fixture(t);
    await call('/verify/start', {});
    state.decision = { id: sessionId, vendorData: state.reference, status, code };
    assert.equal((await call('/verify/status')).value.verification_state, status);
    assert.equal((await call('/enroll', { pub: publicDevice })).status, 403);
    assert.equal(state.writes.length, 0);
    if (status === 'resubmission_requested') {
      await call('/verify/start', {}); assert.equal(state.creates, 1);
    }
  }
});
test('Provider signature tampering and session/account substitution are rejected', async t => {
  for (const attack of ['signature', 'id', 'reference']) {
    const { call, state, approve } = await fixture(t);
    await call('/verify/start', {}); approve();
    if (attack === 'signature') state.badSignature = true;
    if (attack === 'id') state.decision.id = otherUid;
    if (attack === 'reference') state.decision.vendorData = 'another-account-reference';
    assert.equal((await call('/verify/status')).status, 400);
    assert.equal(state.writes.length, 0);
    assert.equal((await call('/enroll', { pub: publicDevice })).status, 403);
  }
});
test('Incomplete DOB, future DOB, missing ID, and stale decisions cannot verify an account', async t => {
  for (const attack of ['partial', 'future', 'document', 'stale']) {
    const { call, state, approve } = await fixture(t);
    await call('/verify/start', {});
    approve(attack === 'partial' ? '2013' : attack === 'future' ? '2030-01-01' : '2013-10-10');
    if (attack === 'document') state.decision.document = null;
    if (attack === 'stale') state.decision.decisionTime = '2020-01-01T00:00:00Z';
    assert.equal((await call('/verify/status')).value.verification_state, 'invalid_result');
    assert.equal(state.writes.length, 0);
  }
});
test('Hosted-link lookalikes and untrusted API origins are rejected', async t => {
  const { call, state } = await fixture(t); state.badUrl = true;
  assert.equal((await call('/verify/start', {})).status, 400);
  assert.throws(() => configuration({ VERIFF_BASE_URL: 'https://veriff.com.attacker.net' }));
});
test('Webhook claims cannot approve a user without an authenticated approved API decision', async t => {
  const { call, state, approve, signature } = await fixture(t);
  await call('/verify/start', {}); approve();
  const event = { verification: state.decision };
  assert.equal((await call('/veriff/webhook', event, null)).status, 400);
  state.decision = null;
  const response = await call('/veriff/webhook', event, null, {
    'x-auth-client': liveSettings.VERIFF_API_KEY, 'x-hmac-signature': signature(JSON.stringify(event))
  });
  assert.equal(response.status, 200); assert.equal(state.writes.length, 0);
});
test('Provider deletion failure does not erase verification or pretend the images were deleted', async t => {
  const { call, state, approve } = await fixture(t); state.deletionFails = true;
  await call('/verify/start', {}); approve();
  assert.equal((await call('/verify/status')).value.verified, true);
  assert.equal((await call('/verify/status')).value.verified, true);
  assert.equal(state.deletes, 1);
  state.now += 3_600_000; state.deletionFails = false;
  assert.equal((await call('/verify/status')).value.verified, true);
  assert.equal(state.deletes, 2);
});
test('Pending account/session binding survives a backend restart without storing document data', async t => {
  const directory = fs.mkdtempSync(path.resolve('test', '.verification-state-'));
  const filename = path.join(directory, 'sessions.json');
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { call, state, approve, restart } = await fixture(t, {}, filename);
  await call('/verify/start', {});
  const persisted = fs.readFileSync(filename, 'utf8');
  assert.equal(persisted.includes('dateOfBirth'), false);
  assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  await restart(); approve();
  assert.equal((await call('/verify/status')).value.verified, true);
  assert.equal(state.creates, 1);
});
test('Public configuration never exposes verification or Supabase secrets', async t => {
  const { call } = await fixture(t);
  const result = await call('/config'); assert.equal(result.value.verification_available, true);
  const raw = JSON.stringify(result);
  for (const name of ['SUPABASE_SERVICE_KEY', 'VERIFF_API_KEY', 'VERIFF_SHARED_SECRET']) {
    assert.equal(raw.includes(liveSettings[name]), false);
  }
});
