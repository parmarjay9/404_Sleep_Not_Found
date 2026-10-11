import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { bandFromDob } from './extension/lib/age.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOCUMENTS = new Set(['PASSPORT', 'ID_CARD', 'DRIVERS_LICENSE', 'RESIDENCE_PERMIT']);
const SESSION_TTL = 24 * 60 * 60 * 1000;

export function createVerifier({ config, remote, saveDob, stateFile, clock = Date.now }) {
  // These settings describe the LIVE integration configured in Veriff's portal.
  // The API does not independently attest to its portal configuration or live/test mode.
  const ready = config.provider === 'veriff' && config.veriffMode === 'live' &&
    config.veriffProduct === 'document_selfie' && config.veriffEngine === 'full_auto' &&
    !!config.veriffKey && !!config.veriffSecret;
  const records = new Map(stateFile && fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile)) : []);
  const starts = new Map(), refreshes = new Map();
  const persist = () => {
    if (!stateFile) return;
    fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
    const temporary = stateFile + '.tmp';
    fs.writeFileSync(temporary, JSON.stringify([...records]), { mode: 0o600 });
    fs.renameSync(temporary, stateFile);
  };
  const sign = value => crypto.createHmac('sha256', config.veriffSecret).update(value).digest('hex');
  const equal = (actual, expected) => {
    if (typeof actual !== 'string') return false;
    const a = Buffer.from(actual), b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  };
  const validSignature = (raw, headers) => equal(headers['x-auth-client'], config.veriffKey) &&
    /^[a-f0-9]{64}$/i.test(headers['x-hmac-signature'] || '') &&
    equal(headers['x-hmac-signature'].toLowerCase(), sign(raw));
  const request = async (resource, { method = 'GET', payload, sessionId } = {}) => {
    const raw = payload === undefined ? undefined : JSON.stringify(payload);
    const headers = { 'content-type': 'application/json', 'x-auth-client': config.veriffKey };
    if (sessionId) headers['x-hmac-signature'] = sign(sessionId);
    const response = await remote(config.veriffUrl + '/v1/' + resource, {
      method, headers, body: raw, redirect: 'error'
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > 1_048_576) throw new Error('The verification response is too large.');
    if (!validSignature(bytes, {
      'x-auth-client': response.headers.get('x-auth-client'),
      'x-hmac-signature': response.headers.get('x-hmac-signature')
    })) throw new Error('The verification response signature could not be validated.');
    let data;
    try { data = JSON.parse(bytes.toString()); }
    catch { throw new Error('The verification service returned an unreadable response.'); }
    if (!response.ok || data.status !== 'success') throw new Error('The verification service could not complete this request. Check the live integration settings.');
    return data;
  };
  const hostedUrl = value => {
    let url;
    try { url = new URL(value); } catch { throw new Error('The verification link is invalid.'); }
    if (url.protocol !== 'https:' || !/(^|\.)veriff\.(com|me)$/i.test(url.hostname) || url.username || url.password) {
      throw new Error('The verification service returned an unexpected link.');
    }
    return url.href;
  };
  const cleanup = async record => {
    if (!record.cleanupPending || record.cleanupAfter > clock()) return;
    try {
      await request('sessions/' + record.id, { method: 'DELETE', sessionId: record.id });
      record.cleanupPending = false;
    } catch {
      // Deletion requires provider-side enablement and has strict rate limits.
      // Keep a retry marker, never claim that provider images were deleted.
      record.cleanupAfter = clock() + 3_600_000;
    }
    persist();
  };
  const start = async uid => {
    if (!ready) throw new Error('Automatic ID verification needs a live Veriff document-and-selfie integration.');
    if (starts.has(uid)) return starts.get(uid);
    const task = (async () => {
      const previous = records.get(uid);
      if (previous && previous.expiresAt > clock() && ['pending', 'resubmission_requested'].includes(previous.state)) {
        return { url: previous.url };
      }
      if (records.size >= 5000 && !records.has(uid)) throw new Error('Too many verification sessions. Please try again later.');
      const today = new Date(clock()).toISOString().slice(0, 10);
      const attempts = previous?.day === today ? previous.attempts || 0 : 0;
      if (attempts >= 3) throw new Error('You have used today’s three verification attempts. Try again tomorrow.');
      if (previous && clock() - previous.createdAt < 60_000) throw new Error('Wait a minute before starting another verification check.');
      // Session references are random and reveal no account ID, email, or DOB.
      const reference = crypto.randomBytes(24).toString('base64url');
      const data = await request('sessions', { method: 'POST', payload: {
        verification: { callback: config.siteUrl + '/?verification=return', vendorData: reference }
      } });
      const session = data.verification;
      if (!session || !UUID.test(session.id) || session.vendorData !== reference) throw new Error('The verification session could not be bound to this account.');
      const url = hostedUrl(session.url);
      records.set(uid, { id: session.id, reference, url, state: 'pending',
        createdAt: clock(), expiresAt: clock() + SESSION_TTL, checkedAt: null, day: today, attempts: attempts + 1 });
      persist();
      return { url };
    })();
    starts.set(uid, task);
    try { return await task; } finally { starts.delete(uid); }
  };
  const refresh = async uid => {
    if (!ready) return { state: 'not_connected' };
    if (refreshes.has(uid)) return refreshes.get(uid);
    const task = (async () => {
      const record = records.get(uid);
      if (!record) return { state: 'not_started' };
      if (['approved', 'declined', 'expired', 'abandoned', 'invalid_result'].includes(record.state)) {
        await cleanup(record);
        return { state: record.state };
      }
      if (record.expiresAt <= clock()) {
        record.state = 'expired'; record.cleanupPending = true; delete record.url;
        persist(); await cleanup(record);
        return { state: 'expired' };
      }
      if (record.checkedAt !== null && clock() - record.checkedAt < 5000) return { state: record.state };
      // Poll the authenticated provider API. A callback URL or browser flag is not approval.
      const result = await request('sessions/' + record.id + '/decision', { sessionId: record.id });
      record.checkedAt = clock();
      const decision = result.verification;
      if (decision === null) { persist(); return { state: 'pending' }; }
      if (!decision || decision.id !== record.id || decision.vendorData !== record.reference) {
        throw new Error('The verification result does not match this account’s session.');
      }
      if (decision.status === 'approved' && decision.code === 9001) {
        const dob = decision.person?.dateOfBirth;
        const decisionTime = Date.parse(decision.decisionTime);
        if (!DOCUMENTS.has(decision.document?.type) || !bandFromDob(dob, new Date(clock())) ||
            !Number.isFinite(decisionTime) || decisionTime < record.createdAt - 60_000 || decisionTime > clock() + 60_000) {
          record.state = 'invalid_result';
        } else {
          // Only the authenticated issuer result may supply the birth date.
          await saveDob(uid, dob);
          record.state = 'approved';
        }
      } else if (decision.status === 'resubmission_requested' && decision.code === 9103) {
        record.state = 'resubmission_requested';
      } else if (['declined', 'expired', 'abandoned'].includes(decision.status)) {
        record.state = decision.status;
      } else {
        throw new Error('The verification service has not returned a supported final decision.');
      }
      if (record.state !== 'resubmission_requested') {
        record.cleanupPending = true; delete record.url;
      }
      persist(); await cleanup(record);
      return { state: record.state };
    })();
    refreshes.set(uid, task);
    try { return await task; } finally { refreshes.delete(uid); }
  };
  const notification = async (raw, headers) => {
    if (!ready || !validSignature(raw, headers)) throw new Error('Bad verification webhook signature.');
    const data = JSON.parse(raw.toString());
    const id = data.verification?.id;
    if (!UUID.test(id)) throw new Error('Missing verification session.');
    const entry = [...records].find(([, record]) => record.id === id);
    if (entry) await refresh(entry[0]);
    // Unknown/previous sessions cannot alter an account's verified birth date.
  };
  return { ready, start, refresh, notification };
}
