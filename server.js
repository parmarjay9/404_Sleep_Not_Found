import http from 'node:http';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bandFromDob, bandAllows } from './extension/lib/age.js';
import { readPayload } from './extension/lib/credential.js';
import { validateRatings } from './extension/lib/policy.js';
import { createVerifier } from './verification.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function configuration(env = process.env) {
  const config = {
    supabaseUrl: env.SUPABASE_URL || '',
    supabaseKey: env.SUPABASE_ANON_KEY || '',
    serviceKey: env.SUPABASE_SERVICE_KEY || '',
    provider: env.VERIFICATION_PROVIDER || 'none',
    veriffKey: env.VERIFF_API_KEY || '',
    veriffSecret: env.VERIFF_SHARED_SECRET || '',
    veriffMode: env.VERIFF_MODE || '',
    veriffProduct: env.VERIFF_PRODUCT || '',
    veriffEngine: env.VERIFF_ENGINE || '',
    veriffUrl: env.VERIFF_BASE_URL || 'https://stationapi.veriff.com',
    demoVerification: env.DEMO_VERIFICATION === 'true' && env.NODE_ENV !== 'production',
    adminToken: env.ADMIN_TOKEN || '',
    port: Number(env.PORT || 3000),
    siteUrl: env.SITE_URL || 'http://localhost:3000'
  };
  if (!['none', 'veriff'].includes(config.provider)) throw new Error('VERIFICATION_PROVIDER must be none or veriff.');
  const veriffUrl = new URL(config.veriffUrl);
  if (veriffUrl.protocol !== 'https:' || !/(^|\.)veriff\.(com|me)$/i.test(veriffUrl.hostname) ||
      veriffUrl.username || veriffUrl.password || veriffUrl.port || veriffUrl.pathname !== '/' || veriffUrl.search || veriffUrl.hash) {
    throw new Error('VERIFF_BASE_URL must be an HTTPS Veriff API origin from your integration settings.');
  }
  config.veriffUrl = veriffUrl.origin;
  if (!/^https:\/\/[a-z0-9.-]+\.supabase\.co\/?$/i.test(config.supabaseUrl)) throw new Error('Set a valid HTTPS Supabase project URL.');
  config.supabaseUrl = config.supabaseUrl.replace(/\/$/, '');
  let clientRole;
  try { clientRole = JSON.parse(Buffer.from(config.supabaseKey.split('.')[1] || '', 'base64url').toString()).role; } catch {}
  if (config.supabaseKey.startsWith('sb_secret_') || clientRole === 'service_role') throw new Error('The public Supabase key must not be a service-role or secret key.');
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) throw new Error('Set a valid PORT.');
  config.siteUrl = new URL(config.siteUrl).origin;
  return config;
}

function loadIssuer() {
  const directory = path.join(ROOT, '.local-data');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const keyfile = path.join(directory, 'issuer.pem');
  if (!fs.existsSync(keyfile)) {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    fs.writeFileSync(keyfile, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  }
  return crypto.createPrivateKey(fs.readFileSync(keyfile));
}

export function createApp({ config = configuration(), fetchImpl = fetch, issuerKey = null,
  revokedFile = path.join(ROOT, '.local-data', 'revoked.json'),
  verificationFile = path.join(ROOT, '.local-data', 'verification-sessions.json'), clock = Date.now } = {}) {
  const privateKey = issuerKey || loadIssuer();
  const publicKey = crypto.createPublicKey(privateKey);
  const publicJwk = publicKey.export({ format: 'jwk' });
  const nonces = new Map();
  const issued = new Map();
  const revoked = new Set(revokedFile && fs.existsSync(revokedFile) ? JSON.parse(fs.readFileSync(revokedFile)) : []);
  const sites = validateRatings(JSON.parse(fs.readFileSync(path.join(ROOT, 'extension', 'site-ratings.json'))));
  const profilesReady = !!config.serviceKey;
  let rpcReady = null, rpcReadyAt = 0;

  const reply = (res, status, data, type = 'application/json') => {
    res.writeHead(status, { 'content-type': type + '; charset=utf-8', 'cache-control': 'no-store',
      'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
      'access-control-allow-origin': config.siteUrl,
      'access-control-allow-headers': 'content-type, authorization, x-admin-token',
      'access-control-allow-methods': 'GET, POST, OPTIONS' });
    res.end(type === 'application/json' ? JSON.stringify(data) : data);
  };
  const rawBody = async (req, limit = 16_384) => {
    let size = 0; const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > limit) throw new Error('Request is too large.');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  };
  const body = async req => JSON.parse((await rawBody(req)).toString() || '{}');
  const remote = (url, options = {}) => fetchImpl(url, { ...options, signal: AbortSignal.timeout(12_000) });
  const admin = req => {
    const actual = Buffer.from(req.headers['x-admin-token'] || '');
    const expected = Buffer.from(config.adminToken);
    return expected.length > 0 && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  };
  const userFrom = async req => {
    const authorization = req.headers.authorization || '';
    if (!/^Bearer \S+$/.test(authorization)) return null;
    const response = await remote(config.supabaseUrl + '/auth/v1/user', {
      headers: { apikey: config.supabaseKey, authorization }
    });
    if (!response.ok) return null;
    const user = await response.json();
    return UUID.test(user.id) ? user : null;
  };
  const userToken = req => (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  const sb = (resource, options = {}) => remote(config.supabaseUrl + '/rest/v1/' + resource, {
    ...options, headers: { apikey: config.serviceKey, authorization: 'Bearer ' + config.serviceKey,
      'content-type': 'application/json', ...options.headers }
  });
  const profileServiceReady = async () => {
    if (profilesReady) return true;
    if (rpcReady === true && clock() - rpcReadyAt < 30_000) return true;
    if (rpcReady === false && clock() - rpcReadyAt < 3_000) return false;
    try {
      const response = await remote(config.supabaseUrl + '/rest/v1/rpc/profile_service_ready', {
        method: 'POST', headers: { apikey: config.supabaseKey, 'content-type': 'application/json' }, body: '{}'
      });
      rpcReady = response.ok && await response.json() === true;
    } catch { rpcReady = false; }
    rpcReadyAt = clock();
    return rpcReady;
  };
  const profileRpc = (name, token, input = {}) => remote(config.supabaseUrl + '/rest/v1/rpc/' + name, {
    method: 'POST', headers: { apikey: config.supabaseKey, authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    body: JSON.stringify(input)
  });
  const profileRpcError = async (res, response, fallback) => {
    const result = await response.json().catch(() => ({}));
    if (result.message === 'verified_profile_immutable') return reply(res, 409, { error: 'A provider-verified profile cannot be replaced with an unverified choice.' });
    return reply(res, 503, { error: fallback });
  };
  const profileFor = async (uid, token) => {
    const response = await remote(config.supabaseUrl + '/rest/v1/profiles?id=eq.' + uid + '&select=birth_date,verified_at,access_tier', {
      headers: { apikey: config.supabaseKey, authorization: 'Bearer ' + token }
    });
    if (!response.ok) throw new Error('Could not read your profile. Apply the updated schema.sql and check Supabase availability.');
    const [row] = await response.json();
    return row || null;
  };
  const profileBand = row => {
    if (row?.access_tier === 'child') return 'under13';
    if (row?.access_tier && row.access_tier !== 'verified') return null;
    if (!row || !row.verified_at || !Number.isFinite(Date.parse(row.verified_at))) return null;
    return bandFromDob(row.birth_date, new Date(clock()));
  };
  const verifier = createVerifier({ config, remote, stateFile: verificationFile, clock,
    saveDob: async (uid, dob) => {
      const stored = await sb('profiles', { method: 'POST', headers: { prefer: 'resolution=merge-duplicates' },
        body: JSON.stringify({ id: uid, birth_date: dob, verified_at: new Date(clock()).toISOString(), access_tier: 'verified' }) });
      if (!stored.ok) throw new Error('Could not save the verified birth date. Check the Supabase schema and private service key.');
    }
  });
  const verificationReady = verifier.ready && profilesReady;
  const verifyProof = proof => {
    const expiry = nonces.get(proof.nonce);
    nonces.delete(proof.nonce);
    if (!expiry || expiry <= clock()) throw new Error('Bad or reused challenge.');
    const p = readPayload(proof.credential, clock());
    if (!crypto.verify('sha256', Buffer.from(proof.credential.payload),
      { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(proof.credential.sig, 'base64'))) {
      throw new Error('The age pass was not signed by this issuer.');
    }
    if (revoked.has(p.id)) throw new Error('This age pass was revoked. Activate it again.');
    if (!crypto.verify('sha256', Buffer.from(proof.nonce),
      { key: crypto.createPublicKey({ key: p.pub, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(proof.signature || '', 'base64'))) throw new Error('This age pass belongs to another browser device.');
    return p;
  };
  const files = {
    '/': ['public/index.html', 'text/html'],
    '/index.html': ['public/index.html', 'text/html'],
    '/ocr.js': ['public/ocr.js', 'application/javascript'],
    '/restricted': ['public/restricted.html', 'text/html']
  };

  return http.createServer(async (req, res) => {
    try {
      const route = new URL(req.url, config.siteUrl).pathname;
      if (req.method === 'OPTIONS') return reply(res, 204, '', 'text/plain');
      if (req.method === 'GET' && files[route]) {
        const [filename, type] = files[route];
        return reply(res, 200, fs.readFileSync(path.join(ROOT, filename), 'utf8'), type);
      }
      if (req.method === 'GET' && route === '/downloads/webcompass-extension.zip') {
        res.writeHead(200, { 'content-type': 'application/zip',
          'content-disposition': 'attachment; filename="webcompass-extension.zip"',
          'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        const archive = spawn('/usr/bin/zip', ['-q', '-r', '-', 'manifest.json', 'background.js', 'content.js',
          'gate.html', 'gate.js', 'popup.html', 'popup.js', 'rules.json', 'site-ratings.json', 'ui.css', 'lib'],
        { cwd: path.join(ROOT, 'extension') });
        archive.stdout.pipe(res);
        archive.stderr.on('data', () => {});
        archive.on('error', () => res.destroy());
        archive.on('close', code => { if (code !== 0) res.destroy(); });
        return;
      }
      if (req.method === 'GET' && route === '/client-config.js') {
        return reply(res, 200, 'window.WEBCOMPASS_CONFIG = ' + JSON.stringify({
          supabaseUrl: config.supabaseUrl, supabaseKey: config.supabaseKey,
          demoVerification: config.demoVerification
        }) + ';', 'application/javascript');
      }
      if (req.method === 'GET' && route === '/config') return reply(res, 200, {
        supabaseUrl: config.supabaseUrl, supabaseKey: config.supabaseKey,
        verification_available: verificationReady, profiles_available: await profileServiceReady(),
        demo_verification: config.demoVerification
      });
      if (req.method === 'GET' && route === '/health') return reply(res, 200, {
        ok: true, profiles_available: await profileServiceReady(), verification_available: verificationReady
      });
      if (req.method === 'GET' && route === '/sites') return reply(res, 200, sites);
      if (req.method === 'GET' && route === '/issuer/public-key') return reply(res, 200, publicJwk);

      if (req.method === 'POST' && route === '/verify/start') {
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        const input = await body(req);
        if (Object.hasOwn(input, 'dob') || Object.hasOwn(input, 'band') || Object.hasOwn(input, 'verified')) {
          return reply(res, 400, { error: 'The verified age must come from the document-verification service.' });
        }
        if (!verificationReady) return reply(res, 503, {
          code: 'VERIFICATION_NOT_CONNECTED', error: 'Automatic ID verification needs live Veriff credentials and the backend Supabase service key. Your account can still be created.'
        });
        const profile = await profileFor(user.id, userToken(req));
        if (profileBand(profile) && profile?.access_tier !== 'child') return reply(res, 200, { verified: true });
        return reply(res, 200, await verifier.start(user.id));
      }
      if (req.method === 'POST' && route === '/profile/child') {
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        if (!await profileServiceReady()) return reply(res, 503, { error: 'Run the updated schema.sql to enable the Supabase profile service.' });
        const stored = await profileRpc('set_child_profile', userToken(req));
        if (!stored.ok) return profileRpcError(res, stored, 'Could not save the child-limited profile. Run the updated schema.sql and retry.');
        return reply(res, 200, { child: true, band: 'under13' });
      }
      if (req.method === 'POST' && route === '/profile/ocr') {
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        if (!await profileServiceReady()) return reply(res, 503, { error: 'Run the updated schema.sql to enable the Supabase profile service.' });
        const input = await body(req);
        if (typeof input.dob !== 'string' || !bandFromDob(input.dob, new Date(clock()))) {
          return reply(res, 400, { error: 'Enter a valid date of birth from the ID.' });
        }
        const stored = await profileRpc('save_ocr_birth_date', userToken(req), { p_birth_date: input.dob });
        if (!stored.ok) return profileRpcError(res, stored, 'Could not save the OCR date. Run the updated schema.sql and retry.');
        return reply(res, 200, { saved: true, verified: false, access_tier: 'ocr_unverified' });
      }
      if (req.method === 'POST' && route === '/demo/verify') {
        if (!config.demoVerification) return reply(res, 404, { error: 'Demo verification is disabled.' });
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        const input = await body(req);
        const band = typeof input.dob === 'string' ? bandFromDob(input.dob, new Date(clock())) : null;
        if (!band) return reply(res, 400, { error: 'The demo needs a valid OCR date of birth.' });
        return reply(res, 200, { demo: true, simulated_decision: 'approved', band, verified: false, age_pass_issued: false });
      }
      if (req.method === 'GET' && route === '/verify/status') {
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        if (!await profileServiceReady()) return reply(res, 200, { verified: false, child: false, band: null,
          adult: false, verification_available: false, profiles_available: false, verification_state: 'account_only' });
        const check = verificationReady ? await verifier.refresh(user.id) : { state: 'not_connected' };
        const profile = await profileFor(user.id, userToken(req)), band = profileBand(profile);
        const child = profile?.access_tier === 'child';
        return reply(res, 200, { verified: !!band && !child, child, band, adult: band === '18plus',
          verification_available: verificationReady, profiles_available: true,
          ocr_birth_date: profile?.access_tier === 'ocr_unverified' ? profile.birth_date : null,
          verification_state: child ? 'child_limited' : band ? 'approved' : check.state });
      }
      if (req.method === 'POST' && route === '/veriff/webhook') {
        if (!verificationReady) return reply(res, 503, { error: 'Automatic document verification is not connected.' });
        const raw = await rawBody(req, 1_048_576);
        await verifier.notification(raw, req.headers);
        return reply(res, 200, { received: true });
      }
      if (req.method === 'GET' && route === '/challenge') {
        for (const [nonce, expiry] of nonces) if (expiry <= clock()) nonces.delete(nonce);
        if (nonces.size >= 5000) return reply(res, 429, { error: 'Please try again in a moment.' });
        const nonce = crypto.randomBytes(24).toString('base64url');
        nonces.set(nonce, clock() + 60_000);
        return reply(res, 200, { nonce });
      }
      if (req.method === 'POST' && route === '/enroll') {
        const input = await body(req);
        if (Object.hasOwn(input, 'dob') || Object.hasOwn(input, 'band')) return reply(res, 400, { error: 'Age must come from a verified account, not a client-supplied birth date or band.' });
        const user = await userFrom(req);
        if (!user) return reply(res, 401, { error: 'Sign in first.' });
        if (!await profileServiceReady()) return reply(res, 503, { error: 'Run the updated schema.sql to enable the Supabase profile service.' });
        const band = profileBand(await profileFor(user.id, userToken(req)));
        if (!band) return reply(res, 403, { error: 'Complete ID verification on the website before activating your pass.' });
        const pub = input.pub;
        if (!pub || pub.kty !== 'EC' || pub.crv !== 'P-256' || !/^[\w-]{43}$/.test(pub.x) || !/^[\w-]{43}$/.test(pub.y) || pub.d) {
          return reply(res, 400, { error: 'A public P-256 device key is required.' });
        }
        const cleanPub = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
        crypto.createPublicKey({ key: cleanPub, format: 'jwk' });
        const id = crypto.randomUUID();
        const payload = JSON.stringify({ v: 2, id, pub: cleanPub, band, exp: clock() + 3_600_000 });
        const sig = crypto.sign('sha256', Buffer.from(payload), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
        issued.set(id, { band, issued_at: new Date(clock()).toISOString() });
        return reply(res, 200, { payload, sig });
      }
      if (req.method === 'POST' && ['/credential/check', '/content'].includes(route)) {
        let p;
        try { p = verifyProof(await body(req)); }
        catch (error) { return reply(res, 401, { error: error.message }); }
        if (route === '/credential/check') return reply(res, 200, { valid: true, band: p.band, exp: p.exp });
        if (!bandAllows(p.band, 18)) return reply(res, 403, { error: 'This particular test page requires the 18+ band.' });
        const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="200"><rect width="480" height="200" rx="18" fill="#173d36"/><text x="240" y="92" text-anchor="middle" font-size="26" fill="#d3ed94">Your age pass checks out.</text><text x="240" y="130" text-anchor="middle" font-size="16" fill="white">Only your age band was needed.</text></svg>';
        return reply(res, 200, { meme: 'data:image/svg+xml;utf8,' + encodeURIComponent(svg) });
      }
      if (req.method === 'POST' && route === '/revoke') {
        if (!admin(req)) return reply(res, 403, { error: 'Admin access required.' });
        const { id } = await body(req);
        if (!UUID.test(id)) return reply(res, 400, { error: 'Invalid credential identifier.' });
        revoked.add(id);
        if (revokedFile) {
          fs.mkdirSync(path.dirname(revokedFile), { recursive: true, mode: 0o700 });
          fs.writeFileSync(revokedFile, JSON.stringify([...revoked]), { mode: 0o600 });
        }
        return reply(res, 200, { revoked: id });
      }
      if (req.method === 'GET' && route === '/log') {
        if (!admin(req)) return reply(res, 403, { error: 'Admin access required.' });
        return reply(res, 200, { credentials: [...issued].map(([id, value]) => ({ id, ...value, revoked: revoked.has(id) })) });
      }
      return reply(res, 404, { error: 'Not found.' });
    } catch (error) {
      return reply(res, 400, { error: error instanceof SyntaxError ? 'Unreadable JSON request.' : error.message || 'Request could not be completed.' });
    }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = configuration();
  createApp({ config }).listen(config.port, '127.0.0.1', () => {
    console.log('WebCompass: http://localhost:' + config.port);
    console.log('Automatic ID verification: use /health to check live Veriff and Supabase configuration.');
  });
}
