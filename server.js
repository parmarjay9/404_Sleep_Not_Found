import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ZipArchive } from 'archiver';
import { bandFromDob, bandAllows } from './extension/lib/age.js';
import { readPayload } from './extension/lib/credential.js';
import { validateRatings } from './extension/lib/policy.js';
import { createVerifier } from './verification.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function extensionFiles(directory, prefix = '') {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const name = prefix ? prefix + '/' + entry.name : entry.name;
    const fullPath = path.join(directory, entry.name);

    return entry.isDirectory()
      ? extensionFiles(fullPath, name)
      : [{ name, fullPath }];
  });
}

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
    demoVerification:
      env.DEMO_VERIFICATION === 'true' && env.NODE_ENV !== 'production',
    vercel: env.VERCEL === '1',
    adminToken: env.ADMIN_TOKEN || '',
    port: Number(env.PORT || 3000),
    siteUrl: env.SITE_URL || (
      env.VERCEL === '1'
        ? `https://${env.VERCEL_ENV === 'production'
          ? 'web-compass-project.vercel.app'
          : env.VERCEL_URL || 'web-compass-project.vercel.app'}`
        : 'http://localhost:3000'
    )
  };

  if (!['none', 'veriff'].includes(config.provider)) {
    throw new Error('VERIFICATION_PROVIDER must be none or veriff.');
  }

  const veriffUrl = new URL(config.veriffUrl);

  if (
    veriffUrl.protocol !== 'https:' ||
    !/(^|\.)veriff\.(com|me)$/i.test(veriffUrl.hostname) ||
    veriffUrl.username ||
    veriffUrl.password ||
    veriffUrl.port ||
    veriffUrl.pathname !== '/' ||
    veriffUrl.search ||
    veriffUrl.hash
  ) {
    throw new Error(
      'VERIFF_BASE_URL must be an HTTPS Veriff API origin from your integration settings.'
    );
  }

  config.veriffUrl = veriffUrl.origin;

  if (!/^https:\/\/[a-z0-9.-]+\.supabase\.co\/?$/i.test(config.supabaseUrl)) {
    throw new Error('Set a valid HTTPS Supabase project URL.');
  }

  config.supabaseUrl = config.supabaseUrl.replace(/\/$/, '');

  if (config.vercel && !config.serviceKey) {
    throw new Error(
      'Set SUPABASE_SERVICE_KEY in Vercel so signing and verification state can be stored durably.'
    );
  }

  let clientRole;

  try {
    clientRole = JSON.parse(
      Buffer.from(
        config.supabaseKey.split('.')[1] || '',
        'base64url'
      ).toString()
    ).role;
  } catch {}

  if (
    config.supabaseKey.startsWith('sb_secret_') ||
    clientRole === 'service_role'
  ) {
    throw new Error(
      'The public Supabase key must not be a service-role or secret key.'
    );
  }

  if (
    !Number.isInteger(config.port) ||
    config.port < 1 ||
    config.port > 65535
  ) {
    throw new Error('Set a valid PORT.');
  }

  config.siteUrl = new URL(config.siteUrl).origin;

  return config;
}

function issuerFromSecret(secret) {
  const secretBytes = Buffer.from(secret);

  for (let counter = 0; counter < 10; counter++) {
    const scalar = crypto
      .createHmac('sha256', secretBytes)
      .update('webcompass-issuer-v1:' + counter)
      .digest();

    try {
      const ecdh = crypto.createECDH('prime256v1');
      ecdh.setPrivateKey(scalar);

      const point = ecdh.getPublicKey(undefined, 'uncompressed');

      return crypto.createPrivateKey({
        key: {
          kty: 'EC',
          crv: 'P-256',
          x: point.subarray(1, 33).toString('base64url'),
          y: point.subarray(33, 65).toString('base64url'),
          d: scalar.toString('base64url')
        },
        format: 'jwk'
      });
    } catch {}
  }

  throw new Error('Could not derive the stable Vercel issuer key.');
}

function loadIssuer(config) {
  if (config.vercel) {
    return issuerFromSecret(config.serviceKey);
  }

  const directory = path.join(ROOT, '.local-data');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const keyfile = path.join(directory, 'issuer.pem');

  if (!fs.existsSync(keyfile)) {
    const pair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256'
    });

    fs.writeFileSync(
      keyfile,
      pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600, flag: 'wx' }
    );
  }

  return crypto.createPrivateKey(fs.readFileSync(keyfile));
}

export function createApp({
  config = configuration(),
  fetchImpl = fetch,
  issuerKey = null,
  revokedFile = path.join(ROOT, '.local-data', 'revoked.json'),
  verificationFile = path.join(
    ROOT,
    '.local-data',
    'verification-sessions.json'
  ),
  clock = Date.now
} = {}) {
  const privateKey = issuerKey || loadIssuer(config);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicJwk = publicKey.export({ format: 'jwk' });

  const nonces = new Map();
  const issued = new Map();

  const localRevokedFile = config.vercel ? null : revokedFile;

  const revoked = new Set(
    localRevokedFile && fs.existsSync(localRevokedFile)
      ? JSON.parse(fs.readFileSync(localRevokedFile))
      : []
  );

  const sites = validateRatings(
    JSON.parse(
      fs.readFileSync(path.join(ROOT, 'extension', 'site-ratings.json'))
    )
  );

  const profilesReady = !!config.serviceKey;
  let rpcReady = null;
  let rpcReadyAt = 0;

  const reply = (
    res,
    status,
    data,
    type = 'application/json'
  ) => {
    res.writeHead(status, {
      'content-type': type + '; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'access-control-allow-origin': config.siteUrl,
      'access-control-allow-headers':
        'content-type, authorization, x-admin-token',
      'access-control-allow-methods': 'GET, POST, OPTIONS'
    });

    res.end(
      type === 'application/json'
        ? JSON.stringify(data)
        : data
    );
  };

  const rawBody = async (req, limit = 16_384) => {
    let size = 0;
    const chunks = [];

    for await (const chunk of req) {
      size += chunk.length;

      if (size > limit) {
        throw new Error('Request is too large.');
      }

      chunks.push(chunk);
    }

    return Buffer.concat(chunks);
  };

  const body = async req => {
    return JSON.parse((await rawBody(req)).toString() || '{}');
  };

  const remote = (url, options = {}) => {
    return fetchImpl(url, {
      ...options,
      signal: AbortSignal.timeout(12_000)
    });
  };

  const admin = req => {
    const actual = Buffer.from(req.headers['x-admin-token'] || '');
    const expected = Buffer.from(config.adminToken);

    return (
      expected.length > 0 &&
      actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected)
    );
  };

  const userFrom = async req => {
    const authorization = req.headers.authorization || '';

    if (!/^Bearer \S+$/.test(authorization)) {
      return null;
    }

    const response = await remote(
      config.supabaseUrl + '/auth/v1/user',
      {
        headers: {
          apikey: config.supabaseKey,
          authorization
        }
      }
    );

    if (!response.ok) {
      return null;
    }

    const user = await response.json();
    return UUID.test(user.id) ? user : null;
  };

  const userToken = req => {
    return (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  };

  const sb = (resource, options = {}) => {
    return remote(config.supabaseUrl + '/rest/v1/' + resource, {
      ...options,
      headers: {
        apikey: config.serviceKey,
        authorization: 'Bearer ' + config.serviceKey,
        'content-type': 'application/json',
        ...options.headers
      }
    });
  };

  const stateGet = async key => {
    const query = new URLSearchParams({
      state_key: `eq.${key}`,
      select: 'state_value'
    });

    const response = await sb('webcompass_runtime_state?' + query);

    if (!response.ok) {
      throw new Error(
        'Supabase runtime-state table is unavailable. Run the updated schema.sql.'
      );
    }

    return (await response.json())[0]?.state_value ?? null;
  };

  const stateSet = async (key, value) => {
    const response = await sb(
      'webcompass_runtime_state?on_conflict=state_key',
      {
        method: 'POST',
        headers: {
          prefer: 'resolution=merge-duplicates,return=minimal'
        },
        body: JSON.stringify({
          state_key: key,
          state_value: value,
          updated_at: new Date(clock()).toISOString()
        })
      }
    );

    if (!response.ok) {
      throw new Error(
        'Could not save durable runtime state in Supabase.'
      );
    }
  };

  const stateDelete = async key => {
    const response = await sb(
      'webcompass_runtime_state?state_key=eq.' + encodeURIComponent(key),
      { method: 'DELETE' }
    );

    if (!response.ok) {
      throw new Error(
        'Could not remove durable runtime state from Supabase.'
      );
    }
  };

  const stateList = async prefix => {
    const query = new URLSearchParams({
      state_key: `like.${prefix}%`,
      select: 'state_key,state_value'
    });

    const response = await sb('webcompass_runtime_state?' + query);

    if (!response.ok) {
      throw new Error(
        'Could not read durable runtime state from Supabase.'
      );
    }

    return response.json();
  };

  const consumeDurableNonce = async (nonce, now) => {
    const response = await sb('rpc/consume_webcompass_nonce', {
      method: 'POST',
      body: JSON.stringify({
        p_nonce: nonce,
        p_now: now
      })
    });

    if (!response.ok) {
      throw new Error(
        'Supabase could not validate the one-time challenge. Run the updated schema.sql.'
      );
    }

    return response.json();
  };

  const stateStore = config.vercel
    ? {
      get: stateGet,
      set: stateSet,
      delete: stateDelete,
      list: stateList
    }
    : null;

  const profileServiceReady = async () => {
    if (profilesReady) {
      return true;
    }

    if (rpcReady === true && clock() - rpcReadyAt < 30_000) {
      return true;
    }

    if (rpcReady === false && clock() - rpcReadyAt < 3_000) {
      return false;
    }

    try {
      const response = await remote(
        config.supabaseUrl + '/rest/v1/rpc/profile_service_ready',
        {
          method: 'POST',
          headers: {
            apikey: config.supabaseKey,
            'content-type': 'application/json'
          },
          body: '{}'
        }
      );

      rpcReady = response.ok && await response.json() === true;
    } catch {
      rpcReady = false;
    }

    rpcReadyAt = clock();
    return rpcReady;
  };

  const profileRpc = (name, token, input = {}) => {
    return remote(config.supabaseUrl + '/rest/v1/rpc/' + name, {
      method: 'POST',
      headers: {
        apikey: config.supabaseKey,
        authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      },
      body: JSON.stringify(input)
    });
  };

  const profileRpcError = async (res, response, fallback) => {
    const result = await response.json().catch(() => ({}));

    if (result.message === 'verified_profile_immutable') {
      return reply(res, 409, {
        error:
          'A provider-verified profile cannot be replaced with an unverified choice.'
      });
    }

    return reply(res, 503, { error: fallback });
  };

  const profileFor = async (uid, token) => {
    const response = await remote(
      config.supabaseUrl +
        '/rest/v1/profiles?id=eq.' +
        uid +
        '&select=birth_date,verified_at,access_tier',
      {
        headers: {
          apikey: config.supabaseKey,
          authorization: 'Bearer ' + token
        }
      }
    );

    if (!response.ok) {
      throw new Error(
        'Could not read your profile. Apply the updated schema.sql and check Supabase availability.'
      );
    }

    const [row] = await response.json();
    return row || null;
  };

  const profileBand = row => {
    if (row?.access_tier === 'child') {
      return 'under13';
    }

    if (row?.access_tier && row.access_tier !== 'verified') {
      return null;
    }

    if (
      !row ||
      !row.verified_at ||
      !Number.isFinite(Date.parse(row.verified_at))
    ) {
      return null;
    }

    return bandFromDob(row.birth_date, new Date(clock()));
  };

  const verifier = createVerifier({
    config,
    remote,
    stateFile: config.vercel ? null : verificationFile,
    stateStore,
    clock,
    saveDob: async (uid, dob) => {
      const stored = await sb('profiles', {
        method: 'POST',
        headers: {
          prefer: 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          id: uid,
          birth_date: dob,
          verified_at: new Date(clock()).toISOString(),
          access_tier: 'verified'
        })
      });

      if (!stored.ok) {
        throw new Error(
          'Could not save the verified birth date. Check the Supabase schema and private service key.'
        );
      }
    }
  });

  const verificationReady = verifier.ready && profilesReady;

  const verifyProof = async proof => {
    if (config.vercel) {
      if (!await consumeDurableNonce(proof.nonce, clock())) {
        throw new Error('Bad or reused challenge.');
      }
    } else {
      const expiry = nonces.get(proof.nonce);
      nonces.delete(proof.nonce);

      if (!expiry || expiry <= clock()) {
        throw new Error('Bad or reused challenge.');
      }
    }

    const p = readPayload(proof.credential, clock());

    if (!crypto.verify(
      'sha256',
      Buffer.from(proof.credential.payload),
      {
        key: publicKey,
        dsaEncoding: 'ieee-p1363'
      },
      Buffer.from(proof.credential.sig, 'base64')
    )) {
      throw new Error('The age pass was not signed by this issuer.');
    }

    const isRevoked = config.vercel
      ? !!await stateGet('revoked:' + p.id)
      : revoked.has(p.id);

    if (isRevoked) {
      throw new Error('This age pass was revoked. Activate it again.');
    }

    if (!crypto.verify(
      'sha256',
      Buffer.from(proof.nonce),
      {
        key: crypto.createPublicKey({
          key: p.pub,
          format: 'jwk'
        }),
        dsaEncoding: 'ieee-p1363'
      },
      Buffer.from(proof.signature || '', 'base64')
    )) {
      throw new Error(
        'This age pass belongs to another browser device.'
      );
    }

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

      if (req.method === 'OPTIONS') {
        return reply(res, 204, '', 'text/plain');
      }

      if (req.method === 'GET' && files[route]) {
        const [filename, type] = files[route];

        return reply(
          res,
          200,
          fs.readFileSync(path.join(ROOT, filename), 'utf8'),
          type
        );
      }

      if (
        req.method === 'GET' &&
        route === '/downloads/webcompass-extension.zip'
      ) {
        const serverOrigin = new URL(config.siteUrl).origin;
        const serverUrl = new URL(serverOrigin);

        if (
          config.vercel &&
          (serverUrl.protocol !== 'https:' ||
            ['localhost', '127.0.0.1', '[::1]'].includes(serverUrl.hostname))
        ) {
          throw new Error(
            'Set SITE_URL in Vercel to your HTTPS website address before downloading the extension.'
          );
        }

        const packagedFiles = [];

        for (const file of extensionFiles(path.join(ROOT, 'extension'))) {
          let contents = fs.readFileSync(file.fullPath);

          if (/\.(js|html|json)$/i.test(file.name)) {
            let text = contents.toString('utf8');

            if (file.name === 'background.js') {
              const declaration =
                /^[ \t]*const\s+SERVER\s*=\s*(['"])[^'"\r\n]*\1[ \t]*;?/m;

              if (!declaration.test(text)) {
                throw new Error(
                  'extension/background.js must contain a const SERVER URL.'
                );
              }

              text = text.replace(
                declaration,
                () => 'const SERVER = ' + JSON.stringify(serverOrigin) + ';'
              );
            }

            text = text
              .replaceAll('http://localhost:3000', serverOrigin)
              .replaceAll('http://127.0.0.1:3000', serverOrigin)
              .replaceAll(
                'The local service is offline. Start the server on localhost:3000, then try again.',
                'WebCompass could not be reached. Check your connection and try again.'
              );

            if (file.name === 'manifest.json') {
              const manifest = JSON.parse(text);

              manifest.host_permissions = [
                ...new Set([
                  ...(manifest.host_permissions || []),
                  serverOrigin + '/*'
                ])
              ];

              for (const script of manifest.content_scripts || []) {
                if (script.js?.includes('content.js')) {
                  script.matches = [
                    ...new Set([
                      ...(script.matches || []),
                      serverOrigin + '/restricted*'
                    ])
                  ];
                }
              }

              text = JSON.stringify(manifest, null, 2);
            }

            contents = Buffer.from(text);
          }

          packagedFiles.push({ name: file.name, contents });
        }

        res.writeHead(200, {
          'content-type': 'application/zip',
          'content-disposition':
            'attachment; filename="webcompass-extension.zip"',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff'
        });

        const archive = new ZipArchive({
          zlib: { level: 9 }
        });

        archive.on('error', () => res.destroy());
        archive.pipe(res);

        for (const file of packagedFiles) {
          archive.append(file.contents, { name: file.name });
        }

        try {
          await archive.finalize();
        } catch {
          res.destroy();
        }

        return;
      }

      if (req.method === 'GET' && route === '/client-config.js') {
        return reply(
          res,
          200,
          'window.WEBCOMPASS_CONFIG = ' + JSON.stringify({
            supabaseUrl: config.supabaseUrl,
            supabaseKey: config.supabaseKey,
            demoVerification: config.demoVerification
          }) + ';',
          'application/javascript'
        );
      }

      if (req.method === 'GET' && route === '/config') {
        return reply(res, 200, {
          supabaseUrl: config.supabaseUrl,
          supabaseKey: config.supabaseKey,
          verification_available: verificationReady,
          profiles_available: await profileServiceReady(),
          demo_verification: config.demoVerification
        });
      }

      if (req.method === 'GET' && route === '/health') {
        return reply(res, 200, {
          ok: true,
          profiles_available: await profileServiceReady(),
          verification_available: verificationReady
        });
      }

      if (req.method === 'GET' && route === '/sites') {
        return reply(res, 200, sites);
      }

      if (req.method === 'GET' && route === '/issuer/public-key') {
        return reply(res, 200, publicJwk);
      }

      if (req.method === 'POST' && route === '/verify/start') {
        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        const input = await body(req);

        if (
          Object.hasOwn(input, 'dob') ||
          Object.hasOwn(input, 'band') ||
          Object.hasOwn(input, 'verified')
        ) {
          return reply(res, 400, {
            error:
              'The verified age must come from the document-verification service.'
          });
        }

        if (!verificationReady) {
          return reply(res, 503, {
            code: 'VERIFICATION_NOT_CONNECTED',
            error:
              'Automatic ID verification needs live Veriff credentials and the backend Supabase service key. Your account can still be created.'
          });
        }

        const profile = await profileFor(
          user.id,
          userToken(req)
        );

        if (profileBand(profile) && profile?.access_tier !== 'child') {
          return reply(res, 200, { verified: true });
        }

        return reply(res, 200, await verifier.start(user.id));
      }

      if (req.method === 'POST' && route === '/profile/child') {
        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        if (!await profileServiceReady()) {
          return reply(res, 503, {
            error:
              'Run the updated schema.sql to enable the Supabase profile service.'
          });
        }

        const stored = await profileRpc(
          'set_child_profile',
          userToken(req)
        );

        if (!stored.ok) {
          return profileRpcError(
            res,
            stored,
            'Could not save the child-limited profile. Run the updated schema.sql and retry.'
          );
        }

        return reply(res, 200, {
          child: true,
          band: 'under13'
        });
      }

      if (req.method === 'POST' && route === '/profile/ocr') {
        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        if (!await profileServiceReady()) {
          return reply(res, 503, {
            error:
              'Run the updated schema.sql to enable the Supabase profile service.'
          });
        }

        const input = await body(req);

        if (
          typeof input.dob !== 'string' ||
          !bandFromDob(input.dob, new Date(clock()))
        ) {
          return reply(res, 400, {
            error: 'Enter a valid date of birth from the ID.'
          });
        }

        const stored = await profileRpc(
          'save_ocr_birth_date',
          userToken(req),
          { p_birth_date: input.dob }
        );

        if (!stored.ok) {
          return profileRpcError(
            res,
            stored,
            'Could not save the OCR date. Run the updated schema.sql and retry.'
          );
        }

        return reply(res, 200, {
          saved: true,
          verified: false,
          access_tier: 'ocr_unverified'
        });
      }

      if (req.method === 'POST' && route === '/demo/verify') {
        if (!config.demoVerification) {
          return reply(res, 404, {
            error: 'Demo verification is disabled.'
          });
        }

        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        const input = await body(req);

        const band = typeof input.dob === 'string'
          ? bandFromDob(input.dob, new Date(clock()))
          : null;

        if (!band) {
          return reply(res, 400, {
            error: 'The demo needs a valid OCR date of birth.'
          });
        }

        return reply(res, 200, {
          demo: true,
          simulated_decision: 'approved',
          band,
          verified: false,
          age_pass_issued: false
        });
      }

      if (req.method === 'GET' && route === '/verify/status') {
        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        if (!await profileServiceReady()) {
          return reply(res, 200, {
            verified: false,
            child: false,
            band: null,
            adult: false,
            verification_available: false,
            profiles_available: false,
            verification_state: 'account_only'
          });
        }

        const check = verificationReady
          ? await verifier.refresh(user.id)
          : { state: 'not_connected' };

        const profile = await profileFor(
          user.id,
          userToken(req)
        );

        const band = profileBand(profile);
        const child = profile?.access_tier === 'child';

        return reply(res, 200, {
          verified: !!band && !child,
          child,
          band,
          adult: band === '18plus',
          verification_available: verificationReady,
          profiles_available: true,
          ocr_birth_date: profile?.access_tier === 'ocr_unverified'
            ? profile.birth_date
            : null,
          verification_state: child
            ? 'child_limited'
            : band
              ? 'approved'
              : check.state
        });
      }

      if (req.method === 'POST' && route === '/veriff/webhook') {
        if (!verificationReady) {
          return reply(res, 503, {
            error: 'Automatic document verification is not connected.'
          });
        }

        const raw = await rawBody(req, 1_048_576);
        await verifier.notification(raw, req.headers);

        return reply(res, 200, { received: true });
      }

      if (req.method === 'GET' && route === '/challenge') {
        if (config.vercel) {
          const entries = await stateList('nonce:');

          for (const entry of entries) {
            if (entry.state_value.expiresAt <= clock()) {
              await stateDelete(entry.state_key);
            }
          }

          const active = entries.filter(
            entry => entry.state_value.expiresAt > clock()
          );

          if (active.length >= 5000) {
            return reply(res, 429, {
              error: 'Please try again in a moment.'
            });
          }
        } else {
          for (const [nonce, expiry] of nonces) {
            if (expiry <= clock()) {
              nonces.delete(nonce);
            }
          }

          if (nonces.size >= 5000) {
            return reply(res, 429, {
              error: 'Please try again in a moment.'
            });
          }
        }

        const nonce = crypto.randomBytes(24).toString('base64url');
        const expiresAt = clock() + 60_000;

        if (config.vercel) {
          await stateSet('nonce:' + nonce, { expiresAt });
        } else {
          nonces.set(nonce, expiresAt);
        }

        return reply(res, 200, { nonce });
      }

      if (req.method === 'POST' && route === '/enroll') {
        const input = await body(req);

        if (
          Object.hasOwn(input, 'dob') ||
          Object.hasOwn(input, 'band')
        ) {
          return reply(res, 400, {
            error:
              'Age must come from a verified account, not a client-supplied birth date or band.'
          });
        }

        const user = await userFrom(req);

        if (!user) {
          return reply(res, 401, { error: 'Sign in first.' });
        }

        if (!await profileServiceReady()) {
          return reply(res, 503, {
            error:
              'Run the updated schema.sql to enable the Supabase profile service.'
          });
        }

        const band = profileBand(
          await profileFor(user.id, userToken(req))
        );

        if (!band) {
          return reply(res, 403, {
            error:
              'Complete ID verification on the website before activating your pass.'
          });
        }

        const pub = input.pub;

        if (
          !pub ||
          pub.kty !== 'EC' ||
          pub.crv !== 'P-256' ||
          !/^[\w-]{43}$/.test(pub.x) ||
          !/^[\w-]{43}$/.test(pub.y) ||
          pub.d
        ) {
          return reply(res, 400, {
            error: 'A public P-256 device key is required.'
          });
        }

        const cleanPub = {
          kty: pub.kty,
          crv: pub.crv,
          x: pub.x,
          y: pub.y
        };

        crypto.createPublicKey({
          key: cleanPub,
          format: 'jwk'
        });

        const id = crypto.randomUUID();

        const payload = JSON.stringify({
          v: 2,
          id,
          pub: cleanPub,
          band,
          exp: clock() + 3_600_000
        });

        const sig = crypto.sign(
          'sha256',
          Buffer.from(payload),
          {
            key: privateKey,
            dsaEncoding: 'ieee-p1363'
          }
        ).toString('base64');

        const issuedAt = new Date(clock()).toISOString();

        issued.set(id, {
          band,
          issued_at: issuedAt
        });

        if (config.vercel) {
          await stateSet('issued:' + id, {
            band,
            issued_at: issuedAt
          });
        }

        return reply(res, 200, {
          data: JSON.parse(payload),
          payload,
          sig
        });
      }

      if (
        req.method === 'POST' &&
        ['/credential/check', '/content'].includes(route)
      ) {
        let p;

        try {
          p = await verifyProof(await body(req));
        } catch (error) {
          return reply(res, 401, { error: error.message });
        }

        if (route === '/credential/check') {
          return reply(res, 200, {
            valid: true,
            band: p.band,
            exp: p.exp
          });
        }

        if (!bandAllows(p.band, 18)) {
          return reply(res, 403, {
            error:
              'This particular test page requires the 18+ band.'
          });
        }

        const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="200"><rect width="480" height="200" rx="18" fill="#173d36"/><text x="240" y="92" text-anchor="middle" font-size="26" fill="#d3ed94">Your age pass checks out.</text><text x="240" y="130" text-anchor="middle" font-size="16" fill="white">Only your age band was needed.</text></svg>';

        return reply(res, 200, {
          meme: 'data:image/svg+xml;utf8,' + encodeURIComponent(svg)
        });
      }

      if (req.method === 'POST' && route === '/revoke') {
        if (!admin(req)) {
          return reply(res, 403, { error: 'Admin access required.' });
        }

        const { id } = await body(req);

        if (!UUID.test(id)) {
          return reply(res, 400, {
            error: 'Invalid credential identifier.'
          });
        }

        revoked.add(id);

        if (config.vercel) {
          await stateSet('revoked:' + id, {
            revoked_at: new Date(clock()).toISOString()
          });
        }

        if (localRevokedFile) {
          fs.mkdirSync(path.dirname(localRevokedFile), {
            recursive: true,
            mode: 0o700
          });

          fs.writeFileSync(
            localRevokedFile,
            JSON.stringify([...revoked]),
            { mode: 0o600 }
          );
        }

        return reply(res, 200, { revoked: id });
      }

      if (req.method === 'GET' && route === '/log') {
        if (!admin(req)) {
          return reply(res, 403, { error: 'Admin access required.' });
        }

        const credentials = config.vercel
          ? (await stateList('issued:')).map(entry => ({
            id: entry.state_key.slice('issued:'.length),
            ...entry.state_value
          }))
          : [...issued].map(([id, value]) => ({
            id,
            ...value
          }));

        const withRevocation = await Promise.all(
          credentials.map(async item => ({
            ...item,
            revoked: config.vercel
              ? !!await stateGet('revoked:' + item.id)
              : revoked.has(item.id)
          }))
        );

        return reply(res, 200, {
          credentials: withRevocation
        });
      }

      return reply(res, 404, { error: 'Not found.' });
    } catch (error) {
      if (res.headersSent) {
        res.destroy();
        return;
      }

      return reply(res, 400, {
        error: error instanceof SyntaxError
          ? 'Unreadable JSON request.'
          : error.message || 'Request could not be completed.'
      });
    }
  });
}

// Vercel imports and invokes this default request handler.
let vercelRequestHandler;

export default function handler(req, res) {
  if (!vercelRequestHandler) {
    const server = createApp({
      config: configuration()
    });

    vercelRequestHandler = server.listeners('request')[0];
  }

  return vercelRequestHandler(req, res);
}

// Start a listening server only when this file is run locally.
if (
  process.env.VERCEL !== '1' &&
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const config = configuration();

  createApp({ config }).listen(config.port, '127.0.0.1', () => {
    console.log('WebCompass: http://localhost:' + config.port);
    console.log(
      'Automatic ID verification: use /health to check live Veriff and Supabase configuration.'
    );
  });
}