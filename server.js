// Issuer + Gate in one file. Run: node server.js  (Node 18+, zero dependencies)
const http = require('http'), crypto = require('crypto');
const issuer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const nonces = new Map();   // nonce -> expiry
const creds = new Map();    // id -> { issued_at }   (the ONLY thing we store: no name, no ID, no DOB)
const revoked = new Set();

const log = (tag, msg) => console.log(`[${new Date().toISOString()}] ${tag.padEnd(8)} ${msg}`);  // terminal only
const send = (res, code, obj, type = 'application/json') => {
  res.writeHead(code, { 'content-type': type });
  res.end(type === 'application/json' ? JSON.stringify(obj) : obj);
};
const readBody = req => new Promise(r => {
  let d = ''; req.on('data', c => d += c);
  req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } });
});
const isAdult = dob => {
  const d = new Date(dob); if (isNaN(d)) return false;
  const cutoff = new Date(); cutoff.setFullYear(cutoff.getFullYear() - 18);
  return d <= cutoff;
};

const MEME = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="200"><rect width="400" height="200" fill="#222"/>
   <text x="200" y="90" fill="#fff" font-size="26" text-anchor="middle">me: *proves I'm 18*</text>
   <text x="200" y="130" fill="#0f0" font-size="22" text-anchor="middle">server: "ok, and nothing else"</text></svg>`);

const PAGE = `<!doctype html><title>Adult Internet</title>
<body style="font-family:sans-serif;text-align:center;margin-top:60px">
<h2>Adult-verified content</h2><div id="slot">🔒 Locked (no extension / no credential)</div></body>`;

http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url.startsWith('/restricted')) return send(res, 200, PAGE, 'text/html');

    if (req.method === 'GET' && req.url === '/challenge') {
      const nonce = crypto.randomBytes(16).toString('hex');
      nonces.set(nonce, Date.now() + 60_000);
      return send(res, 200, { nonce });
    }

    if (req.method === 'POST' && req.url === '/enroll') {
      const { pub, dob } = await readBody(req);   // MOCK ISSUER: real version = ID check, processed in memory
      if (!pub || !isAdult(dob)) return send(res, 403, { error: 'not verified as adult' });
      const id = crypto.randomUUID();
      const payload = JSON.stringify({ id, pub, over18: true, exp: Date.now() + 3600_000 });
      const sig = crypto.sign('sha256', Buffer.from(payload), issuer.privateKey).toString('base64');
      creds.set(id, { issued_at: new Date().toISOString() });
      log('ENROLL', `credential ${id} issued  over18=true`);
      return send(res, 200, { payload, sig });   // DOB is never stored
    }

    if (req.method === 'POST' && req.url === '/content') {
      const { credential: c, nonce, signature } = await readBody(req);
      const fail = why => { log('DENIED', why); return send(res, 401, { error: why }); };
      if (!c || !c.payload || !c.sig || !nonce || !signature) return fail('missing proof');

      const exp = nonces.get(nonce); nonces.delete(nonce);              // single use => replay fails
      if (!exp || exp < Date.now()) return fail('bad or reused nonce');

      if (!crypto.verify('sha256', Buffer.from(c.payload), issuer.publicKey, Buffer.from(c.sig, 'base64')))
        return fail('credential not signed by issuer');                 // forged / tampered

      const p = JSON.parse(c.payload);
      if (!p.over18 || p.exp < Date.now()) return fail('credential expired');
      if (revoked.has(p.id)) return fail('credential revoked');

      const devKey = crypto.createPublicKey({ key: p.pub, format: 'jwk' });
      if (!crypto.verify('sha256', Buffer.from(nonce), { key: devKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64')))
        return fail('device signature invalid (credential not bound to this device)'); // stolen credential

      log('GRANTED', `credential ${p.id}`);
      return send(res, 200, { meme: MEME });
    }

    if (req.method === 'POST' && req.url === '/revoke') {              // demo only: unauthenticated
      const { id } = await readBody(req); revoked.add(id); log('REVOKE', `credential ${id}`); return send(res, 200, { revoked: id });
    }
    send(res, 404, { error: 'not found' });
  } catch (e) { send(res, 400, { error: 'bad request' }); }
}).listen(3000, () => console.log('Gate running on http://localhost:3000/restricted'));