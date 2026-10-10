// Red Team script. Run with server up: node attack.js
const crypto = require('crypto'); const S = 'http://localhost:3000';
const post = async (p, b) => { const r = await fetch(S + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }); return { status: r.status, body: await r.json() }; };
const getNonce = async () => (await (await fetch(S + '/challenge')).json()).nonce;
const mk = () => { const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); const j = k.publicKey.export({ format: 'jwk' }); return { ...k, jwk: { kty: j.kty, crv: j.crv, x: j.x, y: j.y } }; };
const sign = (k, n) => crypto.sign('sha256', Buffer.from(n), { key: k.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
const show = (name, r, shouldPass) => console.log((r.status === 200) === shouldPass ? '✅' : '❌ UNEXPECTED', name.padEnd(40), r.status, r.body.error || 'meme served');

(async () => {
  const alex = mk(), sam = mk();
  show('Sam enrolls with under-18 DOB', await post('/enroll', { pub: sam.jwk, dob: '2015-01-01' }), false);
  const cred = (await post('/enroll', { pub: alex.jwk, dob: '1990-01-01' })).body;

  show('1. No credential at all', await post('/content', {}), false);

  const n1 = await getNonce(); const good = { credential: cred, nonce: n1, signature: sign(alex, n1) };
  show('ALEX: valid access', await post('/content', good), true);
  show('2. Replay Alex\'s captured request', await post('/content', good), false);

  const n2 = await getNonce();
  show('3. Sam uses STOLEN credential + own key', await post('/content', { credential: cred, nonce: n2, signature: sign(sam, n2) }), false);

  const n3 = await getNonce(); const forged = { ...cred, payload: cred.payload.replace(/"exp":\d+/, '"exp":9999999999999') };
  show('4. Forged credential (edited expiry)', await post('/content', { credential: forged, nonce: n3, signature: sign(alex, n3) }), false);

  const n4 = await getNonce(); const selfSigned = { payload: JSON.stringify({ id: 'x', pub: sam.jwk, over18: true, exp: 9999999999999 }) };
  selfSigned.sig = crypto.sign('sha256', Buffer.from(selfSigned.payload), sam.privateKey).toString('base64');
  show('5. Self-signed credential', await post('/content', { credential: selfSigned, nonce: n4, signature: sign(sam, n4) }), false);

  await post('/revoke', { id: JSON.parse(cred.payload).id });
  const n5 = await getNonce();
  show('6. Alex\'s credential revoked (leak)', await post('/content', { credential: cred, nonce: n5, signature: sign(alex, n5) }), false);

  console.log('\nServer log:', JSON.stringify(await (await fetch(S + '/log')).json()));
})();
