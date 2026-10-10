const SERVER = 'http://localhost:3000';

// --- non-extractable key stored in IndexedDB (the "can't copy it" property) ---
const openDb = () => new Promise((res, rej) => {
  const r = indexedDB.open('agegate', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('k');
  r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
});
const idb = async (mode, fn) => {
  const d = await openDb();
  return new Promise((res, rej) => {
    const t = d.transaction('k', mode); const rq = fn(t.objectStore('k'));
    t.oncomplete = () => res(rq.result); t.onerror = () => rej(t.error);
  });
};
async function getKeys() {
  let k = await idb('readonly', s => s.get('pair'));
  if (!k) {
    const p = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    k = { privateKey: p.privateKey, publicKey: p.publicKey };
    await idb('readwrite', s => s.put(k, 'pair'));
  }
  return k;
}
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const post = async (path, body) => {
  const r = await fetch(SERVER + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { ok: r.ok, ...(await r.json()) };
};

async function handle(m) {
  const { privateKey, publicKey } = await getKeys();
  if (m.type === 'enroll') {
    const j = await crypto.subtle.exportKey('jwk', publicKey);
    const r = await post('/enroll', { pub: { kty: j.kty, crv: j.crv, x: j.x, y: j.y }, dob: m.dob });
    if (!r.ok) return { error: r.error };
    await chrome.storage.local.set({ cred: { payload: r.payload, sig: r.sig } });
    return { ok: true };
  }
  if (m.type === 'content') {
    const { cred } = await chrome.storage.local.get('cred');
    if (!cred) return { error: 'not verified yet' };
    const { nonce } = await (await fetch(SERVER + '/challenge')).json();
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(nonce));
    const r = await post('/content', { credential: cred, nonce, signature: b64(sig) });
    return r.ok ? { meme: r.meme } : { error: r.error };
  }
  if (m.type === 'extract') {   // Attack demo: try to steal the private key
    try { await crypto.subtle.exportKey('jwk', privateKey); return { ok: 'KEY LEAKED (bad!)' }; }
    catch (e) { return { error: 'exportKey blocked: ' + e.message }; }
  }
}
chrome.runtime.onMessage.addListener((m, _s, send) => { handle(m).then(send).catch(e => send({ error: String(e) })); return true; });
