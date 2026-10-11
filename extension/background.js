import { bandAllows } from './lib/age.js';
import { validateRatings, redirectRules, siteForUrl, admissionRule } from './lib/policy.js';
import { verifyCredential, base64FromBytes } from './lib/credential.js';

const SERVER = 'http://localhost:3000';
const GATE = chrome.runtime.getURL('gate.html');
let keyPromise;
let tasks = Promise.resolve();
const serial = task => {
  const result = tasks.then(task);
  tasks = result.catch(() => {});
  return result;
};
const errorText = error => error?.message || 'This check could not finish. Please try again.';

async function request(path, options = {}) {
  let response;
  try { response = await fetch(SERVER + path, { cache: 'no-store', ...options, signal: AbortSignal.timeout(12_000) }); }
  catch { throw new Error('The local service is offline. Start the server on localhost:3000, then try again.'); }
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'The age check could not finish.');
  return value;
}
const post = (path, body, token) => request(path, {
  method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
  body: JSON.stringify(body)
});

function getKeys() {
  if (!keyPromise) keyPromise = (async () => {
    const db = await new Promise((resolve, reject) => {
      const open = indexedDB.open('webcompass', 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    const transact = (mode, run) => new Promise((resolve, reject) => {
      const tx = db.transaction('keys', mode);
      const operation = run(tx.objectStore('keys'));
      tx.oncomplete = () => resolve(operation.result);
      tx.onerror = tx.onabort = () => reject(tx.error || new Error('Could not save the device key.'));
    });
    try {
      let pair = await transact('readonly', store => store.get('pair'));
      if (!pair) {
        pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
        await transact('readwrite', store => store.put(pair, 'pair'));
      }
      return pair;
    } finally { db.close(); }
  })().catch(error => { keyPromise = undefined; throw error; });
  return keyPromise;
}

async function forgetPermit(tabId) {
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [100_000 + tabId] });
  await chrome.storage.session.remove('permit:' + tabId);
  await chrome.alarms.clear('permit:' + tabId);
}
async function forgetAllPermits() {
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  if (existing.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: existing.map(rule => rule.id) });
  const state = await chrome.storage.session.get(null);
  const permits = Object.keys(state).filter(key => key.startsWith('permit:'));
  if (permits.length) await chrome.storage.session.remove(permits);
}

// The static rules are already active before this asynchronous initialization.
const ready = (async () => {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  await forgetAllPermits();
  const sites = validateRatings(await (await fetch(chrome.runtime.getURL('site-ratings.json'))).json());
  const previous = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: previous.map(rule => rule.id), addRules: redirectRules(sites, GATE)
  });
  return sites;
})();
ready.catch(() => {}); // A failed initialization leaves the static redirects active.

async function localPass() {
  const { cred, issuer } = await chrome.storage.local.get(['cred', 'issuer']);
  if (!cred || !issuer) throw new Error('Activate your age pass in the WebCompass extension first.');
  const pair = await getKeys();
  const device = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const payload = await verifyCredential(cred, issuer, device);
  return { cred, pair, payload };
}
async function proofFor(pass) {
  const { nonce } = await request('/challenge');
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(nonce)) throw new Error('The local service returned an invalid challenge.');
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pass.pair.privateKey, new TextEncoder().encode(nonce));
  return { credential: pass.cred, nonce, signature: base64FromBytes(signature) };
}
async function status(sites) {
  const { token } = await chrome.storage.session.get('token');
  try {
    const { payload } = await localPass();
    return { ok: true, signedIn: !!token, verified: true, band: payload.band, exp: payload.exp, sites };
  } catch (error) {
    return { ok: true, signedIn: !!token, verified: false, reason: errorText(error), sites };
  }
}
async function clearPass(resetIssuer = false) {
  await forgetAllPermits();
  await chrome.storage.local.remove(resetIssuer ? ['cred', 'issuer'] : ['cred']);
}
async function handle(message, sender) {
  const sites = await ready;
  if (message.type === 'status') return status(sites);
  if (message.type === 'login') {
    await clearPass();
    await chrome.storage.session.remove('token');
    const config = await request('/config');
    if (!/^https:\/\/[a-z0-9.-]+\.supabase\.co$/i.test(config.supabaseUrl)) throw new Error('The Supabase project address is invalid.');
    const response = await fetch(config.supabaseUrl + '/auth/v1/token?grant_type=password', {
      method: 'POST', headers: { apikey: config.supabaseKey, 'content-type': 'application/json' },
      body: JSON.stringify({ email: message.email, password: message.password }), signal: AbortSignal.timeout(12_000)
    });
    const result = await response.json();
    if (!response.ok || !result.access_token) throw new Error(result.error_description || result.msg || 'Sign-in failed. Check your email and password.');
    await chrome.storage.session.set({ token: result.access_token });
    return status(sites);
  }
  if (message.type === 'enroll') {
    const { token } = await chrome.storage.session.get('token');
    if (!token) throw new Error('Sign in to the extension first.');
    await clearPass();
    const incomingIssuer = await request('/issuer/public-key');
    const { issuer: pinned } = await chrome.storage.local.get('issuer');
    if (pinned && (pinned.x !== incomingIssuer.x || pinned.y !== incomingIssuer.y)) {
      throw new Error('The local issuer key changed. Check your backend, then reset the local connection below.');
    }
    const pair = await getKeys();
    const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const pub = { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y };
    const credential = await post('/enroll', { pub }, token);
    await verifyCredential(credential, incomingIssuer, pub);
    await chrome.storage.local.set({ issuer: incomingIssuer, cred: { payload: credential.payload, sig: credential.sig } });
    return status(sites);
  }
  if (message.type === 'logout' || message.type === 'reset') {
    await clearPass(message.type === 'reset');
    await chrome.storage.session.remove('token');
    return status(sites);
  }
  if (message.type === 'extract') {
    const pair = await getKeys();
    try { await crypto.subtle.exportKey('jwk', pair.privateKey); throw new Error('The private key unexpectedly became exportable.'); }
    catch (error) {
      if (error.name !== 'InvalidAccessError') throw error;
      return { ok: true, note: 'The private device key cannot be exported through Web Crypto.' };
    }
  }
  if (message.type === 'content') {
    const pass = await localPass();
    return post('/content', await proofFor(pass));
  }
  if (message.type === 'gate') {
    const site = sites.find(item => item.id === message.siteId);
    const target = typeof message.target === 'string' ? message.target : '';
    if (!site || siteForUrl(sites, target)?.id !== site.id) return { ok: true, allowed: false, state: 'setup', reason: 'This site needs an age check. Open the extension to activate your pass.' };
    let pass;
    try { pass = await localPass(); }
    catch (error) { return { ok: true, allowed: false, state: 'verify', site, reason: errorText(error) }; }
    if (!bandAllows(pass.payload.band, site.minimumAge)) return {
      ok: true, allowed: false, state: 'age', site, band: pass.payload.band,
      reason: site.reason
    };
    try {
      const checked = await post('/credential/check', await proofFor(pass));
      if (!checked.valid || checked.band !== pass.payload.band || checked.exp !== pass.payload.exp || checked.exp <= Date.now()) {
        throw new Error('Your age pass has expired. Activate it again.');
      }
      const url = new URL(target);
      url.hash = ''; // Request rules do not depend on a page fragment.
      const tabId = sender.tab.id;
      const rule = admissionRule(tabId, url.href);
      const supported = await chrome.declarativeNetRequest.isRegexSupported({ regex: rule.condition.regexFilter, isCaseSensitive: true });
      if (!supported.isSupported) throw new Error('This link cannot be checked. Open the site homepage instead.');
      if (pass.payload.exp <= Date.now()) throw new Error('Your age pass has expired. Activate it again.');
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [rule.id], addRules: [rule] });
      const created = Date.now();
      await chrome.storage.session.set({ ['permit:' + tabId]: { target: url.href, created } });
      await chrome.alarms.create('permit:' + tabId, { when: Date.now() + 30_000 });
      // This is a one-navigation permit, not a lasting domain-wide allow rule.
      // The normal cleanup is onCommitted/onErrorOccurred; this timer handles a stalled load.
      setTimeout(() => {
        serial(async () => {
          const key = 'permit:' + tabId;
          const state = await chrome.storage.session.get(key);
          if (state[key]?.created === created) await forgetPermit(tabId);
        }).catch(() => {});
      }, 10_000);
      await chrome.tabs.update(tabId, { url: url.href });
      return { ok: true, allowed: true };
    } catch (error) {
      await forgetPermit(sender.tab.id);
      return { ok: true, allowed: false, state: 'check', site, reason: errorText(error) };
    }
  }
  throw new Error('Unknown extension action.');
}

function pagePath(sender) {
  try {
    const url = new URL(sender.url);
    return url.protocol === 'chrome-extension:' && url.hostname === chrome.runtime.id ? url.pathname : null;
  } catch { return null; }
}
function permittedSender(message, sender) {
  if (!message || sender.id !== chrome.runtime.id) return false;
  if (message.type === 'gate') return pagePath(sender) === '/gate.html' && Number.isInteger(sender.tab?.id) && sender.frameId === 0;
  if (['status', 'login', 'enroll', 'logout', 'reset', 'extract'].includes(message.type)) return pagePath(sender) === '/popup.html';
  if (message.type === 'content') {
    try { const url = new URL(sender.url); return url.origin === SERVER && url.pathname === '/restricted' && sender.frameId === 0; }
    catch { return false; }
  }
  return false;
}

chrome.runtime.onMessage.addListener((message, sender, send) => {
  if (!permittedSender(message, sender)) { send({ error: 'This page cannot request that action.' }); return false; }
  serial(() => handle(message, sender)).then(send).catch(error => send({ error: errorText(error) }));
  return true;
});
chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0) return;
  serial(async () => {
    await ready;
    const key = 'permit:' + details.tabId;
    const state = await chrome.storage.session.get(key);
    if (state[key] && details.timeStamp >= state[key].created) await forgetPermit(details.tabId);
  }).catch(() => {});
});
chrome.webNavigation.onErrorOccurred.addListener(details => {
  if (details.frameId === 0) serial(() => forgetPermit(details.tabId)).catch(() => {});
});
chrome.tabs.onRemoved.addListener(tabId => { serial(() => forgetPermit(tabId)).catch(() => {}); });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name.startsWith('permit:')) serial(() => forgetPermit(Number(alarm.name.slice(7)))).catch(() => {});
});
