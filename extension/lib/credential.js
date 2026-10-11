import { BANDS } from './age.js';

export function readPayload(credential, now = Date.now()) {
  if (!credential || typeof credential.payload !== 'string' || credential.payload.length > 4096 ||
      typeof credential.sig !== 'string') throw new Error('No verified age pass.');
  const p = JSON.parse(credential.payload);
  if (p.v !== 2 || typeof p.id !== 'string' || !Object.hasOwn(BANDS, p.band) ||
      !Number.isSafeInteger(p.exp) || !p.pub || p.pub.kty !== 'EC' || p.pub.crv !== 'P-256') {
    throw new Error('Your age pass could not be read. Activate it again.');
  }
  if (p.exp <= now) throw new Error('Your age pass has expired. Activate it again.');
  return p;
}

export function bytesFromBase64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid signature.');
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

export function base64FromBytes(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)));
}

export async function verifyCredential(credential, issuerJwk, deviceJwk, now = Date.now()) {
  const payload = readPayload(credential, now);
  const key = await crypto.subtle.importKey('jwk', issuerJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
    bytesFromBase64(credential.sig), new TextEncoder().encode(credential.payload));
  if (!valid) throw new Error('Your age pass signature is invalid. Activate it again.');
  if (!deviceJwk || payload.pub.x !== deviceJwk.x || payload.pub.y !== deviceJwk.y) {
    throw new Error('This age pass belongs to another browser device.');
  }
  return payload;
}
