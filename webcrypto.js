// PWA transport crypto — wire-compatible with the PC's src/crypto.js and the Android Crypto.java:
// AES-256-GCM, wire = iv(12) || ciphertext || tag(16), base64; PBKDF2-SHA256 provisioning
// (deriveKey). Standard Web Crypto API, so it runs in iOS Safari AND in Node (globalThis.crypto)
// for testing. (WebCrypto appends the GCM tag to the ciphertext, which is exactly the PC format.)
const subtle = globalThis.crypto.subtle;
const IV_LEN = 12;

const b64enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(String(s));

export async function importAesKey(rawKeyBytes) {
  return subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Import a base64 32-byte transport key (MQTT_AES_KEY).
export async function importAesKeyB64(b64) {
  return importAesKey(b64dec(b64));
}

export async function encrypt(key, plaintext) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext)));
  const out = new Uint8Array(IV_LEN + ct.length);
  out.set(iv, 0); out.set(ct, IV_LEN);
  return b64enc(out);
}

export async function decrypt(key, b64) {
  const raw = b64dec(b64);
  const iv = raw.slice(0, IV_LEN);
  const ct = raw.slice(IV_LEN);
  return new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

// PBKDF2-SHA256 -> 32-byte key, matching the PC's deriveKey / Android deriveKey (same salt+iters).
// Used to unlock the published provision.enc (broker creds + AES key) from the access code.
export async function deriveKeyBytesFromCode(code, saltB64, iters = 200000) {
  const base = await subtle.importKey('raw', utf8(code), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: b64dec(saltB64), iterations: iters, hash: 'SHA-256' }, base, 256);
  return new Uint8Array(bits);
}

// Decrypt the provisioning bundle (provision.enc, base64 iv||ct||tag) with the access code.
export async function unlockProvision(provB64, code, saltB64, iters = 200000) {
  const key = await importAesKey(await deriveKeyBytesFromCode(code, saltB64, iters));
  return JSON.parse(await decrypt(key, provB64));
}

// ---- Per-tech ECDSA P-256 signing identity (see src/tech-identity.js / Identity.java) ----
// Every device shares one MQTT broker login and one AES transport key, so a plaintext `from`
// field in the payload is forgeable by anyone holding that shared key. Signing every request
// with a locally-generated, per-device keypair (bound to this tech's number at admin APPROVE
// time) makes forging another tech's requests impossible without stealing their private key.

export async function generateSigningKeypair() {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
export async function exportSpkiB64(publicKey) {
  return b64enc(await subtle.exportKey('spki', publicKey));
}
export async function exportPkcs8B64(privateKey) {
  return b64enc(await subtle.exportKey('pkcs8', privateKey));
}
export async function importSigningPrivateKey(pkcs8B64) {
  return subtle.importKey('pkcs8', b64dec(pkcs8B64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
// Canonical signed bytes MUST exactly match the PC's tech-identity.js canonical() and
// Android's Identity.sign() field ordering: from + "\n" + ts + "\n" + nonce + "\n" + pubKey +
// "\n" + body. WebCrypto's ECDSA signature output is natively raw r||s (P1363, 64 bytes for
// P-256) — this is the canonical wire format, no conversion needed (unlike Java's Signature,
// which defaults to ASN.1 DER and has to convert on the Android side).
export async function signCanonical(privateKey, canonicalStr) {
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8(canonicalStr));
  return b64enc(sig);
}

export const _internals = { b64enc, b64dec };
