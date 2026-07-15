// PWA transport crypto — wire-compatible with the app's other clients: AES-256-GCM, wire =
// iv(12) || ciphertext || tag(16), base64; PBKDF2-SHA256 for provisioning. Standard Web Crypto
// API, so it runs in iOS Safari and in Node (globalThis.crypto) for testing. (WebCrypto appends
// the GCM tag to the ciphertext.)
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

// PBKDF2-SHA256 -> 32-byte key (same salt+iters as the other clients). Used to unlock the
// provisioning bundle from the access code.
export async function deriveKeyBytesFromCode(code, saltB64, iters = 200000) {
  const base = await subtle.importKey('raw', utf8(code), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: b64dec(saltB64), iterations: iters, hash: 'SHA-256' }, base, 256);
  return new Uint8Array(bits);
}

// Decrypt the provisioning bundle (base64 iv||ct||tag) with the access code.
export async function unlockProvision(provB64, code, saltB64, iters = 200000) {
  const key = await importAesKey(await deriveKeyBytesFromCode(code, saltB64, iters));
  return JSON.parse(await decrypt(key, provB64));
}

// ---- per-device ECDSA P-256 signing identity ----
// Each request is signed with a locally-generated, per-device keypair so the server can confirm
// which device sent it.

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
// Canonical signed bytes match the other clients' field ordering: from + "\n" + ts + "\n" +
// nonce + "\n" + pubKey + "\n" + body. WebCrypto's ECDSA output is raw r||s (P1363, 64 bytes for
// P-256) — the wire format used here, no conversion needed.
export async function signCanonical(privateKey, canonicalStr) {
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8(canonicalStr));
  return b64enc(sig);
}

// ---- ECIES decrypt (per-recipient reply encryption) ----
// The server encrypts some replies to this device's P-256 public key. We decrypt with the same
// key we sign requests with — but a WebCrypto ECDSA key object can't do ECDH, so the stored PKCS8
// private key is re-imported as an ECDH key (same underlying EC scalar). Wire format: env
// {epk:<b64 uncompressed 65B>, iv, data(ct||tag)}.
const ECIES_SALT = utf8('app-ecies-salt-v1');
const ECIES_INFO = utf8('app-ecies-v1');
export async function eciesDecrypt(pkcs8PrivB64, env) {
  const ecdhPriv = await subtle.importKey('pkcs8', b64dec(pkcs8PrivB64), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const ephemPub = await subtle.importKey('raw', b64dec(env.epk), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephemPub }, ecdhPriv, 256); // 32-byte X coord
  const hkdfKey = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const keyBits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ECIES_SALT, info: ECIES_INFO }, hkdfKey, 256);
  const aesKey = await subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['decrypt']);
  return new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: b64dec(env.iv) }, aesKey, b64dec(env.data)));
}

// ---- at-rest wrapping of stored values ----
// A non-extractable AES-GCM key held in IndexedDB wraps the stored values; only in-page code with
// the IndexedDB key can unwrap them. Wrapped values carry a "v1:" prefix.
const IDB_DB = 'tt-secure', IDB_STORE = 'keys', WRAP_KEY_ID = 'wrapKey', WRAP_PREFIX = 'v1:';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(IDB_DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(IDB_STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
function idbReq(store, mode, fn) {
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = fn(tx.objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }));
}
async function wrapKey() {
  let k = await idbReq(IDB_STORE, 'readonly', (s) => s.get(WRAP_KEY_ID));
  if (k) return k;
  k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false /* non-extractable */, ['encrypt', 'decrypt']);
  await idbReq(IDB_STORE, 'readwrite', (s) => s.put(k, WRAP_KEY_ID));
  return k;
}
export async function clearWrapKey() { try { await idbReq(IDB_STORE, 'readwrite', (s) => s.delete(WRAP_KEY_ID)); } catch { /* */ } }

export async function wrapSecret(plaintext) {
  const key = await wrapKey();
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext)));
  const out = new Uint8Array(IV_LEN + ct.length); out.set(iv, 0); out.set(ct, IV_LEN);
  return WRAP_PREFIX + b64enc(out);
}
// Returns { value, migrated } — migrated=true means `stored` was legacy plaintext and the caller
// should re-store the (now-wrappable) value.
export async function unwrapSecret(stored) {
  if (!stored) return { value: '', migrated: false };
  if (!stored.startsWith(WRAP_PREFIX)) return { value: stored, migrated: true }; // legacy plaintext
  const key = await wrapKey();
  const raw = b64dec(stored.slice(WRAP_PREFIX.length));
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, IV_LEN) }, key, raw.slice(IV_LEN));
  return { value: new TextDecoder().decode(pt), migrated: false };
}

// ---- verify a server signature (P-256 ECDSA, raw r||s) against the server key ----
// The server signs its replies; a reply must verify before it's used. Same P1363 form we produce.
export async function verifyServerSig(pubKeyB64, canonicalStr, sigB64) {
  try {
    const key = await subtle.importKey('spki', b64dec(pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64dec(sigB64), utf8(canonicalStr));
  } catch { return false; }
}

export const _internals = { b64enc, b64dec };
