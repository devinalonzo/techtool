// Tech Tool PWA — iOS techs (and any browser). Scope: initiate activation requests.
// It never captures a code; the server-side pool / fallback phone captures and forwards the
// result here as a normal reply.
import { importAesKeyB64, encrypt, decrypt, deriveKeyBytesFromCode,
  generateSigningKeypair, exportSpkiB64, exportPkcs8B64, importSigningPrivateKey, signCanonical,
  eciesDecrypt, wrapSecret, unwrapSecret, clearWrapKey, verifyServerSig } from './webcrypto.js';

// Server message-signing public key (P-256 SPKI, base64). Replies must verify against it.
const SERVER_SIGN_PUBKEY = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5pPV0AYtV8/SOLlLkzv4/eJFQt5cEt5oT/bp9LetxN1XTIwKdsGLJsYorxNZsqKG4MGsqokWbCBtcRygKpofCg==';

// Onboarding front-door derived from the access code — nothing is fetched or published. The public
// salts/iters + the (non-secret) broker host must match src/crypto.js and Config.java byte-for-byte.
// >>> Set BROKER_HOST to your HiveMQ cluster hostname (e.g. "abc123.s1.eu.hivemq.cloud"). <<<
const BROKER_HOST = 'f2a1c65a71b640bda2a4b0e0ac5aa887.s1.eu.hivemq.cloud';
const BOOTSTRAP_USER = 'bootstrap';
const SALT_BOOT = '88RcOoVIlrLZ0p4zXzmC3w==';
const SALT_AES = '03RHBDCT06DXL55HYuT67A==';
const FRONTDOOR_ITERS = 200000;
const CONTENT_BASE = '';
const b64 = (u8) => btoa(String.fromCharCode(...u8));

const $ = (s) => document.querySelector(s);
const digits = (n) => String(n || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
const LS = {
  get: (k) => localStorage.getItem('tt_' + k) || '',
  set: (k, v) => localStorage.setItem('tt_' + k, v),
  clear: () => Object.keys(localStorage).filter((k) => k.startsWith('tt_')).forEach((k) => localStorage.removeItem(k)),
};
// Stored values go through wrapSecret/unwrapSecret (see webcrypto.js). Async — every caller runs
// in an async context. Older unwrapped values are upgraded in place on first read.
const setSecret = async (k, v) => LS.set(k, await wrapSecret(v));
const getSecret = async (k) => {
  const stored = LS.get(k);
  if (!stored) return '';
  const { value, migrated } = await unwrapSecret(stored);
  if (migrated) { try { await setSecret(k, value); } catch { /* */ } }
  return value;
};

let client = null, aesKey = null, myDigits = '';
let signingKey = null, myPubKeyB64 = '';
let statusResolve = null; // pending STATUS request awaiting a reply (see requestStatus())
// Per-device credential mode: once the server delivers this device's own login (over the
// svc/reg/<digits>/res channel), connect with it and use the svc/t/<digits>/ topic set;
// otherwise use the provisioned login + legacy topics and poll the reg channel on each STATUS.
// T = the active topic set; strings match the server's topic scheme.
let T = null, usingPdc = false, credSwitching = false;

// ---- per-device ECDSA P-256 signing identity ----
// Each request is signed with a locally-generated keypair (established at first connect) so the
// server can confirm which device sent it.
async function ensureIdentity() {
  const privB64 = await getSecret('sigPriv');
  if (privB64 && LS.get('sigPub')) {
    signingKey = await importSigningPrivateKey(privB64);
    myPubKeyB64 = LS.get('sigPub');
    return;
  }
  const kp = await generateSigningKeypair();
  const [priv, pub] = await Promise.all([exportPkcs8B64(kp.privateKey), exportSpkiB64(kp.publicKey)]);
  await setSecret('sigPriv', priv); LS.set('sigPub', pub); // priv wrapped at rest; pub is public
  signingKey = kp.privateKey;
  myPubKeyB64 = pub;
}

function setStatus(s, cls) {
  const el = $('#status'); if (!el) return;
  el.textContent = s; el.className = 'dot ' + (cls || '');
}

// ---- provisioning: derive the low-priv onboarding front-door from the access code ----
// Nothing is fetched or published. Two independent PBKDF2 derivations from the one access code give
// the bootstrap MQTT password + the AES envelope key; the host + username are baked non-secrets. The
// real per-device credential is delivered encrypted over MQTT after the office approves this device.
// A wrong access code yields a wrong bootstrap login that the broker rejects at connect.
async function provision(number, code) {
  if (!code) throw new Error('enter the access code');
  const pass = b64(await deriveKeyBytesFromCode(code, SALT_BOOT, FRONTDOOR_ITERS));
  const aes = b64(await deriveKeyBytesFromCode(code, SALT_AES, FRONTDOOR_ITERS));
  LS.set('number', digits(number)); LS.set('host', BROKER_HOST);
  await setSecret('user', BOOTSTRAP_USER); await setSecret('pass', pass); await setSecret('aes', aes);
}

async function connect() {
  if (client) { try { client.end(true); } catch { /* */ } client = null; } // reconnects (cred switch/fallback) start clean
  myDigits = LS.get('number');
  aesKey = await importAesKeyB64(await getSecret('aes'));
  await ensureIdentity();
  // Pick the active mode: this device's own login + its topic set when one is stored, else the
  // provisioned login + legacy topics (+ the reg onboarding channel).
  const pdcUser = await getSecret('pdc_user'), pdcPass = await getSecret('pdc_pass');
  usingPdc = !!(pdcUser && pdcPass);
  const sub = `svc/t/${myDigits}/`;
  const rq = `svc/reg/${myDigits}/req`, rs = `svc/reg/${myDigits}/res`;
  // Unprovisioned: use the reg onboarding channel ONLY. The bootstrap login is scoped to svc/reg/#,
  // so touching any legacy/broadcast topic would get this client disconnected. Real traffic (and the
  // oncall/cfg broadcasts) only start once this device holds its own per-device cred, which switches
  // to its svc/t/<digits>/# subtree.
  T = usingPdc
    ? { req: sub + 'req', res: sub + 'res', cfg: sub + 'cfg', oncall: sub + 'oncall', regReq: null, regRes: null }
    : { req: rq, res: rs, cfg: null, oncall: null, regReq: rq, regRes: rs };
  const user = usingPdc ? pdcUser : await getSecret('user');
  const pass = usingPdc ? pdcPass : await getSecret('pass');
  const url = `wss://${LS.get('host')}:8884/mqtt`;
  setStatus('connecting…', 'busy');
  client = mqtt.connect(url, {
    username: user, password: pass, protocolVersion: 5,
    clientId: 'pwa-' + myDigits + '-' + Math.random().toString(16).slice(2, 8),
    reconnectPeriod: 5000,
  });
  client.on('connect', () => {
    setStatus('online', 'ok');
    client.subscribe(T.res, { qos: 1 });
    if (T.oncall) client.subscribe(T.oncall, { qos: 1 }); // retained daily schedule (subtree only)
    if (T.cfg) client.subscribe(T.cfg, { qos: 1 }); // retained per-tech config (subtree only)
    // Onboarding channel: the server delivers this device's own login here. While unprovisioned
    // it's the same topic as T.res, so only subscribe again if it differs.
    if (T.regRes && T.regRes !== T.res) client.subscribe(T.regRes, { qos: 1 });
  });
  client.on('reconnect', () => setStatus('reconnecting…', 'busy'));
  client.on('close', () => setStatus('offline', 'off'));
  client.on('error', (e) => {
    setStatus('error: ' + e.message, 'off');
    // If the per-device login stops working, drop it and reconnect with the provisioned login so
    // the device can re-onboard. 134/135 = MQTT5 CONNACK bad-credentials / not-authorized.
    if (usingPdc && (e.code === 134 || e.code === 135 || /bad user ?name|not authorized/i.test(e.message))) {
      fallbackToSharedCred();
    }
  });
  client.on('message', async (topic, payload) => {
    try {
      const j = JSON.parse(await decrypt(aesKey, payload.toString()));
      if (topic === T.oncall) {
        const canon = `oncall\n${j.ts}\n${j.schedule || ''}`; // schedule is a JSON string
        if (!j.ssig || !(await verifyServerSig(SERVER_SIGN_PUBKEY, canon, j.ssig))) return;
        if (j.schedule) setOnCall(JSON.parse(j.schedule));
        return;
      }
      if (topic === T.cfg) {
        // Two generations (src/server-sign.js cfgCanonical): "cfg" (On Call only) and "cfg2"
        // once the mileage/gpswt flags exist. The PWA only enforces On Call (the new flags gate
        // Android-only tabs: BLE + foreground GPS aren't available in a browser).
        const v3 = j.visionAllowed === true; // only cfg3 when My Day is actually on (see server-sign.js)
        const v2 = j.mileageAllowed !== undefined || j.gpswtAllowed !== undefined;
        const canon = v3
          ? `cfg3\n${j.ts}\n${j.onCallAllowed === true}\n${j.mileageAllowed === true}\n${j.gpswtAllowed === true}\n${j.visionAllowed === true}`
          : v2
          ? `cfg2\n${j.ts}\n${j.onCallAllowed === true}\n${j.mileageAllowed === true}\n${j.gpswtAllowed === true}`
          : `cfg\n${j.ts}\n${j.onCallAllowed === true}`;
        if (!j.ssig || !(await verifyServerSig(SERVER_SIGN_PUBKEY, canon, j.ssig))) return;
        if (j.onCallAllowed !== undefined) applyOnCallAllowed(j.onCallAllowed);
        // My Day is a PWA feature too, so the PWA enforces visionAllowed (unlike the Android-only
        // mileage/gpswt flags). Defaults OFF until the server enables it for this tech.
        if (j.visionAllowed !== undefined) applyVisionAllowed(j.visionAllowed);
        return;
      }
      // A res reply (on our res topic, or the reg onboarding channel) must verify against the
      // server key before it's used; retained oncall/cfg above verify the same way.
      if (topic === T.res || (T.regRes && topic === T.regRes)) {
        const canon = `res\n${j.ts}\n` + (j.enc === 'ecies' && j.ecies
          ? `e\n${j.ecies.epk}\n${j.ecies.iv}\n${j.ecies.data}` : `b\n${j.body || ''}`);
        if (!j.ssig || !(await verifyServerSig(SERVER_SIGN_PUBKEY, canon, j.ssig))) return;
      }
      // A reg-channel reply can carry this device's own login (see handleCredBundle) — process it
      // after the signature check and before the body, so a STATUS that carries it still resolves.
      if (T.regRes && topic === T.regRes && j.cred) await handleCredBundle(j.cred);
      // Resolve the reply body: some replies are per-recipient encrypted (enc:'ecies') — decrypt
      // with our own key; otherwise use the plain body.
      let body = j.body || '';
      if (j.enc === 'ecies' && j.ecies) {
        try { body = await eciesDecrypt(await getSecret('sigPriv'), j.ecies); }
        catch { return; } // not for us / undecryptable
      }
      // A STATUS reply is consumed by whoever's awaiting one (see requestStatus()), never shown in
      // the reply box. Always swallowed: STATUS is polled on two channels, so a second reply can
      // arrive after the first resolved.
      const m = /^STATUS\s+(\S+)/.exec(body);
      if (m) {
        if (statusResolve) { const r = statusResolve; statusResolve = null; r(m[1]); }
        return;
      }
      // Remote RESET (admin Reset button / owner app): wipe this device's setup exactly like the
      // Unlink button — mirrors Android's MainActivity.doReset, which the PWA never had. The body
      // only reaches here after the server-signature check above, so it can't be forged.
      if (/^RESET$/i.test(body.trim())) { await doRemoteReset(); return; }
      // My Day (Vision) replies drive the My Day card, not the generic reply box.
      if (/^(MYDAY|VISION OK|VISION FAIL)/i.test(body)) { handleMyDayReply(body); return; }
      if (body) showReply(body);
    } catch { /* unreadable message */ }
  });
  // Wait for the actual connection (or a failure) before returning, so onboard() can safely
  // publish a STATUS request right after awaiting this - mqtt.connect() itself only kicks off
  // the connection in the background and returns immediately.
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out connecting')), 15000);
    client.once('connect', () => { clearTimeout(timer); resolve(); });
    client.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// Verify + decrypt + persist this device's own login delivered over the reg channel, then
// reconnect on it. The bundle is ecies-encrypted to this device's key and carries a server
// signature; process it only after both checks pass.
async function handleCredBundle(c) {
  if (usingPdc || credSwitching || !c || !c.ecies) return;
  const canon = `cred\n${c.ts}\n${c.ecies.epk}\n${c.ecies.iv}\n${c.ecies.data}`;
  if (!c.ssig || !(await verifyServerSig(SERVER_SIGN_PUBKEY, canon, c.ssig))) return;
  let cred;
  try { cred = JSON.parse(await eciesDecrypt(await getSecret('sigPriv'), c.ecies)); }
  catch { return; } // not for us / undecryptable
  if (!cred.mqttUser || !cred.mqttPass) return;
  credSwitching = true;
  try {
    await setSecret('pdc_user', cred.mqttUser);
    await setSecret('pdc_pass', cred.mqttPass);
    setStatus('switching to device credential…', 'busy');
    await connect(); // re-reads the stored login -> per-device mode + topic set
  } catch { /* next connect() picks up the stored login */ }
  credSwitching = false;
}

// The per-device login stopped working: drop it and reconnect with the provisioned login + legacy
// topics so the device can re-onboard.
async function fallbackToSharedCred() {
  if (credSwitching) return;
  credSwitching = true;
  localStorage.removeItem('tt_pdc_user');
  localStorage.removeItem('tt_pdc_pass');
  try { await connect(); } catch { /* retry path: the user's next action reconnects */ }
  credSwitching = false;
  // The server is likely mid-rotate (its console automation takes ~15-30s to mint the fresh
  // login); keep polling so the new credential is picked up without a manual refresh.
  scheduleCredPoll();
}

// Remote RESET / unlink: wipe everything this device stores (setup, identity, credentials) and
// restart at the setup screen, so re-onboarding derives a fresh front-door + mints a new identity.
async function doRemoteReset() {
  try { if (client) client.end(true); } catch { /* */ }
  LS.clear();
  await clearWrapKey();
  location.reload();
}

// While approved-but-unprovisioned, re-poll STATUS on the reg channel every 20s (bounded) — the
// per-device cred bundle rides in on those replies (handleCredBundle), and a single poll races
// the server's ~15-30s provision window after an approve/rotate. Self-stops once the per-device
// login is active, on disconnect, or after ~3.5 minutes.
let credPollTimer = null;
function scheduleCredPoll() {
  if (usingPdc || credPollTimer) return;
  let tries = 0;
  credPollTimer = setInterval(async () => {
    if (usingPdc || !client || !client.connected || ++tries > 10) {
      clearInterval(credPollTimer); credPollTimer = null; return;
    }
    try { await publishSigned('STATUS'); } catch { /* next tick retries */ }
  }, 20000);
}

// Build the encrypted, signed request envelope (fresh ts/nonce/signature each call).
async function signedEnvelope(body) {
  const ts = Date.now();
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  // Canonical signed bytes; field order must match the other clients.
  const canonical = `${myDigits}\n${ts}\n${nonce}\n${myPubKeyB64}\n${body}`;
  const sig = await signCanonical(signingKey, canonical);
  // caps lists optional features this client supports (ecies replies, per-device login handoff);
  // the server uses what it recognizes and ignores the rest.
  return encrypt(aesKey, JSON.stringify({ from: myDigits, body, ts, nonce, pubKey: myPubKeyB64, sig, caps: ['ecies', 'pdc'] }));
}

// Publish a signed, encrypted request body - the shared primitive behind both the "New
// activation" send button and the onboarding STATUS/REGISTER handshake below.
async function publishSigned(body) {
  if (!client || !client.connected) throw new Error('not connected');
  client.publish(T.req, await signedEnvelope(body), { qos: 1 });
  // Also send STATUS on the reg onboarding channel — that's where the server returns this device's
  // own login once available. Skip when reg IS the request topic (unprovisioned mode) to avoid a
  // duplicate. Each send is a fresh envelope (a byte-identical copy would be rejected as a replay).
  if (T.regReq && T.regReq !== T.req && /^status$/i.test(body.trim())) {
    try { client.publish(T.regReq, await signedEnvelope(body), { qos: 1 }); } catch { /* best-effort */ }
  }
}

async function sendRequest(body) {
  if (!client || !client.connected) { showReply('Not connected — check your signal and try again.'); return; }
  try { await publishSigned(body); showReply('Sent. Waiting for the activation code…'); }
  catch (e) { showReply('Send failed: ' + e.message); }
}

// Ask the office for this number's registration standing and wait for its STATUS reply (or a
// timeout -> null, treated as a connectivity problem, not "unregistered" - the server replies
// STATUS for ANY sender, registered or not, so a genuine reply of 'none' means truly unregistered).
// 8s was too tight for a real cellular MQTT round trip (connect+publish+server hop+reply) and
// was surfacing "couldn't reach the office" on connections that just hadn't replied yet -
// Android's equivalent (MainActivity.java's requestStatus()) doesn't time out at all, it just
// waits for handleStatus() whenever the reply arrives.
function requestStatus(timeoutMs = 25000) {
  return new Promise((resolve) => {
    statusResolve = resolve;
    const timer = setTimeout(() => { if (statusResolve === resolve) { statusResolve = null; resolve(null); } }, timeoutMs);
    publishSigned('STATUS').catch(() => {
      if (statusResolve === resolve) { statusResolve = null; clearTimeout(timer); resolve(null); }
    });
  });
}

function showReply(text) {
  const el = $('#reply'); if (el) { el.textContent = text; el.style.display = 'block'; }
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ---- On Call schedule (day view + My Schedule) ----
let ocSched = null;          // { days:{iso:[{name,role,note}]}, names:[…] }
let ocDate = new Date();     // viewed day
let ocMine = false;
const isoOf = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
const niceDate = (d) => d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
const niceIso = (iso) => { const [y, m, dd] = iso.split('-').map(Number); return niceDate(new Date(y, m - 1, dd)); };

function setOnCall(schedule) {
  ocSched = schedule;
  try { localStorage.setItem('tt_oncall', JSON.stringify(schedule)); } catch { /* quota */ }
  renderOnCall();
}

// Show/hide the whole On Call card per the server's per-tech permission (svc/cfg).
// Persisted so a denied tech doesn't briefly see the card before MQTT connects.
function applyOnCallAllowed(allowed) {
  LS.set('oncall_allowed', allowed ? '1' : '0');
  const card = $('#oncallCard');
  if (card) card.style.display = allowed ? '' : 'none';
}

// ---- My Day (Vision RFS assigned calls) ----
let mdJobs = [];        // last MYDAY-OK jobs
let mdDay = 0;          // -1 yesterday, 0 today, +1 tomorrow (default today)
// Show/hide the My Day card per the server's per-tech permission (cfg3 visionAllowed). Default OFF
// (opt-in), persisted so a denied tech doesn't flash the card before MQTT connects.
function applyVisionAllowed(allowed) {
  LS.set('vision_allowed', allowed ? '1' : '0');
  const card = $('#myDayCard');
  if (card) card.style.display = allowed ? '' : 'none';
}

const mdIso = (offset) => { const d = new Date(); d.setDate(d.getDate() + offset); return isoOf(d); };
const mdMdy = (offset) => { const d = new Date(); d.setDate(d.getDate() + offset); return `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}/${d.getFullYear()}`; };

function sendMyDay(refresh) { sendRequest('MYDAY' + (refresh ? ' REFRESH' : '')); }

function promptVisionLink() {
  const code = prompt('Vision technician code:', LS.get('vision_code') || '');
  if (!code) return;
  const pass = prompt('Vision password (your login, not the 4-digit app PIN):');
  if (!pass) return;
  LS.set('vision_code', code.trim());
  const nonce = String(Date.now() % 100000);
  sendRequest(`VISION ${code.trim()} ${pass.trim()} ${nonce}`);
  const list = $('#md_list'); if (list) { list.className = 'muted'; list.textContent = 'Verifying your Vision login…'; }
}

function handleMyDayReply(body) {
  const list = $('#md_list');
  if (/^VISION OK/i.test(body)) { if (list) { list.className = 'muted'; list.textContent = 'Vision linked. Loading your day…'; } sendMyDay(true); return; }
  if (/^VISION FAIL/i.test(body)) { if (list) { list.className = 'muted'; list.textContent = 'Vision link failed: ' + body.replace(/^VISION FAIL\s*-?\s*/i, ''); } return; }
  if (/^MYDAY-WAIT/i.test(body)) { if (list) { list.className = 'muted'; list.textContent = 'Loading your day from the office…'; } return; }
  if (/^MYDAY-ERR/i.test(body)) { if (list) { list.className = 'muted'; list.textContent = 'Could not load your day: ' + body.replace(/^MYDAY-ERR\s*/i, ''); } return; }
  if (/^MYDAY-OK/i.test(body)) {
    try { const j = JSON.parse(body.replace(/^MYDAY-OK\s*/i, '')); mdJobs = Array.isArray(j.jobs) ? j.jobs : []; }
    catch { mdJobs = []; }
    try { localStorage.setItem('tt_myday', JSON.stringify(mdJobs)); } catch { /* quota */ }
    renderMyDay();
  }
}

function renderMyDay() {
  const list = $('#md_list'); if (!list) return;
  const iso = mdIso(mdDay), mdy = mdMdy(mdDay);
  const d = new Date(); d.setDate(d.getDate() + mdDay);
  const rel = mdDay === 0 ? 'Today' : mdDay === -1 ? 'Yesterday' : mdDay === 1 ? 'Tomorrow' : null;
  const label = rel ? rel + '  ·  ' + niceDate(d) : niceDate(d);
  const dateEl = $('#md_date'); if (dateEl) dateEl.textContent = label;
  const rows = mdJobs.filter((c) => c && (c.schedDay === iso || c.scheduledDate === mdy));
  if (!rows.length) { list.className = 'muted'; list.textContent = 'No calls for ' + label + '.'; return; }
  list.className = '';
  list.innerHTML = rows.map((c) => `<div style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,.08)">
      <div style="font-weight:600">${esc((c.startTime ? c.startTime + '  ' : '') + (c.customer || '?'))}</div>
      <div class="muted" style="font-size:13px">${esc([c.address, c.city, c.state, c.zip].filter(Boolean).join(', '))}</div>
      <div class="muted" style="font-size:12.5px">${esc([c.callType, 'WO ' + (c.workOrder || ''), c.status].filter(Boolean).join('  ·  '))}</div>
    </div>`).join('');
}

function initMyDay() {
  const on = (id, fn) => { const el = $('#' + id); if (el) el.onclick = fn; };
  on('md_link', promptVisionLink);
  on('md_refresh', () => sendMyDay(true));
  on('md_prev', () => { mdDay--; renderMyDay(); });
  on('md_next', () => { mdDay++; renderMyDay(); });
  on('md_today', () => { mdDay = 0; renderMyDay(); });
  try { const c = localStorage.getItem('tt_myday'); if (c) mdJobs = JSON.parse(c) || []; } catch { /* */ }
  applyVisionAllowed(LS.get('vision_allowed') === '1'); // default OFF; cfg3 updates it live
  renderMyDay();
  if (LS.get('vision_code')) sendMyDay(false); // linked already -> pull the day
}

function renderOnCall() {
  const list = $('#oc_list'), dateEl = $('#oc_date'), mineBtn = $('#oc_mine');
  if (!list) return;
  if (mineBtn) mineBtn.textContent = ocMine ? 'Day view' : 'My Schedule';
  if (dateEl) dateEl.textContent = ocMine ? 'My Schedule' : niceDate(ocDate);
  if (!ocSched || !ocSched.days) { list.className = 'muted'; list.textContent = 'Waiting for the schedule…'; return; }
  list.className = '';

  if (ocMine) {
    let me = LS.get('oncall_name');
    if (!me) { pickName(); return; }
    const today = isoOf(new Date());
    const rows = [];
    for (const iso of Object.keys(ocSched.days).sort()) {
      if (iso < today) continue;
      for (const s of ocSched.days[iso]) {
        for (const n of (s.names || [])) {
          if (n.toLowerCase() !== me.toLowerCase()) continue;
          rows.push(ocRow(niceIso(iso) + '  ·  ' + esc(s.section)));
        }
      }
    }
    list.innerHTML = (rows.length ? rows.join('') : `<div class="muted">You're not on the schedule for any upcoming day (as "${esc(me)}").</div>`)
      + `<button class="alt" id="oc_change" style="margin-top:12px">Change name (${esc(me)})</button>`;
    const cb = $('#oc_change'); if (cb) cb.addEventListener('click', pickName);
    return;
  }

  const arr = ocSched.days[isoOf(ocDate)] || [];
  list.innerHTML = arr.length
    ? arr.map((s) => ocBubble(s.section, s.names || [])).join('')
    : '<div class="muted">No schedule for this day.</div>';
}

// A section bubble: bold header (e.g. "Metro") + the people in it.
function ocBubble(section, names) {
  const body = names.length ? names.map(esc).join('<br>') : '—';
  return `<div style="background:#0d1117;border-radius:10px;padding:11px 14px;margin-bottom:8px">`
    + `<div style="color:#7fb2ff;font-size:12.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase">${esc(section)}</div>`
    + `<div style="font-size:16px;margin-top:3px;line-height:1.35">${body}</div></div>`;
}

// A single line (used by My Schedule): "Wed, Jun 24 · Metro".
function ocRow(primary) {
  return `<div style="background:#0d1117;border-radius:10px;padding:10px 12px;margin-bottom:8px">${primary}</div>`;
}

function pickName() {
  if (!ocSched || !(ocSched.names || []).length) { ocMine = false; renderOnCall(); return; }
  const list = $('#oc_list');
  list.className = '';
  list.innerHTML = '<div class="muted" style="margin-bottom:8px">Pick your name:</div>'
    + ocSched.names.map((n, i) => `<button class="alt" data-n="${i}" style="margin:4px 0">${esc(n)}</button>`).join('');
  list.querySelectorAll('button[data-n]').forEach((b) => b.addEventListener('click', () => {
    LS.set('oncall_name', ocSched.names[+b.dataset.n]); ocMine = true; renderOnCall();
  }));
}

// ---- Pump error codes (offline lookup; mirrors the APK + Pump Codes Pro keypad) ----
let pcCodes = null;   // cached array from ppu-codes.json
let pcInput = '';     // what the keypad has entered (e.g. "5118", "E10")
const PC_MAX = 6;     // longest code we accept from the pad
const PC_LABELS = { E300: 'Type 300', E500: 'Type 500', E700: 'Type 700' };
const pcLabel = (t) => PC_LABELS[t] || t;
const pcClean = (s) => String(s || '').replace(/\r\n|\r|\n/g, ' ').replace(/\s+/g, ' ').trim();

async function loadPumpCodes() {
  if (pcCodes) return pcCodes;
  const r = await fetch(CONTENT_BASE + 'ppu-codes.json', { cache: 'force-cache' });
  if (!r.ok) throw new Error('codes fetch failed (' + r.status + ')');
  pcCodes = await r.json();
  return pcCodes;
}

function pcUpdateDisplay() {
  const d = $('#pc_display'); if (!d) return;
  if (pcInput) { d.textContent = pcInput; d.classList.remove('empty'); }
  else { d.textContent = 'enter code'; d.classList.add('empty'); }
}

function pcCard(o, note) {
  const models = (o.models || []).map(pcLabel).join(', ');
  const fix = pcClean(o.fix) || 'See the Service Manual in Service guides below.';
  const sev = pcClean(o.sev);
  return `<div class="codecard">`
    + `<div class="coderow"><span class="codetag">${esc(o.code)}</span>${sev ? `<span class="sev">${esc(sev)}</span>` : ''}</div>`
    + `<div class="codedesc">${esc(pcClean(o.desc) || '—')}</div>`
    + (models ? `<div class="codemeta">Models: ${esc(models)}</div>` : '')
    + `<div class="codefix"><b>Fix:</b> ${esc(fix)}</div>`
    + (note ? `<div class="codemeta">${esc(note)}</div>` : '')
    + `</div>`;
}

function pcSetResult(html, hint) {
  const box = $('#pc_result'); if (!box) return;
  box.className = hint ? 'pc-hint' : '';
  box.innerHTML = html;
}

async function doPumpCodeLookup() {
  const code = pcInput.trim();
  if (!code) { pcSetResult('Enter an error code first — use the keypad below.', true); return; }
  const model = ($('#pc_model') && $('#pc_model').value) || '';
  let all;
  try { all = await loadPumpCodes(); }
  catch (e) { pcSetResult('Couldn’t load codes (' + esc(e.message) + ').', true); return; }

  const q = code.toLowerCase();
  let hits = all.filter((o) => String(o.code || '').toLowerCase() === q);
  if (!hits.length) hits = all.filter((o) => String(o.code || '').toLowerCase().startsWith(q)); // forgiving
  if (!hits.length) {
    pcSetResult('No match for code <b>' + esc(code) + '</b>' + (model ? ' on ' + esc(pcLabel(model)) : '')
      + '. Double-check the number, or try a different dispenser type.', true);
    return;
  }
  // Narrow to the chosen dispenser when possible; universal (no-model) entries always qualify.
  let note = '';
  if (model) {
    const m = hits.filter((o) => !(o.models || []).length || (o.models || []).includes(model));
    if (m.length) hits = m; else note = 'Not specifically listed for ' + pcLabel(model) + ' — showing the closest match.';
  }
  pcSetResult(hits.slice(0, 8).map((o) => pcCard(o, hits.length === 1 ? note : '')).join(''), false);
}

function initPumpCodes() {
  const pad = $('#pc_pad'); if (!pad || pad.dataset.wired) return;
  pad.dataset.wired = '1';
  pad.addEventListener('click', (e) => {
    const b = e.target.closest('[data-k]'); if (!b) return;
    const k = b.getAttribute('data-k');
    if (k === 'clear') pcInput = '';
    else if (pcInput.length < PC_MAX) pcInput += k;
    pcUpdateDisplay();
  });
  $('#pc_go').addEventListener('click', doPumpCodeLookup);
  const sel = $('#pc_model');
  if (sel) sel.addEventListener('change', () => { if (pcInput) doPumpCodeLookup(); });
  pcUpdateDisplay();
}

// ---- UI wiring ----
// Reveals the full app. Only ever called once onboard() has a server-confirmed 'approved'
// STATUS - connect() has already run by then (onboard() awaits it before checking status), so
// this no longer (re)connects itself.
function showApp() {
  $('#setup').style.display = 'none';
  $('#pending').style.display = 'none';
  $('#main').style.display = 'block';
  $('#me').textContent = myDigits;
  initPumpCodes();
  initMyDay();
  applyOnCallAllowed(LS.get('oncall_allowed') !== '0'); // default allowed; cfg topic updates it live
  // Show the last schedule instantly (retained MQTT message refreshes it on connect).
  try { const c = LS.get('oncall'); if (c) ocSched = JSON.parse(c); } catch { /* */ }
  renderOnCall();
}

function showPending(title, msg, retryable) {
  $('#setup').style.display = 'none';
  $('#main').style.display = 'none';
  $('#pending').style.display = 'block';
  $('#p_title').textContent = title;
  $('#p_msg').textContent = msg || '';
  $('#p_retry').style.display = retryable ? 'block' : 'none';
}

// The gate the PWA was missing entirely before this fix: connect, ask the office for this
// number's actual registration standing, and only reveal the full app once the server has
// confirmed 'approved' - mirrors MainActivity.java's startMqttIfReady()/requestStatus() flow on
// Android, which the PWA never had an equivalent of.
async function onboard() {
  $('#setup').style.display = 'none';
  showPending('Checking your access…', 'Connecting to the office.');
  try { await connect(); }
  catch (e) { showPending("Couldn't connect", e.message || 'Check your connection and try again.', true); return; }
  const status = await requestStatus();
  if (status == null) { showPending("Couldn't reach the office", 'Check your connection, then tap Check again.', true); return; }
  if (status === 'approved') {
    showApp();
    // Approved but still on the bootstrap login: the per-device cred may still be minting
    // (~15-30s console automation after APPROVE) — poll until it arrives.
    if (!usingPdc) scheduleCredPoll();
    return;
  }
  if (status === 'blocked') { showPending('Access blocked', 'Contact your admin if you believe this is a mistake.'); return; }
  if (status === 'pending') { showPending('Pending approval', "Your access request is waiting on an admin. You'll get access once it's approved."); return; }
  // status === 'none': the office has never seen this number before.
  await promptAndRegister();
}

async function promptAndRegister() {
  const name = (window.prompt('This looks like your first time. Enter your name to request access:') || '').trim().slice(0, 60);
  if (!name) { showPending('Access needed', 'Enter your name to finish requesting access.', true); return; }
  try { await publishSigned('REGISTER ' + name); }
  catch (e) { showPending("Couldn't send your request", e.message || 'Check your connection and try again.', true); return; }
  showPending('Request sent', "Thanks — your request was sent for approval. You'll get access once an admin approves it.");
}

window.addEventListener('DOMContentLoaded', () => {
  // Show setup until provisioned (onboard() flips to #main, once approved, when config exists).
  // Kept here rather than inline in index.html so the page needs no inline-script allowance.
  if (!localStorage.getItem('tt_aes')) $('#setup').style.display = 'block';

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(() => {});

  // iOS home-screen PWAs (navigator.standalone) silently ignore target="_blank" — tapping a
  // doc link does nothing. Open document links in-place instead (same-origin PDFs render
  // inline; swipe back returns to the app). Laptop/Android keep their new-tab behavior.
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a.guide, a.sb');
    if (!a || !window.navigator.standalone) return;
    e.preventDefault();
    window.location.href = a.href;
  });

  $('#doSetup').addEventListener('click', async () => {
    const num = $('#s_number').value, code = $('#s_code').value;
    if (digits(num).length !== 10) { $('#s_err').textContent = 'Enter your 10-digit number.'; return; }
    $('#s_err').textContent = 'Activating…';
    // provision() just derives locally now; a wrong access code surfaces later as a connection
    // failure in onboard() (the broker rejects the derived bootstrap login), shown by showPending.
    try { await provision(num, code); onboard(); }
    catch (e) { $('#s_err').textContent = e.message; }
  });
  $('#p_retry').addEventListener('click', onboard);

  $('#send').addEventListener('click', () => {
    const v = $('#req').value.trim();
    if (v) sendRequest(v);
  });
  $('#unlink').addEventListener('click', async () => { LS.clear(); await clearWrapKey(); location.reload(); });

  // On Call controls.
  $('#oc_prev').addEventListener('click', () => { ocMine = false; ocDate.setDate(ocDate.getDate() - 1); renderOnCall(); });
  $('#oc_next').addEventListener('click', () => { ocMine = false; ocDate.setDate(ocDate.getDate() + 1); renderOnCall(); });
  $('#oc_today').addEventListener('click', () => { ocMine = false; ocDate = new Date(); renderOnCall(); });
  $('#oc_mine').addEventListener('click', () => { ocMine = !ocMine; renderOnCall(); });

  if (LS.get('aes') && LS.get('number')) onboard();
});
