// Tech Tool PWA — iOS techs (and any browser). Scope: INITIATE activations + browse guides.
// It NEVER captures a code (iOS can't read SMS; manual entry isn't allowed) — the server's
// Android pool / fallback phone captures, and forwards the result here as a normal reply.
import { importAesKeyB64, encrypt, decrypt, unlockProvision,
  generateSigningKeypair, exportSpkiB64, exportPkcs8B64, importSigningPrivateKey, signCanonical } from './webcrypto.js';

// Same published provisioning bundle + PBKDF2 params as the Android app (Config.java).
// Served from the same GitHub Pages origin as this PWA (relative) — no CORS, cache-friendly.
const PROVISION_URL = 'provision.enc';
const PROV_SALT = 'I+GU5aPNAQiTelN3hz0aEA==';
const PROV_ITERS = 200000;
const CONTENT_BASE = '';

const $ = (s) => document.querySelector(s);
const digits = (n) => String(n || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
const LS = {
  get: (k) => localStorage.getItem('tt_' + k) || '',
  set: (k, v) => localStorage.setItem('tt_' + k, v),
  clear: () => Object.keys(localStorage).filter((k) => k.startsWith('tt_')).forEach((k) => localStorage.removeItem(k)),
};

let client = null, aesKey = null, myDigits = '';
let signingKey = null, myPubKeyB64 = '';

// ---- per-tech ECDSA P-256 signing identity (see src/tech-identity.js / Identity.java) ----
// Every device shares one MQTT broker login and one AES transport key, so a plaintext `from`
// field in the payload is forgeable by anyone holding that shared key. Signing every request
// with a locally-generated keypair (bound to this tech's number at admin APPROVE time) makes
// forging another tech's requests impossible without stealing their private key.
async function ensureIdentity() {
  const privB64 = LS.get('sigPriv');
  if (privB64 && LS.get('sigPub')) {
    signingKey = await importSigningPrivateKey(privB64);
    myPubKeyB64 = LS.get('sigPub');
    return;
  }
  const kp = await generateSigningKeypair();
  const [priv, pub] = await Promise.all([exportPkcs8B64(kp.privateKey), exportSpkiB64(kp.publicKey)]);
  LS.set('sigPriv', priv); LS.set('sigPub', pub);
  signingKey = kp.privateKey;
  myPubKeyB64 = pub;
}

function setStatus(s, cls) {
  const el = $('#status'); if (!el) return;
  el.textContent = s; el.className = 'dot ' + (cls || '');
}

// ---- provisioning (access code unlocks the broker creds + AES key) ----
async function provision(number, code) {
  const res = await fetch(PROVISION_URL, { cache: 'no-store' });
  if (!res.ok) throw new Error('provisioning fetch failed (' + res.status + ')');
  const provB64 = (await res.text()).trim();
  const creds = await unlockProvision(provB64, code, PROV_SALT, PROV_ITERS); // {mqttHost,mqttUser,mqttPass,aesKey}
  if (!creds.aesKey || !creds.mqttHost) throw new Error('bad provisioning bundle');
  LS.set('number', digits(number)); LS.set('host', creds.mqttHost);
  LS.set('user', creds.mqttUser || ''); LS.set('pass', creds.mqttPass || ''); LS.set('aes', creds.aesKey);
}

async function connect() {
  myDigits = LS.get('number');
  aesKey = await importAesKeyB64(LS.get('aes'));
  await ensureIdentity();
  const url = `wss://${LS.get('host')}:8884/mqtt`;
  setStatus('connecting…', 'busy');
  client = mqtt.connect(url, {
    username: LS.get('user'), password: LS.get('pass'), protocolVersion: 5,
    clientId: 'pwa-' + myDigits + '-' + Math.random().toString(16).slice(2, 8),
    reconnectPeriod: 5000,
  });
  client.on('connect', () => {
    setStatus('online', 'ok');
    client.subscribe('gilbarco/res/' + myDigits, { qos: 1 });
    client.subscribe('gilbarco/oncall', { qos: 1 }); // retained daily schedule
    client.subscribe('gilbarco/cfg/' + myDigits, { qos: 1 }); // retained per-tech config (On Call allow/deny)
  });
  client.on('reconnect', () => setStatus('reconnecting…', 'busy'));
  client.on('close', () => setStatus('offline', 'off'));
  client.on('error', (e) => setStatus('error: ' + e.message, 'off'));
  client.on('message', async (topic, payload) => {
    try {
      const j = JSON.parse(await decrypt(aesKey, payload.toString()));
      if (topic === 'gilbarco/oncall' && j.schedule) { setOnCall(j.schedule); return; }
      if (topic === 'gilbarco/cfg/' + myDigits) { if (j.onCallAllowed !== undefined) applyOnCallAllowed(j.onCallAllowed); return; }
      if (j.body) showReply(j.body);
    } catch { /* foreign/tampered */ }
  });
}

async function sendRequest(body) {
  if (!client || !client.connected) { showReply('Not connected — check your signal and try again.'); return; }
  const ts = Date.now();
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  // Canonical signed bytes MUST exactly match tech-identity.js / Identity.sign()'s field order.
  const canonical = `${myDigits}\n${ts}\n${nonce}\n${myPubKeyB64}\n${body}`;
  const sig = await signCanonical(signingKey, canonical);
  const enc = await encrypt(aesKey, JSON.stringify({ from: myDigits, body, ts, nonce, pubKey: myPubKeyB64, sig }));
  client.publish('gilbarco/req/' + myDigits, enc, { qos: 1 });
  showReply('Sent. Waiting for the activation code…');
}

function showReply(text) {
  const el = $('#reply'); if (el) { el.textContent = text; el.style.display = 'block'; }
}

// ---- guides (read-only; served from the hosted content the APK already uses) ----
async function loadGuides() {
  const box = $('#guides'); if (!box) return;
  box.textContent = 'loading…';
  try {
    const r = await fetch(CONTENT_BASE + 'pcn-manifest.json', { cache: 'no-store' });
    const m = await r.json();
    const docs = (m.docs || []);
    // Manifest `url`s are already percent-encoded absolute links — use them verbatim (running
    // encodeURI on them double-encodes the space to %2520 → 404). Only raw relative paths get encoded.
    const href = (d) => { const u = d.url || d.path || ''; return toPages(/^https?:\/\//i.test(u) ? u : CONTENT_BASE + u.split('/').map(encodeURIComponent).join('/')); };
    box.innerHTML = docs.length
      ? docs.map((d) => `<a class="guide" href="${esc(href(d))}" target="_blank" rel="noopener">${esc(d.name || d.title || 'Document')}</a>`).join('')
      : '<span class="muted">No guides published.</span>';
  } catch (e) { box.innerHTML = '<span class="muted">Couldn’t load guides (' + esc(e.message) + ').</span>'; }
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// GitHub Pages serves .pdf as application/pdf AND is same-origin as this PWA, so iOS renders
// it inline. raw.githubusercontent serves octet-stream (iOS won't preview → the tap appears to
// do nothing). Rewrite our repo's raw links to the Pages origin so docs open everywhere.
const toPages = (u) => String(u).replace(/^https?:\/\/raw\.githubusercontent\.com\/devinalonzo\/techtool\/(?:refs\/heads\/)?main\//i, 'https://devinalonzo.github.io/techtool/');

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

// Show/hide the whole On Call card per the server's per-tech permission (gilbarco/cfg).
// Persisted so a denied tech doesn't briefly see the card before MQTT connects.
function applyOnCallAllowed(allowed) {
  LS.set('oncall_allowed', allowed ? '1' : '0');
  const card = $('#oncallCard');
  if (card) card.style.display = allowed ? '' : 'none';
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
const PC_LABELS = { E300: 'Encore 300', E500: 'Encore 500', E700: 'Encore 700' };
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
function showApp() {
  $('#setup').style.display = 'none';
  $('#main').style.display = 'block';
  $('#me').textContent = myDigits;
  connect();
  loadGuides();
  initPumpCodes();
  applyOnCallAllowed(LS.get('oncall_allowed') !== '0'); // default allowed; cfg topic updates it live
  // Show the last schedule instantly (retained MQTT message refreshes it on connect).
  try { const c = LS.get('oncall'); if (c) ocSched = JSON.parse(c); } catch { /* */ }
  renderOnCall();
}

window.addEventListener('DOMContentLoaded', () => {
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
    try { await provision(num, code); showApp(); }
    catch (e) { $('#s_err').textContent = e.message.includes('GCM') || /operation-specific/i.test(e.message) ? 'Wrong access code.' : e.message; }
  });

  $('#send').addEventListener('click', () => {
    const v = $('#req').value.trim();
    if (v) sendRequest(v);
  });
  $('#unlink').addEventListener('click', () => { LS.clear(); location.reload(); });

  // On Call controls.
  $('#oc_prev').addEventListener('click', () => { ocMine = false; ocDate.setDate(ocDate.getDate() - 1); renderOnCall(); });
  $('#oc_next').addEventListener('click', () => { ocMine = false; ocDate.setDate(ocDate.getDate() + 1); renderOnCall(); });
  $('#oc_today').addEventListener('click', () => { ocMine = false; ocDate = new Date(); renderOnCall(); });
  $('#oc_mine').addEventListener('click', () => { ocMine = !ocMine; renderOnCall(); });

  if (LS.get('aes') && LS.get('number')) showApp();
});
