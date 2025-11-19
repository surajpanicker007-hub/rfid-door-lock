// public/app.js (ES module)
import base64url from "https://cdn.jsdelivr.net/npm/base64url@3.0.1/index.min.mjs";

// --- CONFIG: copy your Firebase Web app config here
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT.appspot.com",
  messagingSenderId: "SENDER_ID",
  appId: "APP_ID"
};

// init firebase (compat global)
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

// helpers
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
function show(msg, type='info'){ const n = $('#notif'); if(!n) return; n.textContent = msg; n.className = `notification show ${type}`; setTimeout(()=>n.className='notification',3500); }
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// DOM
const pages = $$('.page');
const navLinks = $$('.nav-link');
const userEmailSpan = $('#userEmail');
const btnSignOut = $('#btnSignOut');

const enrollBtn = $('#enrollBtn');
const fpLabel = $('#fpLabel');
const syncBtn = $('#syncBtn');
const passphraseInput = $('#passphrase');
const setPassBtn = $('#setPassBtn');
const clearPassBtn = $('#clearPassBtn');
const passStatus = $('#passStatus');

const usersList = $('#usersList');
const unlockBtn = $('#unlockBtn');

const logsList = $('#logsList');
const clearLogsBtn = $('#clearLogsBtn');

navLinks.forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    navLinks.forEach(l=>l.classList.remove('active'));
    a.classList.add('active');
    const page = a.dataset.page;
    pages.forEach(p=>p.classList.remove('active'));
    $('#'+page).classList.add('active');
  });
});

// anonymous sign-in helper: ensure user is signed in
async function ensureAnonSignIn(){
  return new Promise((resolve, reject) => {
    const unsub = auth.onAuthStateChanged(async user=>{
      unsub();
      if (user) {
        // already signed in
        resolve(user);
      } else {
        try {
          const result = await auth.signInAnonymously();
          resolve(result.user);
        } catch (e) {
          reject(e);
        }
      }
    });
  });
}

async function getIdToken() {
  const user = auth.currentUser;
  if (!user) throw new Error('Not authenticated');
  return await user.getIdToken();
}

// crypto helpers (WebCrypto)
let sessionKey = null;
let userSalt = null;
let currentUID = null;

function bufToHex(buf){ const bytes = new Uint8Array(buf); return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function hexToBuf(hex){ if(!hex) return new Uint8Array().buffer; const bytes = new Uint8Array(hex.length/2); for(let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16); return bytes.buffer; }

async function deriveKeyFromPassphrase(passphrase, saltHex) {
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  const salt = hexToBuf(saltHex);
  const baseKey = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
    name:'PBKDF2', salt, iterations: 200000, hash:'SHA-256'
  }, baseKey, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
  return key;
}
function bufToBase64(buf){ const bytes = new Uint8Array(buf); let str=''; for(let b of bytes) str += String.fromCharCode(b); return btoa(str); }
function base64ToBuf(b64){ const binary = atob(b64); const len = binary.length; const bytes = new Uint8Array(len); for(let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i); return bytes.buffer; }
async function encryptObject(obj){ if(!sessionKey) throw new Error('No key'); const iv = crypto.getRandomValues(new Uint8Array(12)); const pt = new TextEncoder().encode(JSON.stringify(obj)); const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, sessionKey, pt); return { iv: bufToBase64(iv), ct: bufToBase64(ct) }; }
async function decryptObject({ iv, ct }){ if(!sessionKey) throw new Error('No key'); const plaintext = await crypto.subtle.decrypt({ name:'AES-GCM', iv: base64ToBuf(iv) }, sessionKey, base64ToBuf(ct)); return JSON.parse(new TextDecoder().decode(plaintext)); }

// Firestore refs
function metaDocRef(uid){ return db.collection('users').doc(uid).collection('meta').doc('meta'); }
function fingerprintsColRef(uid){ return db.collection('users').doc(uid).collection('fingerprints'); }

// ensure salt presence in Firestore
async function ensureUserSalt(uid){
  const metaRef = metaDocRef(uid);
  const snap = await metaRef.get();
  if (snap.exists && snap.data().salt) {
    userSalt = snap.data().salt;
    return userSalt;
  } else {
    const saltBuf = crypto.getRandomValues(new Uint8Array(16));
    userSalt = bufToHex(saltBuf);
    await metaRef.set({ salt: userSalt });
    return userSalt;
  }
}

// real-time fingerprint list
let fpUnsub = null;
async function subscribeFingerprints(){
  if (!currentUID) return;
  if (fpUnsub) fpUnsub();
  const col = fingerprintsColRef(currentUID);
  fpUnsub = col.orderBy('createdAt','desc').onSnapshot(async snap=>{
    const rows = snap.docs.map(d=>({ id:d.id, ...d.data() }));
    await renderFingerprints(rows);
  });
}

async function renderFingerprints(rows){
  if (!rows.length) { usersList.innerHTML = `<div class="muted">No fingerprints enrolled</div>`; return; }
  const out = [];
  for (const r of rows) {
    try {
      const obj = await decryptObject({ iv: r.iv, ct: r.ct });
      out.push(`<div class="user-item"><div><strong>${escapeHtml(obj.label)}</strong><div class="muted">${new Date(obj.createdAt).toLocaleString()}</div></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    } catch(e) {
      out.push(`<div class="user-item"><div><strong>Encrypted fingerprint</strong></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    }
  }
  usersList.innerHTML = out.join('');
}
window.deleteFingerprint = async function(docId){
  if (!currentUID) return;
  if (!confirm('Delete?')) return;
  await fingerprintsColRef(currentUID).doc(docId).delete();
  show('Deleted','info');
};

// small conversions for WebAuthn responses
function abToBase64(buffer){ const bytes = new Uint8Array(buffer); let binary=''; for(let i=0;i<bytes.byteLength;i++) binary += String.fromCharCode(bytes[i]); return btoa(binary); }
function base64ToAb(b64){ const binary = atob(b64); const len = binary.length; const bytes = new Uint8Array(len); for(let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i); return bytes.buffer; }
function parseAttestation(cred){ return { id: cred.id, rawId: abToBase64(cred.rawId), response: { clientDataJSON: abToBase64(cred.response.clientDataJSON), attestationObject: abToBase64(cred.response.attestationObject) }, type: cred.type }; }
function parseAssertion(a){ return { id: a.id, rawId: abToBase64(a.rawId), response: { clientDataJSON: abToBase64(a.response.clientDataJSON), authenticatorData: abToBase64(a.response.authenticatorData), signature: abToBase64(a.response.signature), userHandle: a.response.userHandle ? abToBase64(a.response.userHandle) : null }, type: a.type }; }

// helper: POST to /api with idToken
async function postJSON(path, body){
  const headers = { "Content-Type": "application/json" };
  try {
    const token = await getIdToken();
    headers["Authorization"] = "Bearer " + token;
  } catch(e){}
  const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Server ${res.status}: ${txt}`);
  }
  return res.json();
}

// ENROLL (client -> /api/beginRegistration -> navigator.credentials.create -> /api/finishRegistration)
if (enrollBtn) enrollBtn.addEventListener('click', async ()=>{
  if (!auth.currentUser) { show('Sign in first','error'); return; }
  if (!sessionKey) { show('Set passphrase first','error'); return; }
  const label = (fpLabel.value || `FP ${new Date().toLocaleString()}`).trim();
  try {
    // request options
    const optionsResp = await postJSON('/api/beginRegistration', {});
    if (!optionsResp || !optionsResp.publicKey) throw new Error('Invalid server response');
    const publicKey = JSON.parse(JSON.stringify(optionsResp.publicKey));
    // decode base64url challenge and user.id
    publicKey.challenge = base64ToAb(optionsResp.publicKey.challenge);
    if (optionsResp.publicKey.user && optionsResp.publicKey.user.id) publicKey.user.id = base64ToAb(optionsResp.publicKey.user.id);
    if (optionsResp.publicKey.excludeCredentials) {
      publicKey.excludeCredentials = optionsResp.publicKey.excludeCredentials.map(c => ({ type: c.type, id: base64ToAb(c.id) }));
    }
    const cred = await navigator.credentials.create({ publicKey });
    if(!cred) throw new Error('Credential creation failed');
    const att = parseAttestation(cred);
    att.label = label;
    const finish = await postJSON('/api/finishRegistration', att);
    if (!finish || !finish.success) throw new Error(finish && finish.error || 'Server registration failed');

    // save encrypted metadata in Firestore under users/{uid}/fingerprints
    const metadata = { credentialId: att.rawId, label, createdAt: new Date().toISOString() };
    const enc = await encryptObject(metadata);
    const id = fingerprintsColRef(currentUID).doc().id;
    await fingerprintsColRef(currentUID).doc(id).set({ iv: enc.iv, ct: enc.ct, createdAt: firebase.firestore.FieldValue.serverTimestamp() });

    show('Enrolled '+label,'success');
    fpLabel.value = '';
  } catch(e){
    console.error(e);
    show('Enroll failed: '+(e.message||e),'error');
  }
});

// UNLOCK (client -> /api/beginLogin -> navigator.credentials.get -> /api/finishLogin)
if (unlockBtn) unlockBtn.addEventListener('click', async ()=>{
  if (!auth.currentUser) { show('Sign in first','error'); return; }
  try {
    const optionsResp = await postJSON('/api/beginLogin', {});
    if (!optionsResp || !optionsResp.publicKey) throw new Error('Invalid server response');
    const opts = optionsResp.publicKey;
    const publicKey = {};
    publicKey.challenge = base64ToAb(opts.challenge);
    publicKey.userVerification = opts.userVerification || 'preferred';
    publicKey.allowCredentials = (opts.allowCredentials || []).map(c => ({ type: c.type, id: base64ToAb(c.id) }));
    publicKey.rpId = opts.rpId || window.location.hostname;

    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) throw new Error('No assertion');
    const parsed = parseAssertion(assertion);
    const finish = await postJSON('/api/finishLogin', parsed);
    if (finish && finish.success) {
      updateLockUI('UNLOCKED');
      logAccess('UNLOCK','FINGERPRINT','SUCCESS');
      show('Unlocked','success');
    } else {
      updateLockUI('LOCKED');
      logAccess('UNLOCK','FINGERPRINT','FAILED');
      show('Unlock failed','error');
    }
  } catch(e) {
    console.error(e);
    updateLockUI('LOCKED');
    logAccess('UNLOCK','FINGERPRINT','FAILED');
    show('Auth error: '+(e.message||e),'error');
  }
});

// passphrase logic (derive AES-GCM key from user-provided passphrase)
setPassBtn.addEventListener('click', async ()=>{
  const pass = passphraseInput.value;
  if (!pass) { passStatus.textContent = 'Enter passphrase'; return; }
  if (!auth.currentUser) { passStatus.textContent = 'Sign in first'; return; }
  try {
    currentUID = auth.currentUser.uid;
    await ensureUserSalt(currentUID);
    sessionKey = await deriveKeyFromPassphrase(pass, userSalt);
    passStatus.textContent = 'Key derived';
    await subscribeFingerprints();
  } catch(e){
    passStatus.textContent = 'Derive failed: '+(e.message||e);
  }
});
clearPassBtn.addEventListener('click', ()=>{ sessionKey = null; passphraseInput.value=''; passStatus.textContent='Cleared'; });

// sync manual
syncBtn.addEventListener('click', async ()=> {
  try {
    if (!currentUID) { show('Sign in first','error'); return; }
    if (!sessionKey) { show('Set passphrase first','error'); return; }
    const snap = await fingerprintsColRef(currentUID).get();
    const rows = snap.docs.map(d=>({ id:d.id, ...d.data() }));
    await renderFingerprints(rows);
    show('Synced','info');
  } catch(e){ show('Sync failed: '+(e.message||e),'error'); }
});

// logs
function logAccess(action, method, status){ const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]'); logs.unshift({ timestamp: new Date().toLocaleString(), action, method, status }); if(logs.length>200) logs.pop(); localStorage.setItem('accessLogs', JSON.stringify(logs)); renderLogs(); }
function renderLogs(){ const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]'); if(!logs.length) return logsList.innerHTML = `<div class="muted">No logs</div>`; logsList.innerHTML = logs.map(l=>`<div class="log-item"><div><strong>${l.timestamp}</strong><div class="muted">${l.method}</div></div><div>${l.action}</div><div>${l.status}</div></div>`).join(''); }
clearLogsBtn.addEventListener('click', ()=>{ if(confirm('Clear logs?')){ localStorage.removeItem('accessLogs'); renderLogs(); } });

// auth state
auth.onAuthStateChanged(async user=>{
  if (user) {
    currentUID = user.uid;
    userEmailSpan.textContent = user.isAnonymous ? `Anonymous (${user.uid.slice(0,6)})` : (user.email || user.displayName || '');
    btnSignOut.style.display = 'inline-block';
    // ensure salt exists for this user
    await ensureUserSalt(currentUID);
    // subscribe only after passphrase derived
    renderLogs();
  } else {
    currentUID = null;
    userEmailSpan.textContent = '';
    btnSignOut.style.display = 'none';
    usersList.innerHTML = `<div class="muted">Please sign in</div>`;
  }
});

btnSignOut.addEventListener('click', ()=> auth.signOut());

// start: ensure anonymous sign-in immediately
(async ()=>{
  try {
    await ensureAnonSignIn();
    show('Signed in (anonymous)','info');
  } catch(e){
    console.error('Auth init failed', e);
    show('Auth failed: '+(e.message||e),'error');
  }
})();

// helper: update lock UI
function updateLockUI(state){ const icon = $('#lockIcon'); const txt = $('#lockStatus'); if (state==='UNLOCKED'){ icon.textContent='🔓'; icon.classList.remove('locked'); icon.classList.add('unlocked'); txt.textContent='UNLOCKED'; } else { icon.textContent='🔒'; icon.classList.remove('unlocked'); icon.classList.add('locked'); txt.textContent='LOCKED'; } }
