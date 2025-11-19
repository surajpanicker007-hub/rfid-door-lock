// app.js (client) — communicates with /api endpoints on the same host

const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function show(msg, type='info'){ const n = $('#notif'); if(!n) return; n.textContent = msg; n.className = `notification show ${type}`; setTimeout(()=>n.className='notification',3500); }

const pages = $$('.page');
const navLinks = $$('.nav-link');
const navToggle = $('#navToggle');
const navLinksWrap = $('#navLinks');

const btnSignIn = $('#btnSignIn');
const btnSignOut = $('#btnSignOut');
const userEmailSpan = $('#userEmail');
const authModal = $('#authModal');
const authMsg = $('#authMsg');
const authEmail = $('#authEmail');
const authPassword = $('#authPassword');
const btnLogin = $('#btnLogin');
const btnRegister = $('#btnRegister');
const googleLogin = $('#googleLogin');
const closeAuth = $('#closeAuth');

const connectBtBtn = $('#connectBtBtn');
const unlockBtn = $('#unlockBtn');
const lockIcon = $('#lockIcon');
const lockStatus = $('#lockStatus');

const usersList = $('#usersList');
const enrollBtn = $('#enrollBtn');
const fpLabel = $('#fpLabel');
const syncBtn = $('#syncBtn');
const passphraseInput = $('#passphrase');
const setPassBtn = $('#setPassBtn');
const clearPassBtn = $('#clearPassBtn');
const passStatus = $('#passStatus');

const devicesList = $('#devicesList');
const logsList = $('#logsList');
const clearLogsBtn = $('#clearLogsBtn');

navLinks.forEach(a => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    navLinks.forEach(l => l.classList.remove('active'));
    a.classList.add('active');
    const page = a.getAttribute('data-page') || a.dataset.page;
    pages.forEach(p => p.classList.remove('active'));
    $('#' + page).classList.add('active');
  });
});
if (navToggle && navLinksWrap) navToggle.addEventListener('click', ()=> navLinksWrap.classList.toggle('active'));

if (btnSignIn) btnSignIn.addEventListener('click',()=> authModal.setAttribute('aria-hidden','false'));
if (closeAuth) closeAuth.addEventListener('click',()=> authModal.setAttribute('aria-hidden','true'));

if (btnRegister) btnRegister.addEventListener('click', async ()=>{
  const email = authEmail.value.trim(), pw = authPassword.value;
  if(!email || !pw) { authMsg.textContent='Enter email & password'; return; }
  authMsg.textContent='Registering...';
  try {
    await auth.createUserWithEmailAndPassword(email, pw);
    authMsg.textContent='Registered';
    authModal.setAttribute('aria-hidden','true');
  } catch(e){ authMsg.textContent = e.message; }
});

if (btnLogin) btnLogin.addEventListener('click', async ()=>{
  const email = authEmail.value.trim(), pw = authPassword.value;
  if(!email || !pw) { authMsg.textContent='Enter email & password'; return; }
  authMsg.textContent='Signing in...';
  try {
    await auth.signInWithEmailAndPassword(email,pw);
    authModal.setAttribute('aria-hidden','true');
    authMsg.textContent='';
  } catch(e){ authMsg.textContent = e.message; }
});

if (googleLogin) googleLogin.addEventListener('click', async ()=>{
  const provider = new firebase.auth.GoogleAuthProvider();
  try{
    await auth.signInWithPopup(provider);
    authModal.setAttribute('aria-hidden','true');
  } catch(e){ alert('Google login failed: '+e.message) }
});

if (btnSignOut) btnSignOut.addEventListener('click', ()=> auth.signOut());

let sessionKey = null;
let currentUID = null;
let userSalt = null;

function bufToHex(buf){
  const bytes = new Uint8Array(buf);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function hexToBuf(hex){
  if(!hex) return new Uint8Array().buffer;
  const bytes = new Uint8Array(hex.length/2);
  for(let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
  return bytes.buffer;
}
function bufToBase64(buf){
  const bytes = new Uint8Array(buf);
  let str='';
  for(let b of bytes) str += String.fromCharCode(b);
  return btoa(str);
}
function base64ToBuf(b64){
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for(let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
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
async function encryptObject(obj){
  if(!sessionKey) throw new Error('No session key');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, sessionKey, pt);
  return { iv: bufToBase64(iv), ct: bufToBase64(ct) };
}
async function decryptObject({ iv, ct }){
  if(!sessionKey) throw new Error('No session key');
  const plaintext = await crypto.subtle.decrypt({ name:'AES-GCM', iv: base64ToBuf(iv) }, sessionKey, base64ToBuf(ct));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function metaDocRef(uid){ return db.collection('users').doc(uid).collection('meta').doc('meta'); }
function fingerprintsColRef(uid){ return db.collection('users').doc(uid).collection('fingerprints'); }

async function ensureUserSalt(uid){
  const metaRef = metaDocRef(uid);
  const snap = await metaRef.get();
  if(snap.exists && snap.data().salt){
    userSalt = snap.data().salt;
    return userSalt;
  } else {
    const saltBuf = crypto.getRandomValues(new Uint8Array(16));
    userSalt = bufToHex(saltBuf);
    await metaRef.set({ salt: userSalt });
    return userSalt;
  }
}

let fpUnsubscribe = null;
async function subscribeFingerprints(){
  if(!currentUID) return;
  if(fpUnsubscribe) fpUnsubscribe();
  const col = fingerprintsColRef(currentUID);
  fpUnsubscribe = col.orderBy('createdAt','desc').onSnapshot(async snap => {
    const rows = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    await renderFingerprints(rows);
  });
}

async function renderFingerprints(rows){
  if(!rows.length){ usersList.innerHTML = `<div class="muted">No fingerprints enrolled</div>`; return; }
  const out = [];
  for(const r of rows){
    try {
      const obj = await decryptObject({ iv: r.iv, ct: r.ct });
      out.push(`<div class="user-item"><div><strong>${escapeHtml(obj.label)}</strong><div class="muted">${new Date(obj.createdAt).toLocaleString()}</div></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    } catch(e){
      out.push(`<div class="user-item"><div><strong>Encrypted fingerprint</strong></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    }
  }
  usersList.innerHTML = out.join('');
}

window.deleteFingerprint = async function(docId){
  if(!currentUID) return;
  if(!confirm('Delete fingerprint?')) return;
  await fingerprintsColRef(currentUID).doc(docId).delete();
  show('Deleted','info');
};

function abToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToAb(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function parseAttestationResponse(credential) {
  return {
    id: credential.id,
    rawId: abToBase64(credential.rawId),
    response: {
      clientDataJSON: abToBase64(credential.response.clientDataJSON),
      attestationObject: abToBase64(credential.response.attestationObject)
    },
    type: credential.type
  };
}
function parseAssertionResponse(assertion) {
  return {
    id: assertion.id,
    rawId: abToBase64(assertion.rawId),
    response: {
      clientDataJSON: abToBase64(assertion.response.clientDataJSON),
      authenticatorData: abToBase64(assertion.response.authenticatorData),
      signature: abToBase64(assertion.response.signature),
      userHandle: assertion.response.userHandle ? abToBase64(assertion.response.userHandle) : null
    },
    type: assertion.type
  };
}

async function getIdTokenHeader() {
  const user = auth.currentUser;
  if (!user) throw new Error('Not signed in');
  const idToken = await user.getIdToken();
  return { Authorization: 'Bearer ' + idToken };
}

async function postJSON(path, body) {
  const headers = { 'Content-Type': 'application/json' };
  try {
    const authHeader = await getIdTokenHeader();
    Object.assign(headers, authHeader);
  } catch (e) {
    // not signed in
  }
  const res = await fetch(path, {
    method: 'POST', headers, body: JSON.stringify(body)
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Server ${res.status}: ${text}`);
  }
  return res.json();
}

if (enrollBtn) enrollBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('Sign in first','info'); return; }
  if(!sessionKey){ show('Enter passphrase and press Set','info'); return; }
  const label = (fpLabel.value || `FP ${new Date().toLocaleString()}`).trim();
  try {
    const options = await postJSON('/api/beginRegistration', {});
    if(!options || !options.publicKey) throw new Error('Invalid server response');

    const publicKey = JSON.parse(JSON.stringify(options.publicKey));
    publicKey.challenge = base64ToAb(options.publicKey.challenge);
    if (options.publicKey.user && options.publicKey.user.id) publicKey.user.id = base64ToAb(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
      publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({ type: c.type, id: base64ToAb(c.id) }));
    }

    const cred = await navigator.credentials.create({ publicKey });
    if(!cred) throw new Error('Credential creation failed');

    const att = parseAttestationResponse(cred);
    att.label = label;

    const finishResp = await postJSON('/api/finishRegistration', att);
    if (!finishResp || !finishResp.success) throw new Error(finishResp && finishResp.error || 'Server registration failed');

    const metadata = { credentialId: att.rawId, label, createdAt: new Date().toISOString() };
    const enc = await encryptObject(metadata);
    const docId = fingerprintsColRef(currentUID).doc().id;
    await fingerprintsColRef(currentUID).doc(docId).set({ iv: enc.iv, ct: enc.ct, createdAt: firebase.firestore.FieldValue.serverTimestamp() });

    show('Enrolled '+label,'info');
    fpLabel.value='';

  } catch(e){
    console.error(e);
    show('Enroll failed: '+(e.message||e),'error');
  }
});

if (unlockBtn) unlockBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('Please sign in','info'); return; }
  show('Touch your authenticator...','info');
  try {
    const options = await postJSON('/api/beginLogin', {});
    if(!options || !options.publicKey) throw new Error('Invalid server response');
    const publicKey = {};
    publicKey.challenge = base64ToAb(options.publicKey.challenge);
    publicKey.userVerification = options.publicKey.userVerification || 'preferred';
    if (Array.isArray(options.publicKey.credentialIds) && options.publicKey.credentialIds.length) {
      publicKey.allowCredentials = options.publicKey.credentialIds.map(id => ({ type: 'public-key', id: base64ToAb(id) }));
    } else {
      publicKey.allowCredentials = [];
    }
    publicKey.rpId = options.publicKey.rpId || window.location.hostname;

    const assertion = await navigator.credentials.get({ publicKey, mediation: 'conditional' });
    if(!assertion) throw new Error('No assertion returned');

    const parsed = parseAssertionResponse(assertion);
    parsed.userId = currentUID;

    const finishResp = await postJSON('/api/finishLogin', parsed);
    if (finishResp && finishResp.success) {
      updateLockUI('UNLOCKED');
      logAccess('UNLOCK','FINGERPRINT','SUCCESS');
      show('Unlocked','success');
    } else {
      updateLockUI('LOCKED');
      logAccess('UNLOCK','FINGERPRINT','FAILED');
      show('Passkey verification failed','error');
    }
  } catch(e){
    console.error(e);
    updateLockUI('LOCKED');
    logAccess('UNLOCK','FINGERPRINT','FAILED');
    show('Auth error: '+(e.message||e),'error');
  }
});

if (setPassBtn) setPassBtn.addEventListener('click', async ()=>{
  const pass = passphraseInput.value;
  if(!pass){ passStatus.textContent='Enter passphrase'; return; }
  if(!auth.currentUser){ passStatus.textContent='Sign in first'; return; }
  try {
    const uid = auth.currentUser.uid;
    await ensureUserSalt(uid);
    sessionKey = await deriveKeyFromPassphrase(pass, userSalt);
    passStatus.textContent = 'Key derived — ready';
    await subscribeFingerprints();
  } catch(e){ passStatus.textContent = 'Derive key failed: '+(e.message||e) }
});

if (clearPassBtn) clearPassBtn.addEventListener('click', ()=>{
  sessionKey = null; passphraseInput.value=''; passStatus.textContent='Cleared';
});

if (syncBtn) syncBtn.addEventListener('click', async ()=>{
  if(!currentUID){ show('Sign in first','info'); return; }
  if(!sessionKey){ show('Derive key first','info'); return; }
  const snap = await fingerprintsColRef(currentUID).get();
  const rows = snap.docs.map(d=>({ id:d.id, ...d.data() }));
  await renderFingerprints(rows);
  show('Synced','info');
});

class BluetoothManager {
  constructor(){ this.device=null; this.server=null; this.service=null; this.characteristic=null; }
  async requestDevice(){ this.device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true, optionalServices: ['0000ffe0-0000-1000-8000-00805f9b34fb'] }); show('Device selected: '+(this.device && this.device.name ? this.device.name : 'Unnamed'),'info'); return this.device; }
  async connect(){ if(!this.device) await this.requestDevice(); if(!this.device.gatt) throw new Error('No GATT on device'); this.server = await this.device.gatt.connect(); this.service = await this.server.getPrimaryService('0000ffe0-0000-1000-8000-00805f9b34fb'); this.characteristic = await this.service.getCharacteristic('0000ffe1-0000-1000-8000-00805f9b34fb'); show('Bluetooth connected','info'); }
  async send(text){ if(!this.characteristic) await this.connect(); await this.characteristic.writeValue(new TextEncoder().encode(text)); }
}
const bt = new BluetoothManager();
if (connectBtBtn) connectBtBtn.addEventListener('click', async ()=> { try { await bt.requestDevice(); await bt.connect(); } catch(e){ show('BT error: '+(e.message||e),'error'); } });

async function loadDevices(){ if(!currentUID) return devicesList.innerHTML = `<div class="muted">Sign in</div>`; const snap = await db.collection('users').doc(currentUID).collection('devices').get(); if(snap.empty) return devicesList.innerHTML = `<div class="muted">No devices</div>`; devicesList.innerHTML = snap.docs.map(d=>{ const data = d.data(); return `<div class="device-item"><div><strong>${escapeHtml(data.name||'Device')}</strong><div class="muted">${escapeHtml(data.id||'')}</div></div><div><button class="btn small" onclick="connectDevice('${d.id}')">Connect</button></div></div>`; }).join(''); }
window.connectDevice = async function(docId){ const doc = await db.collection('users').doc(currentUID).collection('devices').doc(docId).get(); if(!doc.exists) return show('Device not found','info'); show('Attempting connect','info'); }

function logAccess(action, method, status){ const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]'); logs.unshift({ timestamp: new Date().toLocaleString(), action, method, status }); if(logs.length>200) logs.pop(); localStorage.setItem('accessLogs', JSON.stringify(logs)); renderLogs(); }
function renderLogs(){ const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]'); if(!logs.length) return logsList.innerHTML = `<div class="muted">No logs</div>`; logsList.innerHTML = logs.map(l=>`<div class="log-item"><div><strong>${l.timestamp}</strong><div class="muted">${l.method}</div></div><div>${l.action}</div><div>${l.status}</div></div>`).join(''); }
if (clearLogsBtn) clearLogsBtn.addEventListener('click', ()=> { if(confirm('Clear logs?')){ localStorage.removeItem('accessLogs'); renderLogs(); } });

auth.onAuthStateChanged(async user=>{
  if(user){
    currentUID = user.uid;
    userEmailSpan.textContent = user.email || user.displayName || '';
    if (btnSignIn) btnSignIn.style.display='none'; if (btnSignOut) btnSignOut.style.display='inline-block';
    await ensureUserSalt(currentUID);
    subscribeFingerprints().catch(()=>{});
    loadDevices().catch(()=>{});
    renderLogs();
  } else {
    currentUID = null;
    userEmailSpan.textContent = '';
    if (btnSignIn) btnSignIn.style.display='inline-block'; if (btnSignOut) btnSignOut.style.display='none';
    usersList.innerHTML = `<div class="muted">Please sign in</div>`;
    devicesList.innerHTML = `<div class="muted">Please sign in</div>`;
    logsList.innerHTML = `<div class="muted">Please sign in</div>`;
  }
});

function updateLockUI(state){ if(state==='UNLOCKED'){ lockIcon.textContent='🔓'; lockIcon.classList.remove('locked'); lockIcon.classList.add('unlocked'); lockStatus.textContent='UNLOCKED'; } else { lockIcon.textContent='🔒'; lockIcon.classList.remove('unlocked'); lockIcon.classList.add('locked'); lockStatus.textContent='LOCKED'; } }

(function init(){ renderLogs(); })();
