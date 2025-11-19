// app.js (FULL - server-side WebAuthn integrated)
// ----------------------------
// Utilities
// ----------------------------
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
function el(html){ const div=document.createElement('div'); div.innerHTML=html; return div.firstElementChild; }
function show(node, text, type='info'){ const n = $('#notif'); if(!n) return; n.textContent = text; n.className = `notification show ${type}`; setTimeout(()=>n.className='notification',3500); }
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ----------------------------
// DOM refs
// ----------------------------
const pages = $$('.page');
const navLinks = $$('.nav-link');
const navToggle = $('#navToggle');
const navLinksWrap = $('#navLinks');

const btnSignIn = $('#btnSignIn'); // shows modal
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

// pages controls
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
const connectBtBtnMain = $('#connectBtBtn');

const logsList = $('#logsList');
const clearLogsBtn = $('#clearLogsBtn');

// ----------------------------
// Navigation
// ----------------------------
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

// ----------------------------
// Auth modal logic
// ----------------------------
if ($('#btnSignIn')) $('#btnSignIn').addEventListener('click',()=> authModal.setAttribute('aria-hidden','false'));
if ($('#closeAuth')) $('#closeAuth').addEventListener('click',()=> authModal.setAttribute('aria-hidden','true'));

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

// sign out
if (btnSignOut) btnSignOut.addEventListener('click', ()=> auth.signOut());

// ----------------------------
// Crypto helpers (WebCrypto)
// ----------------------------
let sessionKey = null;   // AES-GCM CryptoKey derived from passphrase + salt
let currentUID = null;
let userSalt = null;     // stored in Firestore under users/{uid}/meta.salt

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
function hexToBuf(hex){
  if(!hex) return new Uint8Array().buffer;
  const bytes = new Uint8Array(hex.length/2);
  for(let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
  return bytes.buffer;
}
function bufToHex(buf){
  const bytes = new Uint8Array(buf);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// AES-GCM encrypt/decrypt (returns base64 strings)
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

// ----------------------------
// Firestore helpers & structure
// - users/{uid}/meta  -> { salt: hex }
// - users/{uid}/fingerprints/{docId} -> { iv, ct, createdAt }
// ----------------------------
function metaDocRef(uid){ return db.collection('users').doc(uid).collection('meta').doc('meta'); }
function fingerprintsColRef(uid){ return db.collection('users').doc(uid).collection('fingerprints'); }

async function ensureUserSalt(uid){
  const metaRef = metaDocRef(uid);
  const snap = await metaRef.get();
  if(snap.exists){
    const data = snap.data();
    if(data.salt) { userSalt = data.salt; return userSalt; }
  }
  // create random salt hex and store
  const salt = bufToHex(crypto.getRandomValues(new Uint8Array(16)));
  await metaRef.set({ salt });
  userSalt = salt;
  return salt;
}

// ----------------------------
// Real-time listener for fingerprints (keeps UI in sync)
// ----------------------------
let fpUnsubscribe = null;
async function subscribeFingerprints(){
  if(!currentUID) return;
  if(fpUnsubscribe) fpUnsubscribe(); // cancel previous
  const col = fingerprintsColRef(currentUID);
  fpUnsubscribe = col.orderBy('createdAt','desc').onSnapshot(async snap => {
    const rows = [];
    for(const d of snap.docs){
      const doc = d.data();
      rows.push({ id: d.id, ...doc });
    }
    // update UI after decryption
    await renderFingerprints(rows);
  });
}

// Render fingerprint list (attempt to decrypt)
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

// delete fingerprint
window.deleteFingerprint = async function(docId){
  if(!currentUID) return;
  if(!confirm('Delete fingerprint?')) return;
  await fingerprintsColRef(currentUID).doc(docId).delete();
  show('','Deleted', 'info');
};

// ----------------------------
// Helper: ArrayBuffer <-> Base64 (for WebAuthn transport)
// ----------------------------
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

// Extract client response parts for assertion/attestation
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

// ----------------------------
// Enrollment (WebAuthn) - server assisted
// flow:
// 1) call functions().httpsCallable('beginRegistration') -> returns options (challenge base64, user info, rp, etc)
// 2) adapt options challenge -> ArrayBuffer, call navigator.credentials.create({ publicKey })
// 3) send attestation result to functions().httpsCallable('finishRegistration') for verification & storage
// 4) on server success, store encrypted metadata (credential id label) into Firestore as before
// ----------------------------
async function beginRegistrationServer() {
  const fn = firebase.functions().httpsCallable('beginRegistration');
  const resp = await fn({}); // server should return options including challenge (base64) and user info
  return resp.data;
}

async function finishRegistrationServer(attestationResponse) {
  const fn = firebase.functions().httpsCallable('finishRegistration');
  const resp = await fn(attestationResponse);
  return resp.data;
}

if (enrollBtn) enrollBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('','Sign in first','info'); return; }
  if(!sessionKey){ show('','Enter passphrase and press Set','info'); return; }
  const label = (fpLabel.value || `FP ${new Date().toLocaleString()}`).trim();

  try {
    // 1. begin registration (get options from server)
    const options = await beginRegistrationServer(); // server returns publicKey options but with challenge & user.id as base64 strings
    // transform options: challenge and user.id and any credentialExclude ids -> ArrayBuffers
    const publicKey = JSON.parse(JSON.stringify(options.publicKey)); // clone

    publicKey.challenge = base64ToAb(options.publicKey.challenge);
    if (options.publicKey.user && options.publicKey.user.id) {
      publicKey.user.id = base64ToAb(options.publicKey.user.id);
    }
    if (options.publicKey.excludeCredentials && options.publicKey.excludeCredentials.length) {
      publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
        type: c.type,
        id: base64ToAb(c.id)
      }));
    }

    // 2. create credential
    const cred = await navigator.credentials.create({ publicKey });
    if(!cred) throw new Error('Credential creation failed');

    // 3. prepare attestation object to send to server
    const attestation = parseAttestationResponse(cred);
    // include label for metadata
    attestation.label = label;

    // 4. finish registration on server (server will verify attestation and store public key & credential id)
    const finishResp = await finishRegistrationServer(attestation);
    if(!finishResp || !finishResp.success) throw new Error(finishResp && finishResp.error ? finishResp.error : 'Server registration failed');

    // 5. locally store encrypted metadata in Firestore (credential id encrypted)
    const metadata = { credentialId: attestation.rawId, label, createdAt: new Date().toISOString() };
    const enc = await encryptObject(metadata);
    const docId = fingerprintsColRef(currentUID).doc().id;
    await fingerprintsColRef(currentUID).doc(docId).set({ iv: enc.iv, ct: enc.ct, createdAt: firebase.firestore.FieldValue.serverTimestamp() });

    show('','Enrolled '+label,'info');
    fpLabel.value='';

  } catch(e){
    console.error(e);
    show('','Enroll failed: '+(e.message||e),'info');
  }
});

// ----------------------------
// LOGIN (WebAuthn) - server assisted
// flow:
// 1) call functions().httpsCallable('beginLogin', { userId }) -> returns challenge base64 and credentialIds list (base64)
// 2) build allowCredentials using those ids, challenge -> ArrayBuffer
// 3) call navigator.credentials.get({ publicKey, mediation: 'conditional' })
// 4) send assertion (parse) to finishLogin server callable for verification
// ----------------------------
async function beginLoginServer() {
  const fn = firebase.functions().httpsCallable('beginLogin');
  const resp = await fn({}); // server should identify the user from session or be passed user id
  return resp.data;
}

async function finishLoginServer(assertionResponse) {
  const fn = firebase.functions().httpsCallable('finishLogin');
  const resp = await fn(assertionResponse);
  return resp.data;
}

if (unlockBtn) unlockBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('','Please sign in','info'); return; }
  show('','Touch your authenticator...','info');

  try {
    // 1. request challenge + credential ids from server
    const options = await beginLoginServer(); // expected: { publicKey: { challenge: base64, credentialIds: [base64,...], userVerification } }
    if(!options || !options.publicKey) throw new Error('Invalid server response');

    // Convert challenge
    const publicKey = {};
    publicKey.challenge = base64ToAb(options.publicKey.challenge);
    publicKey.userVerification = options.publicKey.userVerification || 'preferred';

    // Build allowCredentials from server-provided credentialIds
    if (Array.isArray(options.publicKey.credentialIds) && options.publicKey.credentialIds.length) {
      publicKey.allowCredentials = options.publicKey.credentialIds.map(id => ({
        type: 'public-key',
        id: base64ToAb(id),
        // transports: ['internal','usb','nfc','ble'] // optional
      }));
    } else {
      // If no credentialIds are provided, still try an empty allowCredentials (some browsers may still show platform authenticators)
      publicKey.allowCredentials = [];
    }

    // rpId - server should be authoritative, but set to current host to be safe
    publicKey.rpId = options.publicKey.rpId || window.location.hostname;

    // 2. call navigator.credentials.get with mediation: 'conditional' to encourage mobile passkey UI
    const assertion = await navigator.credentials.get({ publicKey, mediation: 'conditional' });

    if(!assertion) throw new Error('No assertion returned');

    // 3. parse assertion and send to server
    const parsed = parseAssertionResponse(assertion);
    // Optionally include extra info
    parsed.userId = currentUID;

    const finishResp = await finishLoginServer(parsed);

    if (finishResp && finishResp.success) {
      updateLockUI('UNLOCKED');
      logAccess('UNLOCK','FINGERPRINT','SUCCESS');
      show('','Unlocked','success');
      // Optionally send to Bluetooth
      // await bt.send('UNLOCK');
    } else {
      updateLockUI('LOCKED');
      logAccess('UNLOCK','FINGERPRINT','FAILED');
      show('','Passkey verification failed','error');
    }

  } catch(e){
    console.error(e);
    updateLockUI('LOCKED');
    logAccess('UNLOCK','FINGERPRINT','FAILED');
    show('','Auth error: '+(e.message||e),'error');
  }
});

// ----------------------------
// Encryption passphrase flow
// - user enters passphrase, we fetch or create salt for user and derive sessionKey
// ----------------------------
if (setPassBtn) setPassBtn.addEventListener('click', async ()=>{
  const pass = passphraseInput.value;
  if(!pass){ passStatus.textContent='Enter passphrase'; return; }
  if(!auth.currentUser){ passStatus.textContent='Sign in first'; return; }
  try {
    // ensure salt exists
    const uid = auth.currentUser.uid;
    await ensureUserSalt(uid);
    sessionKey = await deriveKeyFromPassphrase(pass, userSalt);
    passStatus.textContent = 'Key derived — ready';
    // subscribe realtime fingerprint updates now that we can decrypt
    await subscribeFingerprints();
  } catch(e){ passStatus.textContent = 'Derive key failed: '+(e.message||e) }
});

if (clearPassBtn) clearPassBtn.addEventListener('click', ()=>{
  sessionKey = null; passphraseInput.value=''; passStatus.textContent='Cleared';
});

// ----------------------------
// ensureUserSalt: used earlier; implement it here
// ----------------------------
async function ensureUserSalt(uid){
  const metaRef = metaDocRef(uid);
  const snap = await metaRef.get();
  if(snap.exists && snap.data().salt){
    userSalt = snap.data().salt;
    return userSalt;
  } else {
    // create a new random 16-byte salt (hex)
    const saltBuf = crypto.getRandomValues(new Uint8Array(16));
    userSalt = bufToHex(saltBuf);
    await metaRef.set({ salt: userSalt });
    return userSalt;
  }
}
function metaDocRef(uid){ return db.collection('users').doc(uid).collection('meta').doc('meta'); }

// ----------------------------
// Sync button: manual fetch/render
// ----------------------------
if (syncBtn) syncBtn.addEventListener('click', async ()=>{
  if(!currentUID){ show('','Sign in first','info'); return; }
  if(!sessionKey){ show('','Derive key first','info'); return; }
  const snap = await fingerprintsColRef(currentUID).get();
  const rows = snap.docs.map(d=>({ id:d.id, ...d.data() }));
  await renderFingerprints(rows);
  show('','Synced','info');
});

function fingerprintsColRef(uid){ return db.collection('users').doc(uid).collection('fingerprints'); }

// ----------------------------
// Bluetooth manager (basic) - connect, send command
// ----------------------------
class BluetoothManager {
  constructor(){
    this.device = null;
    this.server = null;
    this.service = null;
    this.characteristic = null;
  }
  async requestDevice(){
    try{
      this.device = await navigator.bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: ['0000ffe0-0000-1000-8000-00805f9b34fb']
      });
      show('','Device selected: '+(this.device && this.device.name ? this.device.name : 'Unnamed'),'info');
      return this.device;
    } catch(e){ throw e; }
  }
  async connect(){
    if(!this.device) await this.requestDevice();
    if(!this.device.gatt) throw new Error('No GATT on device');
    this.server = await this.device.gatt.connect();
    this.service = await this.server.getPrimaryService('0000ffe0-0000-1000-8000-00805f9b34fb');
    this.characteristic = await this.service.getCharacteristic('0000ffe1-0000-1000-8000-00805f9b34fb');
    show('','Bluetooth connected','info');
  }
  async send(text){
    if(!this.characteristic) await this.connect();
    const encoder = new TextEncoder();
    await this.characteristic.writeValue(encoder.encode(text));
  }
}

const bt = new BluetoothManager();

if (connectBtBtn) connectBtBtn.addEventListener('click', async ()=>{
  try{
    await bt.requestDevice();
    await bt.connect();
  } catch(e){ show('','BT error: '+(e.message||e),'info') }
});

// ----------------------------
// Devices list - minimal store in Firestore under users/{uid}/devices
// ----------------------------
async function loadDevices(){
  if(!currentUID) return devicesList.innerHTML = `<div class="muted">Sign in</div>`;
  const snap = await db.collection('users').doc(currentUID).collection('devices').get();
  if(snap.empty) return devicesList.innerHTML = `<div class="muted">No devices</div>`;
  devicesList.innerHTML = snap.docs.map(d=>{
    const data = d.data();
    return `<div class="device-item"><div><strong>${escapeHtml(data.name||'Device')}</strong><div class="muted">${escapeHtml(data.id||'')}</div></div><div><button class="btn small" onclick="connectDevice('${d.id}')">Connect</button></div></div>`;
  }).join('');
}
window.connectDevice = async function(docId){
  // load device entry and attempt connection (placeholder)
  const doc = await db.collection('users').doc(currentUID).collection('devices').doc(docId).get();
  if(!doc.exists) return show('','Device not found','info');
  const data = doc.data();
  show('','Attempting connect to '+(data.name||'device'),'info');
  // if storing bluetooth address isn't reliable due to browser restrictions; instead user uses UI connect
}

// ----------------------------
// Logging (local) and load
// ----------------------------
function logAccess(action, method, status){
  const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]');
  logs.unshift({ timestamp: new Date().toLocaleString(), action, method, status });
  if(logs.length>200) logs.pop();
  localStorage.setItem('accessLogs', JSON.stringify(logs));
  renderLogs();
}
function renderLogs(){
  const logs = JSON.parse(localStorage.getItem('accessLogs')||'[]');
  if(!logs.length) return logsList.innerHTML = `<div class="muted">No logs</div>`;
  logsList.innerHTML = logs.map(l=>`<div class="log-item"><div><strong>${l.timestamp}</strong><div class="muted">${l.method}</div></div><div>${l.action}</div><div>${l.status}</div></div>`).join('');
}
if (clearLogsBtn) clearLogsBtn.addEventListener('click', ()=> { if(confirm('Clear logs?')){ localStorage.removeItem('accessLogs'); renderLogs(); } });

// ----------------------------
// Auth state changes
// ----------------------------
auth.onAuthStateChanged(async user=>{
  if(user){
    currentUID = user.uid;
    userEmailSpan.textContent = user.email || user.displayName || '';
    if (btnSignIn) btnSignIn.style.display='none'; if (btnSignOut) btnSignOut.style.display='inline-block';
    // ensure salt exists (create if not)
    await ensureUserSalt(currentUID);
    // subscribe to fingerprint updates (will render but decryption requires sessionKey)
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

// ----------------------------
// Helper: update lock UI
// ----------------------------
function updateLockUI(state){
  if(state==='UNLOCKED'){ lockIcon.textContent='🔓'; lockIcon.classList.remove('locked'); lockIcon.classList.add('unlocked'); lockStatus.textContent='UNLOCKED'; }
  else { lockIcon.textContent='🔒'; lockIcon.classList.remove('unlocked'); lockIcon.classList.add('locked'); lockStatus.textContent='LOCKED'; }
}

// ----------------------------
// Misc helpers: hex, buffer conversion
// ----------------------------
function bufToHex(buf){
  const bytes = new Uint8Array(buf);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ----------------------------
// Server call wrappers (Firebase Functions callable)
// ----------------------------
async function beginRegistrationServer() {
  const fn = firebase.functions().httpsCallable('beginRegistration');
  const resp = await fn({});
  return resp.data;
}
async function finishRegistrationServer(attestationResponse) {
  const fn = firebase.functions().httpsCallable('finishRegistration');
  const resp = await fn(attestationResponse);
  return resp.data;
}
async function beginLoginServer() {
  const fn = firebase.functions().httpsCallable('beginLogin');
  const resp = await fn({});
  return resp.data;
}
async function finishLoginServer(assertionResponse) {
  const fn = firebase.functions().httpsCallable('finishLogin');
  const resp = await fn(assertionResponse);
  return resp.data;
}

// ----------------------------
// Startup
// ----------------------------
(async function init(){
  renderLogs();
})();
