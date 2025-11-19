// app.js
// ----------------------------
// Utilities
// ----------------------------
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
function el(html){ const div=document.createElement('div'); div.innerHTML=html; return div.firstElementChild; }
function show(node, text, type='info'){ const n = $('#notif'); n.textContent = text; n.className = `notification show ${type}`; setTimeout(()=>n.className='notification',3500); }
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
navToggle.addEventListener('click', ()=> navLinksWrap.classList.toggle('active'));

// ----------------------------
// Auth modal logic
// ----------------------------
$('#btnSignIn').addEventListener('click',()=> authModal.setAttribute('aria-hidden','false'));
$('#closeAuth').addEventListener('click',()=> authModal.setAttribute('aria-hidden','true'));

btnRegister.addEventListener('click', async ()=>{
  const email = authEmail.value.trim(), pw = authPassword.value;
  if(!email || !pw) { authMsg.textContent='Enter email & password'; return; }
  authMsg.textContent='Registering...';
  try {
    await auth.createUserWithEmailAndPassword(email, pw);
    authMsg.textContent='Registered';
    authModal.setAttribute('aria-hidden','true');
  } catch(e){ authMsg.textContent = e.message; }
});

btnLogin.addEventListener('click', async ()=>{
  const email = authEmail.value.trim(), pw = authPassword.value;
  if(!email || !pw) { authMsg.textContent='Enter email & password'; return; }
  authMsg.textContent='Signing in...';
  try {
    await auth.signInWithEmailAndPassword(email,pw);
    // derive passphrase key if user entered passphrase earlier could be asked separately
    authModal.setAttribute('aria-hidden','true');
    authMsg.textContent='';
  } catch(e){ authMsg.textContent = e.message; }
});

googleLogin.addEventListener('click', async ()=>{
  const provider = new firebase.auth.GoogleAuthProvider();
  try{
    await auth.signInWithPopup(provider);
    authModal.setAttribute('aria-hidden','true');
  } catch(e){ alert('Google login failed: '+e.message) }
});

// sign out
btnSignOut.addEventListener('click', ()=> auth.signOut());

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
// Enrollment (WebAuthn) -> create credential, encrypt metadata (credential id string) and upload
// ----------------------------
enrollBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('','Sign in first','info'); return; }
  if(!sessionKey){ show('','Enter passphrase and press Set','info'); return; }
  const label = (fpLabel.value || `FP ${new Date().toLocaleString()}`).trim();

  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Smart Door Lock' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: auth.currentUser.email, displayName: label },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      authenticatorSelection: { userVerification: 'preferred' }
    };
    const cred = await navigator.credentials.create({ publicKey });
    if(!cred) throw new Error('Credential creation failed');

    // Save only metadata (credential.id) encrypted
    const metadata = { credentialId: arrayBufferToBase64(cred.rawId || cred.id), label, createdAt: new Date().toISOString() };
    const enc = await encryptObject(metadata);

    const id = fingerprintsColRef(currentUID).doc().id;
    await fingerprintsColRef(currentUID).doc(id).set({ iv: enc.iv, ct: enc.ct, createdAt: firebase.firestore.FieldValue.serverTimestamp() });

    show('','Enrolled '+label,'info');
    fpLabel.value='';

  } catch(e){
    console.error(e);
    show('','Enroll failed: '+(e.message||e),'info');
  }
});

// small helper: arrayBuffer -> base64
function arrayBufferToBase64(buf){
  const bytes = new Uint8Array(buf);
  let binary='';
  for(let b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function base64ToArrayBuffer(b64){
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for(let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ----------------------------
// Authentication (WebAuthn get) -> unlocking
// ----------------------------
unlockBtn.addEventListener('click', async ()=>{
  if(!auth.currentUser){ show('','Please sign in','info'); return; }
  show('','Touch your authenticator...','info');

  try {
    // Note: production should supply allowCredentials — here we rely on platform authenticator acceptance.
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: 60000,
      userVerification: 'preferred'
    };
    const assertion = await navigator.credentials.get({ publicKey });
    if(assertion){
      updateLockUI('UNLOCKED');
      logAccess('UNLOCK','FINGERPRINT','SUCCESS');
      show('','Unlocked','info');
      // Optionally send to Bluetooth: await bt.send('UNLOCK');
    } else {
      updateLockUI('LOCKED');
      logAccess('UNLOCK','FINGERPRINT','FAILED');
      show('','Auth failed','info');
    }
  } catch(e){
    console.error(e);
    show('','Auth error: '+(e.message||e),'info');
    logAccess('UNLOCK','FINGERPRINT','FAILED');
  }
});

// ----------------------------
// Encryption passphrase flow
// - user enters passphrase, we fetch or create salt for user and derive sessionKey
// ----------------------------
setPassBtn.addEventListener('click', async ()=>{
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

clearPassBtn.addEventListener('click', ()=>{
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
syncBtn.addEventListener('click', async ()=>{
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
      show('','Device selected: '+this.device.name,'info');
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

connectBtBtn.addEventListener('click', async ()=>{
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
clearLogsBtn.addEventListener('click', ()=> { if(confirm('Clear logs?')){ localStorage.removeItem('accessLogs'); renderLogs(); } });

// ----------------------------
// Auth state changes
// ----------------------------
auth.onAuthStateChanged(async user=>{
  if(user){
    currentUID = user.uid;
    userEmailSpan.textContent = user.email || user.displayName || '';
    btnSignIn.style.display='none'; btnSignOut.style.display='inline-block';
    // ensure salt exists (create if not)
    await ensureUserSalt(currentUID);
    // subscribe to fingerprint updates (will render but decryption requires sessionKey)
    subscribeFingerprints().catch(()=>{});
    loadDevices().catch(()=>{});
    renderLogs();
  } else {
    currentUID = null;
    userEmailSpan.textContent = '';
    btnSignIn.style.display='inline-block'; btnSignOut.style.display='none';
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
// Startup
// ----------------------------
(async function init(){
  renderLogs();
})();
