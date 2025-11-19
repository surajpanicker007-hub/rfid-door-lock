// app.js

// ---------- Helpers: DOM ----------
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Pages
const pages = $$('.page');
const navLinks = $$('.nav-link');

navLinks.forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const page = link.dataset.page;
    navLinks.forEach(l => l.classList.remove('active'));
    link.classList.add('active');
    pages.forEach(p => p.classList.remove('active'));
    document.getElementById(page).classList.add('active');

    if (page === 'enroll') updateUsersList();
    if (page === 'logs') loadLogs();
  });
});

// ---------- Auth Modal ----------
const authModal = $('#authModal');
const authMsg = $('#authMsg');

$('#btnSignIn').addEventListener('click', () => {
  authModal.setAttribute('aria-hidden', 'false');
});
$('#btnCloseAuth').addEventListener('click', () => {
  authModal.setAttribute('aria-hidden', 'true');
});

$('#btnRegister').addEventListener('click', async () => {
  const email = $('#authEmail').value.trim();
  const password = $('#authPassword').value;
  authMsg.textContent = 'Registering...';
  try {
    const u = await auth.createUserWithEmailAndPassword(email, password);
    // store nothing sensitive on server; key is derived from password at login
    authMsg.textContent = 'Registered. Signed in.';
    authModal.setAttribute('aria-hidden','true');
  } catch (err) {
    authMsg.textContent = err.message;
  }
});

$('#btnLogin').addEventListener('click', async () => {
  const email = $('#authEmail').value.trim();
  const password = $('#authPassword').value;
  authMsg.textContent = 'Signing in...';
  try {
    const u = await auth.signInWithEmailAndPassword(email, password);
    // Derive crypto key and keep in memory for this session
    await onSignedIn(password);
    authModal.setAttribute('aria-hidden','true');
    authMsg.textContent = '';
  } catch (err) {
    authMsg.textContent = err.message;
  }
});

$('#btnSignOut').addEventListener('click', async () => {
  await auth.signOut();
  clearSession();
});

// ---------- Crypto: derive key from password ----------
let sessionKey = null;      // CryptoKey used to encrypt/decrypt user's fingerprint metadata
let currentUID = null;
let lastUsedPassword = null;

async function deriveKeyFromPassword(password, saltStr) {
  // saltStr: use user's uid (stable per user) as salt
  const enc = new TextEncoder();
  const salt = enc.encode(saltStr);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 200000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return key;
}

async function encryptJSON(obj) {
  if (!sessionKey) throw new Error('sessionKey not available');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sessionKey, data);
  // return base64 strings
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ct)
  };
}

async function decryptJSON({ iv, ciphertext }) {
  if (!sessionKey) throw new Error('sessionKey not available');
  const ivBuf = base64ToBuf(iv);
  const ctBuf = base64ToBuf(ciphertext);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuf }, sessionKey, ctBuf);
  const txt = new TextDecoder().decode(pt);
  return JSON.parse(txt);
}

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}
function base64ToBuf(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ---------- Firebase + session handling ----------
auth.onAuthStateChanged(async user => {
  if (user) {
    // we still need password to derive sessionKey; user must sign in through email/password flow in this demo
    $('#userEmail').textContent = user.email;
    $('#btnSignOut').style.display = 'inline-block';
    $('#btnSignIn').style.display = 'none';
    currentUID = user.uid;
    // if user signed in but we don't have password-derived key, ask them to re-enter password
    if (!sessionKey) {
      // prompt for password
      showNotification('Please enter your password to unlock encryption key', 'info');
      authModal.setAttribute('aria-hidden','false');
    } else {
      // ready
      updateUsersList();
      loadLogs();
    }
  } else {
    clearSession();
  }
});

async function onSignedIn(password) {
  lastUsedPassword = password;
  const uid = auth.currentUser.uid;
  sessionKey = await deriveKeyFromPassword(password, uid);
  currentUID = uid;
  $('#userEmail').textContent = auth.currentUser.email;
  $('#btnSignOut').style.display = 'inline-block';
  $('#btnSignIn').style.display = 'none';
  updateUsersList();
  loadLogs();
}

function clearSession() {
  sessionKey = null;
  currentUID = null;
  lastUsedPassword = null;
  $('#userEmail').textContent = '';
  $('#btnSignOut').style.display = 'none';
  $('#btnSignIn').style.display = 'inline-block';
  $('#usersList').innerHTML = '<p class="empty">Please sign in</p>';
  $('#logsList').innerHTML = '<p class="empty">Please sign in</p>';
}

// ---------- Firestore helpers ----------
function fpDocRef(fpId) {
  return db.collection('users').doc(currentUID).collection('fingerprints').doc(fpId);
}

async function saveEncryptedFingerprint(fpId, payloadObj) {
  // payloadObj is encrypted JSON stored as { iv, ciphertext }
  await fpDocRef(fpId).set({
    iv: payloadObj.iv,
    ciphertext: payloadObj.ciphertext,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  });
}

async function loadEncryptedFingerprints() {
  const snap = await db.collection('users').doc(currentUID).collection('fingerprints').orderBy('createdAt', 'desc').get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

// ---------- Enrollment (WebAuthn) ----------
$('#enrollBtn').addEventListener('click', async () => {
  if (!auth.currentUser) { showAuthModal(); return; }
  if (!sessionKey) { showNotification('Please sign in (password) to enable encryption', 'error'); return; }

  const label = $('#userName').value.trim() || ('FP-'+new Date().toLocaleString());
  $('#enrollStatus').textContent = 'Place your finger on the authenticator...';

  try {
    // Create a new public key credential (relying party and user fields simplified)
    const publicKey = {
      challenge: Uint8Array.from(window.crypto.getRandomValues(new Uint8Array(32))),
      rp: { name: 'Smart Door Lock' },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: auth.currentUser.email,
        displayName: label
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      authenticatorSelection: { userVerification: 'preferred' }
    };

    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) throw new Error('Credential creation failed');

    // Save credential.id encrypted to Firestore as fingerprint metadata
    const fpId = credential.id; // using the credential id as identifier (still encrypted below)

    // Build metadata to encrypt (do NOT store raw biometric data)
    const metadata = {
      credentialId: credential.id,
      label,
      createdAt: new Date().toISOString()
    };

    const encrypted = await encryptJSON(metadata);

    // store encrypted under a random doc id
    const docId = firebase.firestore().collection('_').doc().id; // quick random id
    await saveEncryptedFingerprint(docId, encrypted);

    $('#enrollStatus').textContent = `Enrolled: ${label}`;
    $('#userName').value = '';
    updateUsersList();

  } catch (err) {
    console.error(err);
    $('#enrollStatus').textContent = 'Enrollment failed: ' + (err.message || err);
  }
});

// ---------- Update UI: users list ----------
async function updateUsersList() {
  if (!auth.currentUser) { $('#usersList').innerHTML = '<p class="empty">Sign in to see fingerprints</p>'; return; }
  if (!sessionKey) { $('#usersList').innerHTML = '<p class="empty">Enter password to decrypt fingerprints</p>'; return; }
  const rows = await loadEncryptedFingerprints();
  if (!rows.length) { $('#usersList').innerHTML = '<p class="empty">No fingerprints enrolled</p>'; return; }

  const out = [];
  for (const r of rows) {
    try {
      const decrypted = await decryptJSON({ iv: r.iv, ciphertext: r.ciphertext });
      // show label + createdAt
      out.push(`<div class="user-item"><div><strong>${escapeHtml(decrypted.label)}</strong><div class="muted">id: ${r.id}</div><div class="muted">${new Date(decrypted.createdAt).toLocaleString()}</div></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    } catch (e) {
      out.push(`<div class="user-item"><div><strong>Encrypted fingerprint (cannot decrypt)</strong></div><div><button class="btn small" onclick="deleteFingerprint('${r.id}')">Delete</button></div></div>`);
    }
  }
  $('#usersList').innerHTML = out.join('');
}

// delete
window.deleteFingerprint = async function(docId){
  if (!confirm('Delete fingerprint?')) return;
  await db.collection('users').doc(currentUID).collection('fingerprints').doc(docId).delete();
  updateUsersList();
  showNotification('Deleted', 'info');
};

// ---------- Auth using WebAuthn for Unlock ----------
$('#unlockBtn').addEventListener('click', async () => {
  if (!auth.currentUser) { showAuthModal(); return; }
  if (!sessionKey) { showNotification('Please sign in (password) to enable encryption', 'error'); return; }

  showNotification('Touch your authenticator...', 'info');

  try {
    // Simple flow: call navigator.credentials.get with a generic request. Many browsers
    // require a proper allowCredentials list; production would fetch user's credential IDs from server.
    // For demo we request a simple credential get which will succeed if user has a platform authenticator.
    const publicKey = {
      challenge: Uint8Array.from(crypto.getRandomValues(new Uint8Array(32))),
      timeout: 60000,
      userVerification: 'preferred'
    };

    const assertion = await navigator.credentials.get({ publicKey });
    if (assertion) {
      // We consider success to unlock.
      updateLockUI('UNLOCKED');
      logAccess('UNLOCK', 'FINGERPRINT', 'SUCCESS');
      showNotification('Unlocked', 'success');
    } else {
      showNotification('Auth failed', 'error');
      logAccess('UNLOCK', 'FINGERPRINT', 'FAILED');
    }
  } catch (err) {
    console.error(err);
    showNotification('Auth error: ' + (err.message || err), 'error');
    logAccess('UNLOCK', 'FINGERPRINT', 'FAILED');
  }
});

// ---------- Bluetooth (connect + send) ----------
let bluetoothDevice = null;
$('#btnConnectBT').addEventListener('click', async () => {
  try {
    bluetoothDevice = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'HC-05' }, { namePrefix: 'HC-06' }],
      optionalServices: ['0000ffe0-0000-1000-8000-00805f9b34fb']
    });
    showNotification('Bluetooth device selected. Connect in device UI if required', 'info');
    // Further connect/characteristic logic goes here — left intentionally minimal.
  } catch (err) {
    showNotification('Bluetooth error: ' + (err.message || err), 'error');
  }
});

// Example function to send command to connected device (requires actual connect flow)
async function sendToBluetooth(command) {
  // Implement full connect/getPrimaryService/getCharacteristic/writeValue
  showNotification('Sending ' + command, 'info');
}

// ---------- Logging ----------
function logAccess(action, method, status) {
  const logs = JSON.parse(localStorage.getItem('accessLogs') || '[]');
  logs.unshift({ timestamp: new Date().toLocaleString(), action, method, status });
  if (logs.length > 200) logs.pop();
  localStorage.setItem('accessLogs', JSON.stringify(logs));
  loadLogs();
}
function loadLogs(){
  const logs = JSON.parse(localStorage.getItem('accessLogs') || '[]');
  if (!logs.length) { $('#logsList').innerHTML = '<p class="empty">No logs yet</p>'; return; }
  $('#logsList').innerHTML = logs.map(l => `<div class="log-item"><div><strong>${l.timestamp}</strong><div class="muted">${l.method}</div></div><div>${l.action}</div><div>${l.status}</div></div>`).join('');
}
$('#clearLogsBtn').addEventListener('click', () => {
  if (confirm('Clear logs?')) { localStorage.removeItem('accessLogs'); loadLogs(); }
});

// ---------- Utilities ----------
function showNotification(text, type = 'info') {
  const n = $('#notification');
  n.textContent = text;
  n.className = `notification show ${type}`;
  setTimeout(()=> n.classList.remove('show'), 3500);
}
function showAuthModal(){ authModal.setAttribute('aria-hidden','false'); }

function escapeHtml(str){ return (str+'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---------- Startup ----------
(function init(){
  // minimal startup
  if (!firebase || !firebase.apps) {
    alert('Firebase SDK not loaded. Check firebaseConfig.js and network.');
    return;
  }
  loadLogs();
})();
