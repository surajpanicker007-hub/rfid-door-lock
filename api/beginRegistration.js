// api/beginRegistration.js
const base64url = require('base64url');
const { Fido2Lib } = require('fido2-lib');
const initAdmin = require('./_admin');

const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: process.env.RP_ID || undefined,
  rpName: "Smart Door Lock",
  challengeSize: 32,
  attestation: "none",
  authenticatorAttachment: undefined
});

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).send('Method not allowed');

    // extract Firebase ID token
    const authHeader = req.headers.authorization || '';
    const token = (authHeader.match(/^Bearer (.+)$/) || [])[1];
    if (!token) return res.status(401).json({ error: 'Missing id token' });

    const admin = initAdmin();
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const user = {
      id: base64url(uid),
      name: decoded.email || uid,
      displayName: decoded.name || decoded.email || uid
    };

    const registrationOptions = await f2l.attestationOptions();
    registrationOptions.user = user;

    // exclude existing creds
    const credsSnap = await admin.firestore().collection('webauthn').doc(uid).collection('credentials').get();
    if (!credsSnap.empty) {
      registrationOptions.excludeCredentials = credsSnap.docs.map(d => ({ id: d.id, type: 'public-key' }));
    }

    const challengeB64 = base64url(registrationOptions.challenge);
    // store challenge (single-use) in Firestore
    await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('registration').set({
      challenge: challengeB64,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // send publicKey with base64url-challenge and base64user id
    registrationOptions.challenge = challengeB64;
    registrationOptions.user.id = base64url(Buffer.from(user.id));

    return res.json({ publicKey: registrationOptions });
  } catch (err) {
    console.error('beginRegistration error', err);
    return res.status(500).json({ error: err.message || String(err) });
  }
};
