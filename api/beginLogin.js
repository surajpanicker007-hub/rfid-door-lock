// api/beginLogin.js
const base64url = require('base64url');
const { Fido2Lib } = require('fido2-lib');
const initAdmin = require('./_admin');

const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: process.env.RP_ID || undefined,
  rpName: "Smart Door Lock",
  challengeSize: 32
});

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).send('Method not allowed');

    const authHeader = req.headers.authorization || '';
    const token = (authHeader.match(/^Bearer (.+)$/) || [])[1];
    if (!token) return res.status(401).json({ error: 'Missing id token' });

    const admin = initAdmin();
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const options = await f2l.assertionOptions();
    const challengeB64 = base64url(options.challenge);

    const credSnap = await admin.firestore().collection('webauthn').doc(uid).collection('credentials').get();
    const credentialIds = credSnap.docs.map(d => d.id);

    await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('login').set({
      challenge: challengeB64,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.json({
      publicKey: {
        challenge: challengeB64,
        credentialIds: credentialIds,
        userVerification: options.userVerification || 'preferred',
        rpId: process.env.RP_ID || undefined
      }
    });
  } catch (err) {
    console.error('beginLogin error', err);
    return res.status(500).json({ error: err.message || String(err) });
  }
};
