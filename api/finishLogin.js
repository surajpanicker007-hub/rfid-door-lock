// api/finishLogin.js
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

    const assertion = req.body;
    if (!assertion || !assertion.rawId) return res.status(400).json({ error: 'Invalid assertion' });

    const challDoc = await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('login').get();
    if (!challDoc.exists) return res.status(400).json({ error: 'No login challenge found' });
    const challengeB64 = challDoc.data().challenge;

    const clientAssertionResponse = {
      id: assertion.id,
      rawId: base64url.toBuffer(assertion.rawId),
      response: {
        clientDataJSON: base64url.toBuffer(assertion.response.clientDataJSON),
        authenticatorData: base64url.toBuffer(assertion.response.authenticatorData),
        signature: base64url.toBuffer(assertion.response.signature),
        userHandle: assertion.response.userHandle ? base64url.toBuffer(assertion.response.userHandle) : null
      },
      type: assertion.type
    };

    const credId = assertion.id;
    const storedDoc = await admin.firestore().collection('webauthn').doc(uid).collection('credentials').doc(credId).get();
    if (!storedDoc.exists) return res.status(400).json({ success: false, error: 'Credential not found' });
    const stored = storedDoc.data();

    const publicKeyPemBase64 = stored.publicKey;
    const publicKeyPem = Buffer.from(publicKeyPemBase64, 'base64').toString();

    const origin = process.env.ORIGIN || `https://${process.env.RP_ID || req.headers.host}`;
    const expected = {
      challenge: challengeB64,
      origin: origin,
      factor: "either",
      publicKey: publicKeyPem,
      prevCounter: stored.signCount || 0
    };

    const authnResult = await f2l.assertionResult(clientAssertionResponse, expected);

    await admin.firestore().collection('webauthn').doc(uid).collection('credentials').doc(credId).update({
      signCount: authnResult.auditInfo.counter
    });

    await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('login').delete();

    return res.json({ success: true });
  } catch (err) {
    console.error('finishLogin error', err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
};
