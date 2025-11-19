// api/finishRegistration.js
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

    const authHeader = req.headers.authorization || '';
    const token = (authHeader.match(/^Bearer (.+)$/) || [])[1];
    if (!token) return res.status(401).json({ error: 'Missing id token' });

    const admin = initAdmin();
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const attestation = req.body;
    if (!attestation || !attestation.rawId) return res.status(400).json({ error: 'Invalid attestation' });

    const challDoc = await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('registration').get();
    if (!challDoc.exists) return res.status(400).json({ error: 'No registration challenge found' });

    const challengeB64 = challDoc.data().challenge;

    const clientAttestationResponse = {
      id: attestation.id,
      rawId: base64url.toBuffer(attestation.rawId),
      response: {
        clientDataJSON: base64url.toBuffer(attestation.response.clientDataJSON),
        attestationObject: base64url.toBuffer(attestation.response.attestationObject)
      },
      type: attestation.type
    };

    const origin = process.env.ORIGIN || `https://${process.env.RP_ID || req.headers.host}`;
    const expected = {
      challenge: challengeB64,
      origin: origin,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, expected);

    const credIdBuf = regResult.authnrData.get('credId');
    const credIdB64url = base64url(Buffer.from(credIdBuf));
    const publicKeyBuf = regResult.authnrData.get('credentialPublicKey');
    const publicKeyBase64 = Buffer.isBuffer(publicKeyBuf) ? publicKeyBuf.toString('base64') : Buffer.from(publicKeyBuf || '').toString('base64');
    const counter = regResult.authnrData.get('counter') || 0;

    const credRef = admin.firestore().collection('webauthn').doc(uid).collection('credentials').doc(credIdB64url);
    await credRef.set({
      credId: credIdB64url,
      publicKey: publicKeyBase64,
      signCount: counter,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await admin.firestore().collection('webauthn').doc(uid).collection('challenges').doc('registration').delete();

    return res.json({ success: true });
  } catch (err) {
    console.error('finishRegistration error', err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
};
