// functions/webauthn.js
const { Fido2Lib } = require('fido2-lib');
const admin = require('firebase-admin');
const base64url = require('base64url');

const db = admin.firestore();

// FIDO2 settings
const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: process.env.RP_ID || undefined, // optional: use project domain
  rpName: "Smart Door Lock",
  challengeSize: 32,
  attestation: "none",
  authenticatorAttachment: "platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "preferred"
});

// Helpers
function toBase64Url(buffer) {
  return base64url(Buffer.from(buffer));
}
function fromBase64Url(str) {
  return base64url.toBuffer(str);
}

// store public key and credentialId for user
async function storeCredential(uid, cred) {
  // cred should include credentialId (base64url), publicKey (Buffer), signCount
  const ref = db.collection('webauthn').doc(uid).collection('credentials').doc(cred.credId);
  await ref.set({
    credId: cred.credId,
    publicKey: cred.publicKey.toString('base64'),
    fmt: cred.fmt || 'none',
    signCount: cred.counter || 0,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

// fetch all credential ids for user
async function getCredentialIds(uid) {
  const snap = await db.collection('webauthn').doc(uid).collection('credentials').get();
  return snap.docs.map(d => d.id);
}

// get stored public key for credId
async function getCredential(uid, credId) {
  const doc = await db.collection('webauthn').doc(uid).collection('credentials').doc(credId).get();
  return doc.exists ? doc.data() : null;
}

// BEGIN REGISTRATION
async function beginRegistration(uid) {
  // create user object
  const user = {
    id: base64url(Buffer.from(uid)), // store user id as base64url to pass to client
    name: uid,
    displayName: uid
  };

  const challengeMakeCred = await f2l.attestationOptions();
  challengeMakeCred.user = user;
  // exclude existing credentials
  const existing = await getCredentialIds(uid);
  if (existing.length) {
    challengeMakeCred.excludeCredentials = existing.map(id => ({ id: id, type: "public-key" }));
  }
  // convert challenge and user.id to base64url strings for client
  challengeMakeCred.challenge = toBase64Url(challengeMakeCred.challenge);
  challengeMakeCred.user.id = toBase64Url(challengeMakeCred.user.id);

  return { publicKey: challengeMakeCred };
}

// FINISH REGISTRATION
async function finishRegistration(uid, attestationResponse) {
  try {
    // attestationResponse should contain id, rawId, response.clientDataJSON, response.attestationObject
    const clientAttestationResponse = {
      id: attestationResponse.id,
      rawId: fromBase64Url(attestationResponse.rawId),
      response: {
        clientDataJSON: fromBase64Url(attestationResponse.response.clientDataJSON),
        attestationObject: fromBase64Url(attestationResponse.response.attestationObject)
      },
      type: attestationResponse.type
    };

    const origin = process.env.ORIGIN || `https://${process.env.RP_DOMAIN || process.env.GCLOUD_PROJECT || ''}`;
    // validate attestation
    const regResult = await f2l.attestationResult(clientAttestationResponse, {
      origin: origin,
      factor: "either"
    });

    // regResult contains authnrData (including public key, counter)
    const credId = toBase64Url(regResult.authnrData.get('credId'));
    const publicKey = regResult.authnrData.get('credentialPublicKeyPem') || regResult.authnrData.get('credentialPublicKey');
    const counter = regResult.authnrData.get('counter');

    // store credential for user
    await storeCredential(uid, {
      credId,
      publicKey: Buffer.from(publicKey),
      counter,
      fmt: regResult.fmt
    });

    return { success: true };
  } catch (err) {
    console.error('finishRegistration error', err);
    return { success: false, error: err.message || String(err) };
  }
}

// BEGIN LOGIN
async function beginLogin(uid) {
  // build challenge and allowed credential IDs
  const allowCredsDocs = await db.collection('webauthn').doc(uid).collection('credentials').get();
  const credentialIds = allowCredsDocs.docs.map(d => d.id); // stored as base64url as id

  const options = await f2l.assertionOptions();
  options.challenge = toBase64Url(options.challenge);
  options.allowCredentials = credentialIds.map(id => ({ type: 'public-key', id }));

  // rpId optional: include server rpId if requires
  return { publicKey: { challenge: options.challenge, credentialIds: credentialIds, userVerification: options.userVerification || 'preferred', rpId: options.rpId } };
}

// FINISH LOGIN
async function finishLogin(uid, assertionResponse) {
  try {
    // assertionResponse contains id, rawId, response.clientDataJSON, response.authenticatorData, response.signature, response.userHandle
    const clientAssertionResponse = {
      id: assertionResponse.id,
      rawId: fromBase64Url(assertionResponse.rawId),
      response: {
        clientDataJSON: fromBase64Url(assertionResponse.response.clientDataJSON),
        authenticatorData: fromBase64Url(assertionResponse.response.authenticatorData),
        signature: fromBase64Url(assertionResponse.response.signature),
        userHandle: assertionResponse.response.userHandle ? fromBase64Url(assertionResponse.response.userHandle) : null
      },
      type: assertionResponse.type
    };

    const credId = assertionResponse.id; // it's base64url-encoded id

    const stored = await getCredential(uid, credId);
    if (!stored) return { success: false, error: 'Credential not found' };

    // Build expected parameters
    const origin = process.env.ORIGIN || `https://${process.env.RP_DOMAIN || process.env.GCLOUD_PROJECT || ''}`;
    const publicKeyPem = Buffer.from(stored.publicKey, 'base64').toString();

    // Create assertionResult options
    const assertionExpectations = {
      challenge: undefined, // not required by fido2-lib if you provide clientDataJSON
      origin: origin,
      factor: "either",
      publicKey: publicKeyPem,
      prevCounter: stored.signCount || 0,
      userHandle: null
    };

    const authnResult = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    // update counter
    await db.collection('webauthn').doc(uid).collection('credentials').doc(credId).update({ signCount: authnResult.auditInfo.counter });

    return { success: true };
  } catch (err) {
    console.error('finishLogin error', err);
    return { success: false, error: err.message || String(err) };
  }
}

module.exports = {
  beginRegistration,
  finishRegistration,
  beginLogin,
  finishLogin
};
