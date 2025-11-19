const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

const webauthn = require('./webauthn');

// Callable endpoints
exports.beginRegistration = functions.https.onCall(async (data, context) => {
  // Must be authenticated
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'User must be signed in');
  const uid = context.auth.uid;
  return await webauthn.beginRegistration(uid);
});

exports.finishRegistration = functions.https.onCall(async (attestation, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'User must be signed in');
  const uid = context.auth.uid;
  return await webauthn.finishRegistration(uid, attestation);
});

exports.beginLogin = functions.https.onCall(async (data, context) => {
  // allow unauthenticated callers in case you want to start login flow before sign-in to Firebase
  // but for our flow, we require auth
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'User must be signed in');
  const uid = context.auth.uid;
  return await webauthn.beginLogin(uid);
});

exports.finishLogin = functions.https.onCall(async (assertion, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'User must be signed in');
  const uid = context.auth.uid;
  return await webauthn.finishLogin(uid, assertion);
});
