// api/_admin.js
const admin = require('firebase-admin');

let initialized = false;

function initAdmin() {
  if (initialized) return admin;

  const svc = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!svc) throw new Error('FIREBASE_SERVICE_ACCOUNT env var missing');
  const serviceAccount = JSON.parse(svc);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
  });

  initialized = true;
  return admin;
}

module.exports = initAdmin;
