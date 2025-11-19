// api/_admin.js
import admin from "firebase-admin";

let initialized = false;

export function initAdmin() {
  if (initialized) return admin;

  // If full JSON placed in FIREBASE_SERVICE_ACCOUNT env var (minified), use it:
  const svcEnv = process.env.FIREBASE_SERVICE_ACCOUNT;
  let credentialObj = null;

  if (svcEnv) {
    try {
      credentialObj = JSON.parse(svcEnv);
      // some users provide private_key with actual newlines -> normalize to \n sequences
      if (credentialObj.private_key && credentialObj.private_key.includes("\\n")) {
        credentialObj.private_key = credentialObj.private_key.replace(/\\n/g, "\n");
      }
    } catch (err) {
      console.error("FIREBASE_SERVICE_ACCOUNT parse error:", err);
      throw new Error("Invalid FIREBASE_SERVICE_ACCOUNT JSON");
    }
  } else if (process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_PROJECT_ID) {
    // fallback to separate env vars
    credentialObj = {
      type: "service_account",
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
      client_email: process.env.FIREBASE_CLIENT_EMAIL
    };
  } else {
    throw new Error("Missing Firebase service account configuration in env");
  }

  admin.initializeApp({
    credential: admin.credential.cert(credentialObj),
    projectId: credentialObj.project_id || process.env.FIREBASE_PROJECT_ID
  });

  initialized = true;
  return admin;
}
