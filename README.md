# Smart Door Lock — Full App (Client + Server-side WebAuthn)

## Overview
- Frontend: static site (index.html, styles.css, app.js) — host on Vercel or any static host
- Backend: Firebase (Auth, Firestore) + Cloud Functions (server-side WebAuthn using fido2-lib)
- Client uses WebAuthn with server challenges and `allowCredentials` (cross-device passkeys)
- Fingerprint metadata encrypted client-side with AES-GCM derived from a passphrase

## Setup

### 1. Firebase project
- Create project in Firebase Console
- Enable Authentication: Email/Password and Google Sign-In
- Add authorized domains (your-vercel-domain.vercel.app, localhost)
- Create Firestore database (production mode)
- Deploy Cloud Functions (see `functions` folder)
- Add Firestore rules from README (restrict direct web access to /webauthn)

### 2. Cloud Functions
- `cd functions`
- `npm install`
- Set env var for `RP_DOMAIN` or `ORIGIN` if required:
- `firebase deploy --only functions`

### 3. Frontend
- Fill `firebaseConfig.js` with your Firebase web app config.
- Deploy static site to Vercel (or use `firebase hosting`).

### 4. Test
- Sign in with email on Device A
- In Enroll page, set passphrase, enroll a passkey (WebAuthn)
- Check Cloud Functions logs for registration success
- On Device B (same user), sign in; in Home -> Unlock should call beginLogin -> server returns allowed credential IDs -> browser shows passkey prompt

## Notes & Security
- Do not store raw biometric scans — we only store credential IDs / public keys on server.
- Client encrypts fingerprint metadata with passphrase-derived AES-GCM key — server does not have passphrase.
- For production, consider:
- Using WebAuthn resident keys or relying on platform passkeys UX improvements
- Server-side assertion attestation verification with strict origins and rpId
- Rate-limiting and monitoring Cloud Functions

## Tests
- `tests/ui-walkthrough.md` contains manual steps
- `tests/e2e.test.js` contains Puppeteer (or Playwright) skeleton for automation

