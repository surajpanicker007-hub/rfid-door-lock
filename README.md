# Smart Door Lock — Vercel + Firestore + WebAuthn (anonymous auth)

## Overview
- Frontend: static files in `public/`
- Server: Vercel Serverless functions under `api/` using `@simplewebauthn/server` and Firebase Admin
- Uses anonymous Firebase Auth for user identity (uid) and ID token protection

## Environment variables (set in Vercel Dashboard)
Required:
- `FIREBASE_SERVICE_ACCOUNT` = (minified JSON of service account) OR supply individual vars below
- `FIREBASE_PROJECT_ID` = your firebase project id
- `FIREBASE_CLIENT_EMAIL` = client_email from service account
- `FIREBASE_PRIVATE_KEY` = private_key as single-line with `\n` sequences (if not using FIREBASE_SERVICE_ACCOUNT)
- `RP_ID` = example: `yourproject.vercel.app` (recommended)
- `ORIGIN` = example: `https://yourproject.vercel.app` (recommended)
- `RP_NAME` (optional) friendly name e.g. "Smart Door Lock"

**Important:** If you use `FIREBASE_SERVICE_ACCOUNT` (single minified JSON), ensure `private_key` inside it has `\n` escaped (i.e., `\\n` when the JSON is raw), or Vercel will parse it — the `_admin.js` will replace `\\n` with `\n`.

## Deploy
1. `git push` repository to your Git provider and import to Vercel OR use `vercel` CLI.
2. Ensure environment variables are set in Vercel.
3. Deploy and visit `https://<your-site>.vercel.app`.

## Testing
- Open site on Device A: you’ll be signed-in anonymously automatically. Enroll a passkey (go to Enroll).
- Open site on Device B (same account or sign in same anonymous user?): for cross-device, sign-in with same Firebase user (upgrade anonymous account to permanent by linking credential) — otherwise, credentials belong to a uid.
- Use DevTools -> Network to inspect `/api/beginRegistration`, `/api/finishRegistration`, `/api/beginLogin`, `/api/finishLogin`.

## Firestore layout
- `webauthn/{uid}/challenges/registration` -> { challenge, createdAt }
- `webauthn/{uid}/challenges/login` -> { challenge, createdAt }
- `webauthn/{uid}/credentials/{credentialId}` -> { credentialID, publicKey, signCount, createdAt }
- `users/{uid}/fingerprints/{doc}` -> { iv, ct, createdAt } (encrypted metadata)

## Notes
- For true cross-device passkey portability, users must sign-in on multiple devices with the *same* Firebase user (link anonymous account to Google/email) or transfer credentials by other means.
- Keep `FIREBASE_SERVICE_ACCOUNT` secret.

