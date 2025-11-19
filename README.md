# Smart Door Lock — Vercel + Firestore + WebAuthn (server-side)

## Overview
Frontend: static site deployed on Vercel.  
Server: Vercel Serverless Functions (/api/*) implement WebAuthn server flows using `fido2-lib` and Firebase Admin SDK.  
Firestore stores user data (`users/{uid}/...`) and server stores WebAuthn credentials under `webauthn/{uid}/...` via Admin SDK.

## Setup steps

1. **Firebase**
   - Create Firebase project.
   - Enable Authentication (Email/Password, Google).
   - Create Firestore database.
   - Add your Vercel domain to Authorized domains (Auth settings).

2. **Service account**
   - In Firebase Console → Project Settings → Service accounts → Generate new private key (JSON).
   - Copy the JSON contents. In Vercel project settings, add environment variable:
     - `FIREBASE_SERVICE_ACCOUNT` = (paste JSON as single-line string)
   - Also add:
     - `FIREBASE_PROJECT_ID` = your project id
     - `RP_ID` = your domain (e.g., yourdomain.vercel.app) — recommended
     - `ORIGIN` = `https://yourdomain.vercel.app` (used in verification)

3. **Deploy to Vercel**
   - Push this repo to Git provider and import to Vercel.
   - Vercel will install dependencies and deploy.
   - Make sure environment variables are set in Vercel.

4. **Frontend**
   - Edit `firebaseConfig.js` with your web app config (from Firebase Console).
   - Deploy, open site.

5. **Test**
   - Sign in on Device A → Enroll passkey → Server `webauthn` collection should contain credential docs.
   - Sign in on Device B → Unlock should call `beginLogin` and the browser should show passkey choices.

## Notes
- Vercel functions will run on demand; Firestore and Admin SDK are used in server functions.
- Keep `FIREBASE_SERVICE_ACCOUNT` secret.
- For production, ensure `RP_ID` and `ORIGIN` match exactly your site domain.

