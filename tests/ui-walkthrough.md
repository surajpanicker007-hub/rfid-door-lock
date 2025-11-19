1. Deploy frontend to Vercel and functions to Firebase.
2. Open site on Device A (phone or desktop).
3. Register user (Email or Google).
4. Go to Enroll -> set passphrase -> Enroll (WebAuthn).
5. Confirm Cloud Function finished registration (check logs).
6. Open site on Device B, sign in with same user.
7. Click Unlock on Home — you should see your passkey offered (if platform supports it).
8. On success, lock UI shows UNLOCKED and logs an entry.
