// /api/login-verify.js
import { db, auth } from "./_firebase";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";

export default async function handler(req, res) {
  try {
    const { uid, response } = req.body;

    const challengeDoc = await db.collection("webauthn_challenges").doc(uid).get();
    const credDoc = await db.collection("webauthn_credentials").doc(uid).get();

    if (!challengeDoc.exists || !credDoc.exists) {
      return res.status(400).json({ error: "Missing data" });
    }

    const { credentialID, credentialPublicKey, counter } = credDoc.data();

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeDoc.data().challenge,
      expectedOrigin: process.env.ORIGIN,
      expectedRPID: process.env.ORIGIN_DOMAIN,
      authenticator: {
        credentialID,
        credentialPublicKey,
        counter,
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Verification failed" });
    }

    await db.collection("webauthn_credentials").doc(uid).update({
      counter: verification.authenticationInfo.newCounter,
    });

    const customToken = await auth.createCustomToken(uid);

    return res.status(200).json({ verified: true, token: customToken });
  } catch (err) {
    console.error("Login verify error:", err);
    return res.status(500).json({ error: "Server error" });
  }
}
