// /api/verify-enrollment.js
import { auth, db } from "./_firebase";
import {
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

export default async function handler(req, res) {
  try {
    const { uid, response } = req.body;

    const challengeDoc = await db.collection("webauthn_challenges").doc(uid).get();
    if (!challengeDoc.exists) {
      return res.status(400).json({ error: "Challenge not found" });
    }

    const expectedChallenge = challengeDoc.data().challenge;

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: process.env.ORIGIN,
      expectedRPID: process.env.ORIGIN_DOMAIN,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Verification failed" });
    }

    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

    await db.collection("webauthn_credentials").doc(uid).set({
      credentialID,
      credentialPublicKey,
      counter,
    });

    await auth.updateUser(uid, { emailVerified: true });

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Verify enrollment error:", err);
    return res.status(500).json({ error: "Server error" });
  }
}
