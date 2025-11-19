// /api/login-challenge.js
import { db } from "./_firebase";
import { generateAuthenticationOptions } from "@simplewebauthn/server";

export default async function handler(req, res) {
  try {
    const { uid } = req.query;

    const credDoc = await db.collection("webauthn_credentials").doc(uid).get();
    if (!credDoc.exists) {
      return res.status(400).json({ error: "User has no credentials" });
    }

    const { credentialID } = credDoc.data();

    const options = generateAuthenticationOptions({
      allowCredentials: [
        {
          id: Buffer.from(credentialID, "base64url"),
          type: "public-key",
        },
      ],
      userVerification: "required",
      rpID: process.env.ORIGIN_DOMAIN,
    });

    await db.collection("webauthn_challenges").doc(uid).set({
      challenge: options.challenge,
      createdAt: Date.now(),
    });

    return res.status(200).json(options);
  } catch (err) {
    console.error("Login challenge error:", err);
    return res.status(500).json({ error: "Server error" });
  }
}
