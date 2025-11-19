// /api/enroll-device.js
import { db } from "./_firebase";
import { generateRegistrationOptions } from "@simplewebauthn/server";

export default async function handler(req, res) {
  try {
    const { uid } = req.body;

    if (!uid) return res.status(400).json({ error: "Missing uid" });

    const options = generateRegistrationOptions({
      rpName: "My App",
      rpID: process.env.ORIGIN_DOMAIN,
      userID: uid,
      userName: uid,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
      },
    });

    await db.collection("webauthn_challenges").doc(uid).set({
      challenge: options.challenge,
      createdAt: Date.now(),
    });

    return res.status(200).json(options);
  } catch (err) {
    console.error("Enroll error:", err);
    return res.status(500).json({ error: "Server error" });
  }
}
