// api/beginLogin.js
import { initAdmin } from "./_admin.js";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import base64url from "base64url";

const RP_ID = process.env.RP_ID || undefined;
const ORIGIN = process.env.ORIGIN || undefined;

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");
    const admin = initAdmin();

    const authHeader = req.headers.authorization || "";
    const idToken = (authHeader.match(/^Bearer (.+)$/) || [])[1];
    if (!idToken) return res.status(401).json({ error: "Missing Authorization token" });
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    // fetch saved credential ids for user
    const credsSnap = await admin.firestore().collection("webauthn").doc(uid).collection("credentials").get();
    const allowedCreds = credsSnap.docs.map(d => ({
      id: d.id,
      type: "public-key"
    }));

    const opts = generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: allowedCreds,
      userVerification: "preferred"
    });

    // store challenge
    await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("login").set({
      challenge: opts.challenge,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.json({ publicKey: opts, rpId: RP_ID, origin: ORIGIN });
  } catch (err) {
    console.error("beginLogin error:", err);
    return res.status(500).json({ error: err.message || String(err) });
  }
}
