// api/beginRegistration.js
import { initAdmin } from "./_admin.js";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import base64url from "base64url";

const RP_NAME = process.env.RP_NAME || "Smart Door Lock";
const RP_ID = process.env.RP_ID || undefined; // recommended set to your domain (no https)
const ORIGIN = process.env.ORIGIN || undefined;

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).send("Method Not Allowed");
    const admin = initAdmin();

    // verify idToken from Authorization header
    const authHeader = req.headers.authorization || "";
    const idToken = (authHeader.match(/^Bearer (.+)$/) || [])[1];
    if (!idToken) return res.status(401).json({ error: "Missing Authorization token" });
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    // build user object (user.id must be a buffer when consumed by client; we'll base64url it)
    const user = {
      id: base64url.encode(uid), // client will decode to get user.id buffer
      name: decoded.email || uid,
      displayName: decoded.name || decoded.email || uid
    };

    const opts = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: user.id,
      userName: user.name,
      attestationType: "none",
      authenticatorSelection: {
        userVerification: "preferred"
      }
    });

    // excludeCredentials (use stored credential ids if exist)
    const credsRef = admin.firestore().collection("webauthn").doc(uid).collection("credentials");
    const credsSnap = await credsRef.get();
    if (!credsSnap.empty) {
      opts.excludeCredentials = credsSnap.docs.map(d => ({
        id: d.id,
        type: "public-key"
      }));
    }

    // store challenge (single-use)
    await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("registration").set({
      challenge: opts.challenge,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Send publicKey options — challenge and user.id are base64url strings for client usage
    return res.json({ publicKey: opts, rpId: RP_ID, origin: ORIGIN });
  } catch (err) {
    console.error("beginRegistration error:", err);
    return res.status(500).json({ error: err.message || String(err) });
  }
}
