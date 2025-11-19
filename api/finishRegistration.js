// api/finishRegistration.js
import { initAdmin } from "./_admin.js";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
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

    const body = req.body;
    if (!body || !body.rawId) return res.status(400).json({ error: "Invalid attestation body" });

    // load stored challenge
    const challDoc = await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("registration").get();
    if (!challDoc.exists) return res.status(400).json({ error: "No registration challenge found" });
    const expectedChallenge = challDoc.data().challenge;

    const verification = await verifyRegistrationResponse({
      credential: {
        id: body.id,
        rawId: base64url.toBuffer(body.rawId),
        response: {
          attestationObject: base64url.toBuffer(body.response.attestationObject),
          clientDataJSON: base64url.toBuffer(body.response.clientDataJSON)
        },
        type: body.type
      },
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID
    });

    if (!verification.verified) {
      return res.status(400).json({ success: false, error: "Registration verification failed" });
    }

    const { registrationInfo } = verification;
    const credentialID = registrationInfo.credentialID; // Buffer
    const credentialID_b64url = base64url.encode(Buffer.from(credentialID));
    const credentialPublicKey = registrationInfo.credentialPublicKey; // Uint8Array or Buffer
    const credentialPublicKey_b64 = Buffer.from(credentialPublicKey).toString("base64");
    const counter = registrationInfo.counter || 0;

    // store credential under webauthn/{uid}/credentials/{credId}
    await admin.firestore().collection("webauthn").doc(uid).collection("credentials").doc(credentialID_b64url).set({
      credentialID: credentialID_b64url,
      publicKey: credentialPublicKey_b64,
      signCount: counter,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // delete challenge
    await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("registration").delete();

    return res.json({ success: true });
  } catch (err) {
    console.error("finishRegistration error:", err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
}
