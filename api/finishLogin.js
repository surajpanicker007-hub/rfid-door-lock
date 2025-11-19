// api/finishLogin.js
import { initAdmin } from "./_admin.js";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
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
    if (!body || !body.rawId) return res.status(400).json({ error: "Invalid assertion body" });

    // load challenge
    const challDoc = await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("login").get();
    if (!challDoc.exists) return res.status(400).json({ error: "No login challenge found" });
    const expectedChallenge = challDoc.data().challenge;

    // load stored credential (document id should equal the base64url credential id)
    const credId_b64url = body.id;
    const credDoc = await admin.firestore().collection("webauthn").doc(uid).collection("credentials").doc(credId_b64url).get();
    if (!credDoc.exists) return res.status(400).json({ error: "Credential not found" });
    const stored = credDoc.data();

    const verification = await verifyAuthenticationResponse({
      credential: {
        id: body.id,
        rawId: base64url.toBuffer(body.rawId),
        response: {
          authenticatorData: base64url.toBuffer(body.response.authenticatorData),
          clientDataJSON: base64url.toBuffer(body.response.clientDataJSON),
          signature: base64url.toBuffer(body.response.signature),
          userHandle: body.response.userHandle ? base64url.toBuffer(body.response.userHandle) : undefined
        },
        type: body.type
      },
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: base64url.toBuffer(stored.credentialID),
        credentialPublicKey: Buffer.from(stored.publicKey, "base64"),
        counter: stored.signCount || 0
      }
    });

    if (!verification.verified) {
      return res.status(400).json({ success: false, error: "Authentication verification failed" });
    }

    // update counter
    await admin.firestore().collection("webauthn").doc(uid).collection("credentials").doc(credId_b64url).update({
      signCount: verification.authenticationInfo.newCounter
    });

    // delete challenge
    await admin.firestore().collection("webauthn").doc(uid).collection("challenges").doc("login").delete();

    return res.json({ success: true });
  } catch (err) {
    console.error("finishLogin error:", err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
}
