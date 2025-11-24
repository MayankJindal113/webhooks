const crypto = require("crypto");

const SECRET = process.env.GITHUB_WEBHOOK_SECRET || ""; // set in Vercel env vars
// In-memory storage (ephemeral)
if (!global.__gh_events) global.__gh_events = [];
const events = global.__gh_events;

function verifySignature(reqBody, header) {
  if (!header) return false;
  const sigParts = header.split("=");
  if (sigParts.length !== 2) return false;
  const algo = sigParts[0]; // should be 'sha256'
  const signature = sigParts[1];

  const hmac = crypto.createHmac("sha256", SECRET);
  const digest = hmac.update(reqBody).digest("hex");
  // timing-safe compare
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
}

module.exports = async function (req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).send("Method Not Allowed");
  }

  // Raw body is needed to verify signature correctly.
  // Vercel provides body parsed by default; ensure raw body available.
  // If using Next.js, use the raw body approach; here we assume the body is already parsed,
  // so reconstruct canonical JSON string for signature (GitHub signs raw bytes).
  // For a minimal approach, use X-Hub-Signature-256 verification computed from JSON.stringify(req.body)
  const rawBody = JSON.stringify(req.body || {});
  const sigHeader = req.headers["x-hub-signature-256"];

  if (!SECRET) {
    console.warn(
      "GITHUB_WEBHOOK_SECRET is not set. Signature verification disabled!"
    );
  } else if (!verifySignature(rawBody, sigHeader)) {
    console.warn("Invalid GitHub webhook signature");
    return res.status(401).send("Invalid signature");
  }

  const ghEvent = req.headers["x-github-event"] || "unknown";
  const deliveryId = req.headers["x-github-delivery"] || "";

  // handle ping
  if (ghEvent === "ping") {
    events.unshift({
      id: deliveryId,
      type: "ping",
      received_at: new Date().toISOString(),
      payload: req.body,
    });
    return res.status(200).json({ msg: "pong" });
  }

  // Store payload minimally
  events.unshift({
    id: deliveryId,
    type: ghEvent,
    received_at: new Date().toISOString(),
    payload: req.body,
  });

  // keep only last N in memory
  if (events.length > 200) events.length = 200;

  // Respond quickly
  res.status(200).send("ok");
};
