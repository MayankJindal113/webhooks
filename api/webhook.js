// api/webhook.js
const crypto = require('crypto');
const { URLSearchParams } = require('url');

function safeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch (e) {
    return false;
  }
}

async function getRawBody(req) {
  // accumulate raw bytes from the incoming request stream
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function computeHmacHex(secret, buf, algo = 'sha256') {
  return crypto.createHmac(algo, secret).update(buf).digest('hex');
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method Not Allowed');
  }

  const SECRET = process.env.GITHUB_WEBHOOK_SECRET || '';
  if (!SECRET) {
    console.warn('GITHUB_WEBHOOK_SECRET is not set!');
  }

  // Read raw bytes (important for correct signature verification)
  const raw = await getRawBody(req); // Buffer
  const contentType = (req.headers['content-type'] || '').toLowerCase();

  // Headers from GitHub
  const sig256Header = req.headers['x-hub-signature-256']; // "sha256=..."
  const sig1Header = req.headers['x-hub-signature']; // "sha1=..."
  const event = req.headers['x-github-event'] || 'unknown';
  const delivery = req.headers['x-github-delivery'] || '';

  // Compute expected HMACs
  const expected256 = computeHmacHex(SECRET, raw, 'sha256'); // hex string
  const expected1 = computeHmacHex(SECRET, raw, 'sha1'); // hex string

  // Extract signature values from headers (strip algo=)
  const header256 = sig256Header && sig256Header.startsWith('sha256=') ? sig256Header.slice(7) : sig256Header;
  const header1 = sig1Header && sig1Header.startsWith('sha1=') ? sig1Header.slice(5) : sig1Header;

  const valid256 = header256 ? safeEqual(header256, expected256) : false;
  const valid1 = header1 ? safeEqual(header1, expected1) : false;

  if (!valid256 && !valid1) {
    // Debug helpers (DO NOT LOG SECRET)
    console.warn('Webhook signature mismatch', {
      has_sig256: !!sig256Header,
      has_sig1: !!sig1Header,
      expected256,
      expected1,
      header256,
      header1,
      contentType,
    });
    return res.status(401).send('Invalid signature');
  }

  // Parse payload into JS object:
  let payload = null;
  try {
    if (contentType.includes('application/json')) {
      payload = JSON.parse(raw.toString('utf8'));
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      // GitHub may send body like: payload=%7B...%7D
      const s = raw.toString('utf8');
      const params = new URLSearchParams(s);
      // prefer "payload" key if present
      if (params.has('payload')) {
        payload = JSON.parse(params.get('payload'));
      } else {
        // else attempt parsing entire body as JSON
        try { payload = JSON.parse(s); } catch (e) { payload = { form: Object.fromEntries(params) }; }
      }
    } else {
      // fallback: try parse JSON
      payload = JSON.parse(raw.toString('utf8'));
    }
  } catch (err) {
    console.warn('Failed parsing payload', err.message);
    payload = { parse_error: err.message, raw: raw.toString('utf8').slice(0, 2000) };
  }

  // store in-memory (ephemeral)
  if (!global.__gh_events) global.__gh_events = [];
  const events = global.__gh_events;
  events.unshift({
    id: delivery || Math.random().toString(36).slice(2),
    event,
    received_at: new Date().toISOString(),
    payload,
  });
  if (events.length > 200) events.length = 200;

  // respond quickly
  res.status(200).json({ ok: true, received_event: event, id: delivery });
};
