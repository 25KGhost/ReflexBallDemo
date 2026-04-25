// ═══════════════════════════════════════════════════
//  REFLEX BALL — Vercel Serverless Function
//  File: api/admin.js
//  URL:  /api/admin
//  Handles: Admin Auth · Cloudinary Upload Signatures
// ═══════════════════════════════════════════════════

const crypto = require('crypto');

const {
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET,
  SESSION_SECRET,
} = process.env;

// ── Vercel uses module.exports = async (req, res) ──
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body = req.body || {};
  const { action } = body;

  switch (action) {

    // ── LOGIN ──────────────────────────────────────
    case 'login': {
      const { username, password } = body;
      const validUser = safeCompare(username || '', ADMIN_USERNAME || '');
      const validPass = safeCompare(password || '', ADMIN_PASSWORD || '');
      if (!validUser || !validPass) return res.status(401).json({ error: 'Invalid credentials' });

      const expires = Date.now() + 8 * 60 * 60 * 1000;
      const payload = `${expires}`;
      const sig = hmac(payload, SESSION_SECRET || 'fallback-change-me');
      const token = `${payload}.${sig}`;
      return res.status(200).json({ token, expires });
    }

    // ── VERIFY ─────────────────────────────────────
    case 'verify': {
      if (!validateToken(body.token)) return res.status(401).json({ error: 'Invalid or expired token' });
      return res.status(200).json({ valid: true });
    }

    // ── CLOUDINARY SIGN ────────────────────────────
    case 'cloudinary-sign': {
      if (!validateToken(body.token)) return res.status(401).json({ error: 'Unauthorized' });

      const folder = body.folder || 'products';
      const timestamp = Math.round(Date.now() / 1000);
      const params = { timestamp, folder };
      if (body.public_id) params.public_id = body.public_id;

      const toSign = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
      const signature = crypto.createHash('sha256')
        .update(toSign + (CLOUDINARY_API_SECRET || ''))
        .digest('hex');

      return res.status(200).json({
        signature, timestamp,
        api_key: CLOUDINARY_API_KEY,
        cloud_name: CLOUDINARY_CLOUD_NAME,
        folder,
        ...(body.public_id ? { public_id: body.public_id } : {}),
      });
    }

    default:
      return res.status(400).json({ error: `Unknown action: ${action}` });
  }
};

function hmac(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function validateToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expires, sig] = parts;
  if (Date.now() > parseInt(expires, 10)) return false;
  const expected = hmac(expires, SESSION_SECRET || 'fallback-change-me');
  return safeCompare(sig, expected);
}

function safeCompare(a, b) {
  if (a.length !== b.length) {
    crypto.timingSafeEqual(Buffer.from(a.padEnd(b.length)), Buffer.from(b.padEnd(a.length)));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
