// ═══════════════════════════════════════════════════
//  REFLEX BALL — Vercel Serverless Function
//  File: api/admin.js
//  URL:  /api/admin
//  Handles: Cloudinary Upload Signatures
//  Auth: Supabase JWT verification
// ═══════════════════════════════════════════════════

const crypto = require('crypto');

const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_JWT_SECRET,   // Supabase → Project Settings → API → JWT Secret
  CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET,
} = process.env;

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body = req.body || {};
  const { action } = body;

  // ── AUTH: verify Supabase JWT from Authorization header ──
  const authHeader = req.headers.authorization || '';
  const supabaseToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  switch (action) {

    // ── CLOUDINARY SIGN — requires valid Supabase JWT ──
    case 'cloudinary-sign': {
      if (!supabaseToken) return res.status(401).json({ error: 'Unauthorized — no token' });

      const valid = await verifySupabaseJWT(supabaseToken);
      if (!valid) return res.status(401).json({ error: 'Invalid or expired session' });

      const folder = body.folder || 'products';
      const timestamp = Math.round(Date.now() / 1000);
      const params = { timestamp, folder };
      if (body.public_id) params.public_id = body.public_id;

      const toSign = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
      const signature = crypto
        .createHash('sha256')
        .update(toSign + (CLOUDINARY_API_SECRET || ''))
        .digest('hex');

      return res.status(200).json({
        signature,
        timestamp,
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

// ── Verify Supabase JWT ──
async function verifySupabaseJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check expiry
    if (!payload.exp || Date.now() / 1000 > payload.exp) return false;

    // Verify signature if JWT secret is configured
    if (SUPABASE_JWT_SECRET) {
      const signingInput = parts[0] + '.' + parts[1];
      const expectedSig = crypto
        .createHmac('sha256', SUPABASE_JWT_SECRET)
        .update(signingInput)
        .digest('base64url');

      // FIX: safeCompare must handle equal-length buffers — pad both to same length
      // before timingSafeEqual, then confirm actual string equality separately.
      return safeCompare(parts[2], expectedSig);
    }

    // Fallback: validate via Supabase REST API
    return await verifyViaSupabaseAPI(token);
  } catch (e) {
    console.error('JWT verify error:', e);
    return false;
  }
}

// Fallback: call Supabase /auth/v1/user to validate the token
async function verifyViaSupabaseAPI(token) {
  try {
    const url = (SUPABASE_URL || '').replace(/\/$/, '') + '/auth/v1/user';
    const r = await fetch(url, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'apikey': SUPABASE_ANON_KEY || '',
      },
    });
    return r.ok;
  } catch (e) {
    console.error('Supabase API verify error:', e);
    return false;
  }
}

// FIX: original version returned false for valid JWTs because base64url strings
// of different padding lengths failed the length check before timingSafeEqual.
// Solution: compare actual string equality AND use equal-length buffers for timing safety.
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;

  // First do a constant-time compare on equal-length buffers (prevents timing attacks).
  const maxLen = Math.max(a.length, b.length);
  const bufA = Buffer.alloc(maxLen);
  const bufB = Buffer.alloc(maxLen);
  bufA.write(a);
  bufB.write(b);

  // timingSafeEqual requires same-length buffers — now guaranteed.
  const timingOk = crypto.timingSafeEqual(bufA, bufB);

  // Also confirm actual string lengths match (the padded compare above would pass
  // if only the overlapping prefix matched).
  return timingOk && a.length === b.length;
}
