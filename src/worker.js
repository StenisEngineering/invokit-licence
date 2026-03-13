export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/$/, '') || '/';
      const method = request.method.toUpperCase();

      if (method === 'OPTIONS') return handleCors(request, env);

      if (path === '/health') {
        return json({ ok: true, service: 'invokit-licence', ts: Date.now() }, 200, env);
      }

      if (path === '/validate' && method === 'POST') {
        return await handleValidate(request, env);
      }

      if (path === '/generate' && method === 'POST') {
        await requireAdmin(request, env);
        return await handleGenerate(request, env);
      }

      if (path === '/revoke' && method === 'POST') {
        await requireAdmin(request, env);
        return await handleRevoke(request, env);
      }

      if (path === '/find' && method === 'GET') {
        await requireAdmin(request, env);
        return await handleFind(request, env, url);
      }

      return json({ ok: false, error: 'Not found' }, 404, env);
    } catch (err) {
      return json({ ok: false, error: err.message || 'Server error' }, err.status || 500, env);
    }
  }
};

function corsHeaders(env) {
  const origin = env.ALLOWED_ORIGIN || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Secret',
    'Access-Control-Max-Age': '86400'
  };
}

function json(data, status = 200, env) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...corsHeaders(env)
    }
  });
}

function handleCors(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(env) });
}

async function requireAdmin(request, env) {
  const provided = request.headers.get('X-Admin-Secret') || '';
  const expected = env.ADMIN_SECRET || '';
  if (!provided || !expected) {
    const e = new Error('Admin secret missing');
    e.status = 401;
    throw e;
  }
  const ok = await timingSafeTextEqual(provided, expected);
  if (!ok) {
    const e = new Error('Unauthorized');
    e.status = 403;
    throw e;
  }
}

async function handleGenerate(request, env) {
  const body = await request.json();
  const buyerName = clean(body.buyerName, 120);
  const buyerEmail = normalizeEmail(body.buyerEmail);
  const plan = clean(body.plan || 'lifetime', 40).toLowerCase();
  const orderRef = clean(body.orderRef || '', 120);
  const deviceLimit = clampInt(body.deviceLimit ?? 1, 1, 5);
  const expiresAt = normalizeExpiry(body.expiresAt);
  const notes = clean(body.notes || '', 500);

  if (!buyerEmail) throw httpError('Buyer email is required', 400);

  const serial = crypto.randomUUID().replace(/-/g, '').slice(0, 12).toUpperCase();
  const key = formatKeyFromSerial(serial);
  const keyHash = await sha256Hex(key + '|' + env.KEY_PEPPER);
  const now = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO licences (
      serial, licence_key_hash, buyer_name, buyer_email, plan,
      order_ref, device_limit, expires_at, status, notes, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `).bind(
    serial,
    keyHash,
    buyerName,
    buyerEmail,
    plan,
    orderRef,
    deviceLimit,
    expiresAt,
    notes,
    now,
    now
  ).run();

  return json({
    ok: true,
    licence: {
      key,
      serial,
      buyerName,
      buyerEmail,
      plan,
      orderRef,
      deviceLimit,
      expiresAt,
      status: 'active',
      createdAt: now
    }
  }, 200, env);
}

async function handleValidate(request, env) {
  const body = await request.json();
  const key = clean(body.key, 64).toUpperCase();
  const installId = clean(body.installId, 120);
  const deviceName = clean(body.deviceName || '', 160);
  const appVersion = clean(body.appVersion || '', 40);

  if (!key) throw httpError('Licence key is required', 400);
  if (!installId) throw httpError('Install ID is required', 400);

  const keyHash = await sha256Hex(key + '|' + env.KEY_PEPPER);
  const { results } = await env.DB.prepare(`
    SELECT * FROM licences WHERE licence_key_hash = ? LIMIT 1
  `).bind(keyHash).all();

  const licence = results?.[0];
  if (!licence) throw httpError('Invalid licence key', 404);
  if (licence.status !== 'active') throw httpError('Licence is not active', 403);

  if (licence.expires_at) {
    const expiryTime = Date.parse(licence.expires_at);
    if (!Number.isNaN(expiryTime) && expiryTime < Date.now()) {
      throw httpError('Licence has expired', 403);
    }
  }

  const existingActivation = await env.DB.prepare(`
    SELECT * FROM activations WHERE licence_id = ? AND install_id = ? LIMIT 1
  `).bind(licence.id, installId).first();

  let activationCountRow = await env.DB.prepare(`
    SELECT COUNT(*) AS c FROM activations WHERE licence_id = ?
  `).bind(licence.id).first();
  const activationCount = Number(activationCountRow?.c || 0);

  if (!existingActivation && activationCount >= Number(licence.device_limit || 1)) {
    throw httpError('Activation limit reached for this licence', 403);
  }

  const now = new Date().toISOString();
  if (!existingActivation) {
    await env.DB.prepare(`
      INSERT INTO activations (
        licence_id, install_id, device_name, app_version, activated_at, last_seen_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(licence.id, installId, deviceName, appVersion, now, now).run();
  } else {
    await env.DB.prepare(`
      UPDATE activations
      SET device_name = ?, app_version = ?, last_seen_at = ?
      WHERE id = ?
    `).bind(deviceName, appVersion, now, existingActivation.id).run();
  }

  await env.DB.prepare(`UPDATE licences SET last_validated_at = ?, updated_at = ? WHERE id = ?`)
    .bind(now, now, licence.id)
    .run();

  const activationToken = await signActivationToken({
    licenceId: licence.id,
    serial: licence.serial,
    installId,
    plan: licence.plan,
    buyerEmail: licence.buyer_email,
    activatedAt: now,
    expiresAt: licence.expires_at || null,
    deviceLimit: licence.device_limit
  }, env.ACTIVATION_SECRET);

  return json({
    ok: true,
    activation: {
      token: activationToken,
      licence: {
        serial: licence.serial,
        plan: licence.plan,
        buyerEmail: licence.buyer_email,
        deviceLimit: licence.device_limit,
        expiresAt: licence.expires_at || null
      }
    }
  }, 200, env);
}

async function handleRevoke(request, env) {
  const body = await request.json();
  const key = clean(body.key, 64).toUpperCase();
  if (!key) throw httpError('Licence key is required', 400);
  const keyHash = await sha256Hex(key + '|' + env.KEY_PEPPER);
  const now = new Date().toISOString();
  const res = await env.DB.prepare(`
    UPDATE licences SET status = 'revoked', updated_at = ? WHERE licence_key_hash = ?
  `).bind(now, keyHash).run();
  return json({ ok: true, updated: res.meta?.changes || 0 }, 200, env);
}

async function handleFind(request, env, url) {
  const email = normalizeEmail(url.searchParams.get('email') || '');
  const serial = clean(url.searchParams.get('serial') || '', 40).toUpperCase();
  if (!email && !serial) throw httpError('Provide email or serial', 400);

  let stmt;
  if (email) {
    stmt = env.DB.prepare(`
      SELECT id, serial, buyer_name, buyer_email, plan, order_ref, device_limit, expires_at, status, created_at, last_validated_at
      FROM licences WHERE buyer_email = ? ORDER BY id DESC LIMIT 20
    `).bind(email);
  } else {
    stmt = env.DB.prepare(`
      SELECT id, serial, buyer_name, buyer_email, plan, order_ref, device_limit, expires_at, status, created_at, last_validated_at
      FROM licences WHERE serial = ? LIMIT 1
    `).bind(serial);
  }
  const { results } = await stmt.all();
  return json({ ok: true, licences: results || [] }, 200, env);
}

function clean(value, maxLen = 255) {
  return String(value || '').trim().slice(0, maxLen);
}

function normalizeEmail(value) {
  const v = clean(value, 200).toLowerCase();
  if (!v) return '';
  const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  return ok ? v : '';
}

function normalizeExpiry(value) {
  const v = clean(value, 40);
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw httpError('Invalid expiry date', 400);
  return d.toISOString();
}

function clampInt(value, min, max) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function httpError(message, status = 400) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function formatKeyFromSerial(serial) {
  const chunks = serial.match(/.{1,4}/g) || [serial];
  return ['IVK', ...chunks].join('-');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function signActivationToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'IVK1' };
  const body = payload;
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedBody = base64url(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const key = await importHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlBytes(new Uint8Array(sig))}`;
}

function base64url(input) {
  return base64urlBytes(new TextEncoder().encode(input));
}

function base64urlBytes(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function timingSafeTextEqual(a, b) {
  const enc = new TextEncoder();
  const ah = await crypto.subtle.digest('SHA-256', enc.encode(a));
  const bh = await crypto.subtle.digest('SHA-256', enc.encode(b));
  return crypto.subtle.timingSafeEqual(new Uint8Array(ah), new Uint8Array(bh));
}
