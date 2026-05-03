var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/worker.js
var worker_default = {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/$/, "") || "/";
      const method = request.method.toUpperCase();
      if (method === "OPTIONS") return handleCors(request, env);
      if (path === "/health") {
        return json({ ok: true, service: "invokit-licence", ts: Date.now() }, 200, request, env);
      }
      if (path === "/validate" && method === "POST") {
        return await handleValidate(request, env);
      }
      if (path === "/generate" && method === "POST") {
        await requireAdmin(request, env);
        return await handleGenerate(request, env);
      }
      if (path === "/generate-free" && method === "POST") {
        await requireAdmin(request, env);
        return await handleGenerateFree(request, env);
      }
      if (path === "/revoke" && method === "POST") {
        await requireAdmin(request, env);
        return await handleRevoke(request, env);
      }
      if (path === "/find" && method === "GET") {
        await requireAdmin(request, env);
        return await handleFind(request, env, url);
      }
      if (path === "/webhook/lemonsqueezy" && method === "POST") {
        return await handleLemonSqueezyWebhook(request, env);
      }
      return json({ ok: false, error: "Not found" }, 404, request, env);
    } catch (err) {
      return json({ ok: false, error: err.message || "Server error" }, err.status || 500, request, env);
    }
  }
};

// ── PLAN RULES ────────────────────────────────────────────────────────────────
const PLAN_RULES = {
  free:     { deviceLimit: 1, invoiceLimit: 5,  pdfExport: false, analytics: false, recurring: false, export: false },
  annual:   { deviceLimit: 2, invoiceLimit: null, pdfExport: true,  analytics: true,  recurring: true,  export: true  },
  lifetime: { deviceLimit: 5, invoiceLimit: null, pdfExport: true,  analytics: true,  recurring: true,  export: true  },
};

function getPlanRules(plan) {
  return PLAN_RULES[String(plan || "").toLowerCase()] || PLAN_RULES["lifetime"];
}
__name(getPlanRules, "getPlanRules");

function getAllowedOrigins(env) {
  const configured = String(env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
  return new Set([
    "https://app.getinvokitpro.com",
    "https://admin-invokit.pages.dev",
    ...configured
  ]);
}
__name(getAllowedOrigins, "getAllowedOrigins");

function corsHeaders(request, env) {
  const requestOrigin = request.headers.get("Origin") || "";
  const allowedOrigins = getAllowedOrigins(env);
  const allowOrigin = allowedOrigins.has(requestOrigin) ? requestOrigin : [...allowedOrigins][0] || "https://app.getinvokitpro.com";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
__name(corsHeaders, "corsHeaders");

function json(data, status = 200, request, env) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(request, env)
    }
  });
}
__name(json, "json");

function handleCors(request, env) {
  return new Response(null, { status: 204, headers: corsHeaders(request, env) });
}
__name(handleCors, "handleCors");

async function requireAdmin(request, env) {
  const provided = request.headers.get("X-Admin-Secret") || "";
  const expected = env.ADMIN_SECRET || "";
  if (!provided || !expected) {
    throw httpError("Admin secret missing", 401);
  }
  const ok = await timingSafeTextEqual(provided, expected);
  if (!ok) {
    throw httpError("Unauthorized", 403);
  }
}
__name(requireAdmin, "requireAdmin");

// ── GENERATE (standard paid) ──────────────────────────────────────────────────
async function handleGenerate(request, env) {
  const body = await request.json();
  const buyerName = clean(body.buyerName, 120);
  const buyerEmail = normalizeEmail(body.buyerEmail);
  const plan = clean(body.plan || "lifetime", 40).toLowerCase();
  const orderRef = clean(body.orderRef || "", 120);
  const rules = getPlanRules(plan);
  const deviceLimit = clampInt(body.deviceLimit ?? rules.deviceLimit, 1, 5);
  const expiresAt = normalizeExpiry(body.expiresAt);
  const notes = clean(body.notes || "", 500);
  if (!buyerEmail) throw httpError("Buyer email is required", 400);
  const serial = crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
  const key = formatKeyFromSerial(serial);
  const keyHash = await sha256Hex(key + "|" + env.KEY_PEPPER);
  const now = (new Date()).toISOString();
  await env.DB.prepare(`
    INSERT INTO licences (
      serial, licence_key_hash, buyer_name, buyer_email, plan,
      order_ref, device_limit, expires_at, status, notes, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `).bind(
    serial, keyHash, buyerName, buyerEmail, plan,
    orderRef, deviceLimit, expiresAt, notes, now, now
  ).run();
  return json({
    ok: true,
    licence: { key, serial, buyerName, buyerEmail, plan, orderRef, deviceLimit, expiresAt, status: "active", createdAt: now }
  }, 200, request, env);
}
__name(handleGenerate, "handleGenerate");

// ── GENERATE FREE (1-device, restricted plan) ─────────────────────────────────
async function handleGenerateFree(request, env) {
  const body = await request.json();
  const buyerName = clean(body.recipientName || body.buyerName || "Free User", 120);
  const buyerEmail = normalizeEmail(body.recipientEmail || body.buyerEmail || "");
  const notes = clean(body.notes || "Free licence - 1 device, 5 invoices", 500);
  if (!buyerEmail) throw httpError("Recipient email is required", 400);
  // Check: cap total free licences at 10 to prevent abuse
  const { results: existing } = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM licences WHERE plan = 'free'`
  ).all();
  const freeCount = Number(existing?.[0]?.c || 0);
  if (freeCount >= 10) throw httpError("Free licence cap reached (10 max)", 403);
  const serial = crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
  const key = formatKeyFromSerial(serial);
  const keyHash = await sha256Hex(key + "|" + env.KEY_PEPPER);
  const now = (new Date()).toISOString();
  await env.DB.prepare(`
    INSERT INTO licences (
      serial, licence_key_hash, buyer_name, buyer_email, plan,
      order_ref, device_limit, expires_at, status, notes, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'free', 'FREE-GIFT', 1, NULL, 'active', ?, ?, ?)
  `).bind(serial, keyHash, buyerName, buyerEmail, notes, now, now).run();
  return json({
    ok: true,
    licence: {
      key,
      serial,
      recipientName: buyerName,
      recipientEmail: buyerEmail,
      plan: "free",
      deviceLimit: 1,
      restrictions: PLAN_RULES.free,
      status: "active",
      createdAt: now
    }
  }, 200, request, env);
}
__name(handleGenerateFree, "handleGenerateFree");

// ── VALIDATE ──────────────────────────────────────────────────────────────────
async function handleValidate(request, env) {
  const body = await request.json();
  const key = clean(body.key, 64).toUpperCase();
  const installId = clean(body.installId, 120);
  const deviceName = clean(body.deviceName || "", 160);
  const appVersion = clean(body.appVersion || "", 40);
  if (!key) throw httpError("Licence key is required", 400);
  if (!installId) throw httpError("Install ID is required", 400);
  const keyHash = await sha256Hex(key + "|" + env.KEY_PEPPER);
  const { results } = await env.DB.prepare(`
    SELECT * FROM licences WHERE licence_key_hash = ? LIMIT 1
  `).bind(keyHash).all();
  const licence = results?.[0];
  if (!licence) throw httpError("Invalid licence key", 404);
  if (licence.status !== "active") throw httpError("Licence is not active", 403);
  if (licence.expires_at) {
    const expiryTime = Date.parse(licence.expires_at);
    if (!Number.isNaN(expiryTime) && expiryTime < Date.now()) {
      throw httpError("Licence has expired", 403);
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
    // For free plan give a clearer message
    const isFree = String(licence.plan || "").toLowerCase() === "free";
    throw httpError(
      isFree
        ? "This free licence is already activated on another device. Free licences are single-device only."
        : "Activation limit reached for this licence",
      403
    );
  }
  const now = (new Date()).toISOString();
  if (!existingActivation) {
    await env.DB.prepare(`
      INSERT INTO activations (
        licence_id, install_id, device_name, app_version, activated_at, last_seen_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(licence.id, installId, deviceName, appVersion, now, now).run();
  } else {
    await env.DB.prepare(`
      UPDATE activations SET device_name = ?, app_version = ?, last_seen_at = ? WHERE id = ?
    `).bind(deviceName, appVersion, now, existingActivation.id).run();
  }
  await env.DB.prepare(`UPDATE licences SET last_validated_at = ?, updated_at = ? WHERE id = ?`).bind(now, now, licence.id).run();

  const planRules = getPlanRules(licence.plan);

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
        expiresAt: licence.expires_at || null,
        // Return plan rules so the app can enforce them client-side
        features: planRules
      }
    }
  }, 200, request, env);
}
__name(handleValidate, "handleValidate");

// ── REVOKE ────────────────────────────────────────────────────────────────────
async function handleRevoke(request, env) {
  const body = await request.json();
  const key = clean(body.key, 64).toUpperCase();
  if (!key) throw httpError("Licence key is required", 400);
  const keyHash = await sha256Hex(key + "|" + env.KEY_PEPPER);
  const now = (new Date()).toISOString();
  const res = await env.DB.prepare(`
    UPDATE licences SET status = 'revoked', updated_at = ? WHERE licence_key_hash = ?
  `).bind(now, keyHash).run();
  return json({ ok: true, updated: res.meta?.changes || 0 }, 200, request, env);
}
__name(handleRevoke, "handleRevoke");

// ── FIND ──────────────────────────────────────────────────────────────────────
async function handleFind(request, env, url) {
  const email = normalizeEmail(url.searchParams.get("email") || "");
  const serial = clean(url.searchParams.get("serial") || "", 40).toUpperCase();
  if (!email && !serial) throw httpError("Provide email or serial", 400);
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
  return json({ ok: true, licences: results || [] }, 200, request, env);
}
__name(handleFind, "handleFind");


// ── LEMONSQUEEZY WEBHOOK ──────────────────────────────────────────────────────
// Handles order_created events → auto-generates licence key → emails buyer
async function handleLemonSqueezyWebhook(request, env) {
  // 1. Verify signature
  const rawBody = await request.text();
  const signature = request.headers.get("X-Signature") || "";
  const secret = env.LS_WEBHOOK_SECRET || "";
  if (secret) {
    const valid = await verifyLsSignature(rawBody, signature, secret);
    if (!valid) {
      return json({ ok: false, error: "Invalid webhook signature" }, 401, request, env);
    }
  }

  // 2. Parse event
  let event;
  try { event = JSON.parse(rawBody); } catch {
    return json({ ok: false, error: "Invalid JSON" }, 400, request, env);
  }

  const eventName = event?.meta?.event_name;
  if (eventName !== "order_created") {
    // Acknowledge but ignore other events
    return json({ ok: true, ignored: eventName }, 200, request, env);
  }

  // 3. Extract order data
  const order = event?.data?.attributes;
  const variantId = String(event?.data?.relationships?.order_items?.data?.[0]?.id || 
                           event?.data?.attributes?.first_order_item?.variant_id || "");
  const buyerEmail = normalizeEmail(order?.user_email || "");
  const buyerName = clean(order?.user_name || "InvoKit Pro Customer", 120);
  const orderRef = clean(String(event?.data?.id || ""), 120);
  const orderNumber = clean(String(order?.order_number || ""), 40);

  if (!buyerEmail) {
    return json({ ok: false, error: "No buyer email in webhook" }, 400, request, env);
  }

  // 4. Map variant → plan
  const annualVariantId  = env.LS_VARIANT_ANNUAL  || "";
  const lifetimeVariantId = env.LS_VARIANT_LIFETIME || "";
  let plan = "lifetime"; // default safe fallback
  if (annualVariantId  && variantId === annualVariantId)  plan = "annual";
  if (lifetimeVariantId && variantId === lifetimeVariantId) plan = "lifetime";

  // 5. Generate key
  const rules = getPlanRules(plan);
  const deviceLimit = rules.deviceLimit;
  const expiresAt = plan === "annual"
    ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    : null;

  const serial = crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
  const key = formatKeyFromSerial(serial);
  const keyHash = await sha256Hex(key + "|" + env.KEY_PEPPER);
  const now = (new Date()).toISOString();
  const notes = `LemonSqueezy order #${orderNumber} | variant ${variantId}`;

  await env.DB.prepare(`
    INSERT INTO licences (
      serial, licence_key_hash, buyer_name, buyer_email, plan,
      order_ref, device_limit, expires_at, status, notes, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `).bind(
    serial, keyHash, buyerName, buyerEmail, plan,
    orderRef, deviceLimit, expiresAt, notes, now, now
  ).run();

  // 6. Send email via Resend
  const emailSent = await sendKeyEmail({
    to: buyerEmail,
    name: buyerName,
    key,
    plan,
    deviceLimit,
    expiresAt,
    resendApiKey: env.RESEND_API_KEY || "",
  });

  return json({
    ok: true,
    generated: { key, serial, plan, buyerEmail, emailSent }
  }, 200, request, env);
}
__name(handleLemonSqueezyWebhook, "handleLemonSqueezyWebhook");

// ── RESEND EMAIL ──────────────────────────────────────────────────────────────
async function sendKeyEmail({ to, name, key, plan, deviceLimit, expiresAt, resendApiKey }) {
  if (!resendApiKey) return false;

  const planLabel  = plan === "annual" ? "Annual" : "Lifetime";
  const expiryLine = expiresAt
    ? `<p style="color:#9d9a94;font-size:13px;margin:0 0 16px;">Your licence expires on <strong style="color:#f0ede8;">${new Date(expiresAt).toLocaleDateString("en-GB", { day:"numeric", month:"long", year:"numeric" })}</strong>. You can renew from the app settings.</p>`
    : `<p style="color:#9d9a94;font-size:13px;margin:0 0 16px;">Your licence never expires — this is a lifetime purchase.</p>`;

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0c0d14;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0c0d14;padding:40px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#111220;border-radius:16px;border:1px solid rgba(255,255,255,0.08);overflow:hidden;max-width:560px;width:100%;">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#1a1c2e,#111220);padding:32px 40px;border-bottom:1px solid rgba(201,168,76,0.2);">
          <p style="margin:0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:0.02em;">InvoKit Pro</p>
          <p style="margin:6px 0 0;font-size:13px;color:#6e6b65;">Your licence is ready to activate</p>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:36px 40px;">
          <p style="color:#f0ede8;font-size:16px;margin:0 0 20px;">Hi ${name.split(" ")[0] || name},</p>
          <p style="color:#c4bdb1;font-size:15px;line-height:1.7;margin:0 0 24px;">Thank you for purchasing <strong style="color:#f0ede8;">InvoKit Pro ${planLabel}</strong>. Your licence key is below — enter it in the app to activate.</p>
          <!-- Key block -->
          <div style="background:#0c0d14;border:1px solid rgba(201,168,76,0.3);border-radius:12px;padding:20px 24px;text-align:center;margin:0 0 24px;">
            <p style="margin:0 0 8px;font-size:11px;color:#6e6b65;letter-spacing:0.12em;text-transform:uppercase;">Your Licence Key</p>
            <p style="margin:0;font-family:'Courier New',monospace;font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:0.08em;">${key}</p>
          </div>
          <!-- Plan info -->
          <p style="color:#9d9a94;font-size:13px;margin:0 0 8px;">Plan: <strong style="color:#f0ede8;">${planLabel}</strong> &nbsp;·&nbsp; Activations: <strong style="color:#f0ede8;">${deviceLimit} device${deviceLimit > 1 ? "s" : ""}</strong></p>
          ${expiryLine}
          <!-- CTA -->
          <table cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td style="background:linear-gradient(135deg,#f0cf7d,#c9a84c,#9a6e1c);border-radius:10px;">
              <a href="https://app.getinvokitpro.com" style="display:block;padding:14px 32px;color:#0c0c0e;font-size:15px;font-weight:700;text-decoration:none;letter-spacing:0.02em;">Activate InvoKit Pro →</a>
            </td></tr>
          </table>
          <!-- Steps -->
          <p style="color:#9d9a94;font-size:13px;line-height:1.8;margin:0 0 8px;"><strong style="color:#f0ede8;">How to activate:</strong></p>
          <ol style="color:#9d9a94;font-size:13px;line-height:1.9;margin:0 0 24px;padding-left:20px;">
            <li>Open <a href="https://app.getinvokitpro.com" style="color:#c9a84c;">app.getinvokitpro.com</a></li>
            <li>Click <strong style="color:#f0ede8;">Install on this device</strong> to add it to your home screen</li>
            <li>Enter your licence key when prompted</li>
            <li>You're done — the app works fully offline from here</li>
          </ol>
          <p style="color:#6e6b65;font-size:12px;line-height:1.7;margin:0;">Keep this email — your key is your access. If you need help, reply to this email or contact <a href="mailto:support@getinvokitpro.com" style="color:#c9a84c;">support@getinvokitpro.com</a></p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,0.06);">
          <p style="margin:0;font-size:11px;color:#3a3835;text-align:center;">© ${new Date().getFullYear()} InvoKit Pro · getinvokitpro.com · Offline-first invoicing</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendApiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "InvoKit Pro <noreply@getinvokitpro.com>",
        to: [to],
        subject: `Your InvoKit Pro ${planLabel} licence key`,
        html
      })
    });
    return res.ok;
  } catch {
    return false;
  }
}
__name(sendKeyEmail, "sendKeyEmail");

// ── VERIFY LEMONSQUEEZY WEBHOOK SIGNATURE ─────────────────────────────────────
async function verifyLsSignature(rawBody, signature, secret) {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
    const expected = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
    return expected === signature;
  } catch {
    return false;
  }
}
__name(verifyLsSignature, "verifyLsSignature");

// ── HELPERS ───────────────────────────────────────────────────────────────────
function clean(value, maxLen = 255) {
  return String(value || "").trim().slice(0, maxLen);
}
__name(clean, "clean");

function normalizeEmail(value) {
  const v = clean(value, 200).toLowerCase();
  if (!v) return "";
  const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  return ok ? v : "";
}
__name(normalizeEmail, "normalizeEmail");

function normalizeExpiry(value) {
  const v = clean(value, 40);
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw httpError("Invalid expiry date", 400);
  return d.toISOString();
}
__name(normalizeExpiry, "normalizeExpiry");

function clampInt(value, min, max) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}
__name(clampInt, "clampInt");

function httpError(message, status = 400) {
  return Object.assign(new Error(message), { status });
}
__name(httpError, "httpError");

function formatKeyFromSerial(serial) {
  const chunks = serial.match(/.{1,4}/g) || [serial];
  return ["IVK", ...chunks].join("-");
}
__name(formatKeyFromSerial, "formatKeyFromSerial");

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}
__name(importHmacKey, "importHmacKey");

async function signActivationToken(payload, secret) {
  const header = { alg: "HS256", typ: "IVK1" };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedBody = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const key = await importHmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlBytes(new Uint8Array(sig))}`;
}
__name(signActivationToken, "signActivationToken");

function base64url(input) {
  return base64urlBytes(new TextEncoder().encode(input));
}
__name(base64url, "base64url");

function base64urlBytes(bytes) {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(base64urlBytes, "base64urlBytes");

async function timingSafeTextEqual(a, b) {
  const enc = new TextEncoder();
  const ah = await crypto.subtle.digest("SHA-256", enc.encode(a));
  const bh = await crypto.subtle.digest("SHA-256", enc.encode(b));
  return crypto.subtle.timingSafeEqual(new Uint8Array(ah), new Uint8Array(bh));
}
__name(timingSafeTextEqual, "timingSafeTextEqual");

export { worker_default as default };
