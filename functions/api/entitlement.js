// Songbench Pro entitlement verification (Cloudflare Pages Function).
//
// Stateless, no KV and no database. A Pro licence is derived from the order
// that actually exists in Waffo, verified server-side on every activation:
//
//   Google ID token (HttpOnly cookie) -> verified with Google tokeninfo
//   -> GraphQL /v1/graphql onetimeOrders (completed, no refund, right product,
//      buyer email or our metadata.googleEmail matches the signed-in address)
//   -> signed HMAC ticket in an HttpOnly cookie (sb_pro)
//
// The ticket is a short-lived cache. It is re-checked against Waffo at least
// once a day, so a refund or chargeback that sets hasRefund=true revokes Pro
// without any server-side storage. The HMAC key is derived from the Waffo
// private key already present in the environment - no new secret is needed.
// The private key itself is never sent to the browser and never logged.

const API_BASE = "https://api.waffo.ai";
const GRAPHQL_PATH = "/v1/graphql";
const GOOGLE_CLIENT_ID = "1001028322938-jebcce8lq1u8mu21i12t20ppvqht24jj.apps.googleusercontent.com";
const SESSION_COOKIE = "sb_session";
const PRO_COOKIE = "sb_pro";
const TICKET_TTL_SEC = 365 * 24 * 3600;
const RECHECK_AFTER_SEC = 24 * 3600;
const REF_RE = /^SB1-[A-Za-z0-9_-]{10,90}$/;

// Two aliases of the same query: one finds a purchase by the buyer's email
// (works on a new device after signing in again), the other by our own
// orderMerchantExternalId (works even if the buyer edited the checkout email).
const ORDER_QUERY = [
  'query($storeId:String!,$email:String!,$productId:String!,$ref:String!){',
  ' byEmail:onetimeOrders(storeId:$storeId,filter:{buyerEmail:{eq:$email},status:{eq:"completed"},productId:{eq:$productId},hasRefund:{eq:false}},limit:20){id buyerEmail status orderMerchantExternalId metadata createdAt testMode}',
  ' byRef:onetimeOrders(storeId:$storeId,filter:{orderMerchantExternalId:{eq:$ref},status:{eq:"completed"},productId:{eq:$productId},hasRefund:{eq:false}},limit:5){id buyerEmail status orderMerchantExternalId metadata createdAt testMode}',
  '}',
].join("\n");

function json(data, status, headers) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Cookie",
  });
  if (headers) for (const kv of headers) h.append(kv[0], kv[1]);
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}

function b64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(out);
}
function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
}

function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const m = new RegExp("(?:^|;\\s*)" + name + "=([^;]+)").exec(raw);
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; }
}
function proCookie(value) {
  return PRO_COOKIE + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + TICKET_TTL_SEC;
}
function clearProCookie() {
  return PRO_COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0";
}

// No Client Secret is used. Google's own tokeninfo endpoint re-verifies the
// ID token held in the cookie, so nothing the browser claims is trusted.
async function verifiedSession(request) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  try {
    const res = await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(token),
      { headers: { Accept: "application/json" }, cf: { cacheTtl: 0 } }
    );
    if (!res.ok) return null;
    const t = await res.json();
    if (t.aud !== GOOGLE_CLIENT_ID) return null;
    if (t.iss !== "accounts.google.com" && t.iss !== "https://accounts.google.com") return null;
    if (t.email_verified !== true && String(t.email_verified) !== "true") return null;
    if (!Number(t.exp) || Number(t.exp) * 1000 <= Date.now() + 5000) return null;
    if (!t.sub || typeof t.email !== "string" || t.email.length > 180) return null;
    return { email: String(t.email).toLowerCase(), sub: String(t.sub) };
  } catch (_) {
    return null;
  }
}

// Waffo issues PKCS#8 keys. Accept a bare base64 DER, a normal PEM, or a PEM
// whose line breaks were stored as literal \n in an environment variable.
function privateKeyDer(raw) {
  if (!raw) throw new Error("WAFFO_PRIVATE_KEY is missing");
  const text = String(raw).replace(/\\n/g, "\n").trim();
  if (text.includes("BEGIN RSA PRIVATE KEY")) {
    throw new Error("PKCS#1 key is not supported here - use the PKCS#8 PEM");
  }
  const body = text
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  if (!body) throw new Error("private key is empty");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

// Derive a stable HMAC key from the merchant private key. Only the SHA-256
// digest is used as key material; the RSA key never leaves this isolate.
async function entitlementKey(env) {
  const der = privateKeyDer(env.WAFFO_PRIVATE_KEY);
  const tag = new TextEncoder().encode("songbench.pro-entitlement.v1");
  const material = new Uint8Array(der.length + tag.length);
  material.set(der, 0);
  material.set(tag, der.length);
  const seed = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  return crypto.subtle.importKey("raw", seed, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signTicket(key, payload) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body))
  );
  return body + "." + b64url(sig);
}
async function readTicket(key, raw) {
  const parts = String(raw || "").split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  let sig;
  try { sig = fromB64url(parts[1]); } catch (_) { return null; }
  let ok = false;
  try {
    ok = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(parts[0]));
  } catch (_) { return null; }
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
  } catch (_) { return null; }
}

// Waffo API Key auth: sign METHOD \n PATH \n TIMESTAMP \n BASE64(SHA256(BODY))
// with RSA-SHA256 (PKCS#1 v1.5). Timestamp window: -5min / +1min.
async function signedPost(env, path, payload) {
  const body = JSON.stringify(payload);
  const offset = Number(env.WAFFO_CLOCK_OFFSET_SEC || 0);
  const ts = String(Math.floor(Date.now() / 1000) + offset);
  const enc = new TextEncoder();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(body)));
  const canonical = "POST\n" + path + "\n" + ts + "\n" + b64(digest);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    privateKeyDer(env.WAFFO_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(canonical))
  );
  const res = await fetch(API_BASE + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Merchant-Id": env.WAFFO_MERCHANT_ID,
      "X-Timestamp": ts,
      "X-Signature": b64(signature),
    },
    body,
  });
  return { status: res.status, text: await res.text() };
}

function belongsTo(order, email) {
  if (String(order.buyerEmail || "").toLowerCase() === email) return true;
  // If the buyer edited the email on Waffo's checkout form, our server-side
  // metadata still carries the verified Google address used to place it.
  let meta = {};
  try { meta = JSON.parse(order.metadata || "{}"); } catch (_) { return false; }
  return String(meta.googleEmail || "").toLowerCase() === email;
}

async function lookupOrder(env, email, ref) {
  const payload = {
    query: ORDER_QUERY,
    variables: {
      storeId: env.WAFFO_STORE_ID,
      email: email,
      productId: env.WAFFO_PRODUCT_ID,
      ref: ref || "",
    },
  };
  const upstream = await signedPost(env, GRAPHQL_PATH, payload);
  if (upstream.status < 200 || upstream.status >= 300) {
    throw new Error("waffo_http_" + upstream.status);
  }
  let parsed;
  try { parsed = JSON.parse(upstream.text); } catch (_) { throw new Error("waffo_bad_json"); }
  if (!parsed || (parsed.errors && parsed.errors.length)) {
    throw new Error("waffo_graphql_error");
  }
  const data = parsed.data || {};
  const rows = [].concat(data.byEmail || [], data.byRef || []);
  let best = null;
  let bestTime = -1;
  for (const o of rows) {
    if (!o || o.testMode !== false) continue;   // prod key only; still reject test orders
    if (!belongsTo(o, email)) continue;
    const t = Date.parse(o.createdAt || "") || 0;
    if (t > bestTime) { best = o; bestTime = t; }
  }
  return best;
}

export async function onRequest(context) {
  const request = context.request;
  const env = context.env;
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);

  const url = new URL(request.url);
  const sender = request.headers.get("Origin");
  if (sender && sender !== url.origin) return json({ error: "origin_not_allowed" }, 403);

  const session = await verifiedSession(request);
  if (!session) {
    return json({ pro: false, signedIn: false, reason: "sign_in_required" }, 200,
      [["Set-Cookie", clearProCookie()]]);
  }

  const refresh = url.searchParams.get("refresh") === "1";
  const rawRef = (url.searchParams.get("ref") || "").trim();
  const ref = REF_RE.test(rawRef) ? rawRef : "";
  const now = Math.floor(Date.now() / 1000);

  let key;
  try { key = await entitlementKey(env); }
  catch (_) { return json({ pro: false, signedIn: true, reason: "payments_not_configured" }, 503); }

  const ticket = await readTicket(key, readCookie(request, PRO_COOKIE));
  const ticketUsable = ticket && ticket.v === 1 &&
    String(ticket.e || "").toLowerCase() === session.email && Number(ticket.x) > now;

  // Fast path: a fresh ticket avoids an upstream call on every Pro action.
  // It is deliberately short (24h) so refunds still take effect.
  if (!refresh && ticketUsable && Number(ticket.i) + RECHECK_AFTER_SEC > now) {
    return json({
      pro: true, signedIn: true, source: "ticket", email: session.email,
      orderId: ticket.o, checkedAt: now, expiresAt: Number(ticket.x),
    });
  }

  for (const k of ["WAFFO_MERCHANT_ID", "WAFFO_PRIVATE_KEY", "WAFFO_STORE_ID", "WAFFO_PRODUCT_ID"]) {
    if (!env[k]) return json({ pro: false, signedIn: true, reason: "payments_not_configured", missing: k }, 503);
  }

  let order = null;
  let upstreamError = null;
  try { order = await lookupOrder(env, session.email, ref); }
  catch (err) { upstreamError = String(err).slice(0, 100); }

  if (!order) {
    if (upstreamError) {
      // Never lock out a paying customer because Waffo is briefly unreachable.
      if (ticketUsable) {
        return json({
          pro: true, signedIn: true, source: "ticket_offline", email: session.email,
          orderId: ticket.o, expiresAt: Number(ticket.x),
        });
      }
      console.warn("Songbench: entitlement lookup failed", upstreamError);
      return json({ pro: false, signedIn: true, reason: "verification_unavailable", detail: upstreamError }, 503);
    }
    return json({ pro: false, signedIn: true, reason: "no_purchase", email: session.email }, 200,
      [["Set-Cookie", clearProCookie()]]);
  }

  const payload = {
    v: 1,
    e: session.email,
    o: String(order.id),
    i: now,
    x: now + TICKET_TTL_SEC,
  };
  const token = await signTicket(key, payload);
  return json({
    pro: true, signedIn: true, source: "order", email: session.email,
    orderId: payload.o, checkedAt: now, expiresAt: payload.x,
  }, 200, [["Set-Cookie", proCookie(token)]]);
}
