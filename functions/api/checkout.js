// Songbench -> Waffo Pancake hosted checkout.
// Cloudflare Pages Function (server-side only).
// A server-verified Google sign-in is REQUIRED. An anonymous request never
// reaches Waffo, so every order can be attributed to a real email address.
// The RSA private key is injected as an encrypted environment variable and
// is NEVER stored in this repository or sent to the browser.

const API_BASE = "https://api.waffo.ai";
const SESSION_PATH = "/v1/actions/checkout/create-session";
const GOOGLE_CLIENT_ID = "1001028322938-jebcce8lq1u8mu21i12t20ppvqht24jj.apps.googleusercontent.com";

// Re-verify the Google ID token held in the HttpOnly cookie against Google's
// own tokeninfo endpoint. Nothing the browser claims is trusted here.
async function verifiedSession(request) {
  const m = /(?:^|;\s*)sb_session=([^;]+)/.exec(request.headers.get("Cookie") || "");
  if (!m) return null;
  try {
    const token = decodeURIComponent(m[1]);
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
    return { email: String(t.email), sub: String(t.sub) };
  } catch (_) {
    return null;
  }
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function b64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(out);
}

// Waffo issues PKCS#8 keys. Accept a bare base64 DER, a normal PEM, or a
// PEM whose line breaks were stored as literal \n in an environment variable.
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

// Waffo API Key auth: sign METHOD \n PATH \n TIMESTAMP \n BASE64(SHA256(BODY))
// with RSA-SHA256 (PKCS#1 v1.5). Timestamp must be within -5min / +1min of
// Waffo server time, so WAFFO_CLOCK_OFFSET_SEC exists for clock-skewed hosts.
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

export async function onRequest(context) {
  const request = context.request;
  const env = context.env;
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  // Do not let other sites use this endpoint as a free checkout proxy.
  const origin = new URL(request.url).origin;
  const sender = request.headers.get("Origin");
  if (sender && sender !== origin) return json({ error: "origin_not_allowed" }, 403);

  for (const k of ["WAFFO_MERCHANT_ID", "WAFFO_PRIVATE_KEY", "WAFFO_PRODUCT_ID"]) {
    if (!env[k]) return json({ error: "payments_not_configured", missing: k }, 503);
  }

  // Hard gate: no verified identity, no checkout session. This is enforced on
  // the server, so bypassing the front end cannot create an anonymous order.
  const session = await verifiedSession(request);
  if (!session) return json({ error: "sign_in_required" }, 401);

  // Product, price, currency and successUrl are decided here and signed with
  // the merchant key. The buyer email comes only from the verified Google
  // session, never from the request body.
  const payload = {
    productId: env.WAFFO_PRODUCT_ID,
    productType: "onetime",
    currency: env.WAFFO_CURRENCY || "USD",
    buyerEmail: session.email,
    successUrl: origin + "/pro/thanks/",
    metadata: {
      site: "songbench",
      plan: "pro-lifetime",
      environment: env.WAFFO_ENVIRONMENT || "prod",
      googleEmail: session.email,
    },
  };

  try {
    const upstream = await signedPost(env, SESSION_PATH, payload);
    if (upstream.status < 200 || upstream.status >= 300) {
      console.error("waffo checkout failed", upstream.status, upstream.text.slice(0, 300));
      return json({ error: "checkout_unavailable" }, 502);
    }
    const parsed = JSON.parse(upstream.text);
    const url = parsed && parsed.data && parsed.data.checkoutUrl;
    if (typeof url !== "string" || url.indexOf("https://") !== 0) {
      console.error("waffo checkout response has no checkoutUrl", upstream.text.slice(0, 300));
      return json({ error: "checkout_unavailable" }, 502);
    }
    return json({ url: url });
  } catch (err) {
    console.error("waffo checkout error", String(err));
    return json({ error: "checkout_unavailable" }, 502);
  }
}
