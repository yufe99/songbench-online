// Songbench - Google sign-in (server side of the GIS ID-token flow).
//
// Flow: the browser obtains a signed Google ID token from Google Identity
// Services and POSTs it here. We verify it with Google's own tokeninfo
// endpoint (server-to-server), so NO Client Secret is needed and none is
// stored anywhere. On success the verified ID token itself becomes an
// HttpOnly session cookie; /api/auth/session re-verifies it on each use.
//
// This endpoint is only ever called when a visitor reaches a paid action.
// Free tools and trials never load the Google script and never set a cookie.

const GOOGLE_CLIENT_ID = "1001028322938-jebcce8lq1u8mu21i12t20ppvqht24jj.apps.googleusercontent.com";
const SESSION_COOKIE = "sb_session";
const FLAG_COOKIE = "sb_signed";

function json(data, status, headers) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  if (headers) for (const kv of headers) h.append(kv[0], kv[1]);
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}

function cookie(name, value, maxAge) {
  return name + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + maxAge;
}

function flagCookie(maxAge) {
  // Non-sensitive, JS-readable marker so the front end knows whether to call
  // /api/auth/session at all. Contains no personal data.
  return FLAG_COOKIE + "=" + (maxAge > 0 ? "1" : "") +
    "; Path=/; Secure; SameSite=Lax; Max-Age=" + maxAge;
}

async function verifyIdToken(idToken) {
  if (!idToken || typeof idToken !== "string" || idToken.length > 4096) return null;
  try {
    const res = await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken),
      { headers: { Accept: "application/json" }, cf: { cacheTtl: 0 } }
    );
    if (!res.ok) return null;
    const t = await res.json();
    if (t.aud !== GOOGLE_CLIENT_ID) return null;               // issued for this site only
    if (t.iss !== "accounts.google.com" && t.iss !== "https://accounts.google.com") return null;
    if (t.email_verified !== true && String(t.email_verified) !== "true") return null;
    const exp = Number(t.exp);
    if (!exp || exp * 1000 <= Date.now() + 5000) return null;   // expired (5s skew guard)
    if (!t.sub || !t.email) return null;
    return { sub: String(t.sub), email: String(t.email), name: String(t.name || ""), exp: exp };
  } catch (_) {
    return null;
  }
}

export async function onRequest(context) {
  const request = context.request;
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  // Same-origin only: no third party may turn this into a token relay.
  const origin = new URL(request.url).origin;
  const sender = request.headers.get("Origin");
  if (sender && sender !== origin) return json({ error: "origin_not_allowed" }, 403);

  let credential;
  try {
    const body = await request.json();
    credential = body && body.credential;
  } catch (_) {
    return json({ error: "invalid_request" }, 400);
  }
  const user = await verifyIdToken(credential);
  if (!user) return json({ error: "invalid_google_token" }, 401);

  const ttl = Math.max(60, Math.min(3600, user.exp - Math.floor(Date.now() / 1000)));
  return json(
    { ok: true, email: user.email, name: user.name, sub: user.sub, expiresIn: ttl },
    200,
    [
      ["Set-Cookie", cookie(SESSION_COOKIE, credential, ttl)],
      ["Set-Cookie", flagCookie(ttl)],
    ]
  );
}
