// Returns the current Google sign-in state. Stateless: the HttpOnly cookie
// holds Google's own signed ID token and is re-verified with Google here.
// Free visitors have no cookie, so this returns immediately without any
// upstream request and without setting anything.

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

function clearCookies() {
  return [
    ["Set-Cookie", SESSION_COOKIE + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"],
    ["Set-Cookie", FLAG_COOKIE + "=; Path=/; Secure; SameSite=Lax; Max-Age=0"],
  ];
}

function readToken(request) {
  const raw = request.headers.get("Cookie") || "";
  const m = /(?:^|;\s*)sb_session=([^;]+)/.exec(raw);
  return m ? decodeURIComponent(m[1]) : null;
}

async function verify(idToken) {
  try {
    const res = await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken),
      { headers: { Accept: "application/json" }, cf: { cacheTtl: 0 } }
    );
    if (!res.ok) return null;
    const t = await res.json();
    if (t.aud !== GOOGLE_CLIENT_ID) return null;
    if (t.iss !== "accounts.google.com" && t.iss !== "https://accounts.google.com") return null;
    if (t.email_verified !== true && String(t.email_verified) !== "true") return null;
    if (!Number(t.exp) || Number(t.exp) * 1000 <= Date.now()) return null;
    if (!t.sub || !t.email) return null;
    return { sub: String(t.sub), email: String(t.email), name: String(t.name || ""), exp: Number(t.exp) };
  } catch (_) {
    return null;
  }
}

export async function onRequest(context) {
  const request = context.request;
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
  const token = readToken(request);
  if (!token) return json({ signedIn: false }, 200);
  const user = await verify(token);
  if (!user) return json({ signedIn: false, expired: true }, 200, clearCookies());
  return json({ signedIn: true, email: user.email, name: user.name, sub: user.sub, exp: user.exp }, 200);
}
