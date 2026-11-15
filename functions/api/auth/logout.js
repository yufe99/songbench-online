// Clears the Google sign-in session and the local Pro entitlement ticket.
// No database is involved - signing out simply removes the browser cookies.
// A later sign-in with the same Google account restores Pro from the Waffo
// order via /api/entitlement.

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Set-Cookie": "sb_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    },
  });
}

export async function onRequest(context) {
  const request = context.request;
  if (request.method !== "POST" && request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }
  const origin = new URL(request.url).origin;
  const sender = request.headers.get("Origin");
  if (sender && sender !== origin) return json({ error: "origin_not_allowed" }, 403);

  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  h.append("Set-Cookie", "sb_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
  h.append("Set-Cookie", "sb_signed=; Path=/; Secure; SameSite=Lax; Max-Age=0");
  h.append("Set-Cookie", "sb_pro=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
  return new Response(JSON.stringify({ ok: true, signedIn: false, pro: false }), { status: 200, headers: h });
}
