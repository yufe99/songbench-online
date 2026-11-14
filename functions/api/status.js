// Non-secret configuration self-check. Reports which Waffo settings are
// present without ever returning their values.

export async function onRequest(context) {
  if (context.request.method !== "GET") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { "Cache-Control": "no-store" },
    });
  }
  const env = context.env;
  const keys = [
    "WAFFO_MERCHANT_ID",
    "WAFFO_PRIVATE_KEY",
    "WAFFO_STORE_ID",
    "WAFFO_PRODUCT_ID",
  ];
  const configured = {};
  for (const k of keys) configured[k] = Boolean(env[k]);
  return new Response(JSON.stringify({
    ok: keys.every((k) => Boolean(env[k])),
    environment: env.WAFFO_ENVIRONMENT || "test",
    currency: env.WAFFO_CURRENCY || "USD",
    productId: env.WAFFO_PRODUCT_ID || null,
    configured: configured,
    google_sign_in: {
      enabled: true,
      mode: "gis-id-token",
      client_id: "1001028322938-jebcce8lq1u8mu21i12t20ppvqht24jj.apps.googleusercontent.com",
      client_secret_stored: false,
      gate: "paid-download-only",
      endpoints: ["/api/auth/google", "/api/auth/session", "/api/auth/logout"],
    },
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
