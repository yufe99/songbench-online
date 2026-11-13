// Waffo Pancake webhook receiver for Songbench.
// Verifies the RSA-SHA256 signature before trusting any event. Public keys
// are the official ones embedded in @waffo/pancake-ts (test + prod).

const TEST_PUBLIC_KEY = [
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnmRY6yMMA3lVqmAU6ZG",
  "b1sjL/+r/z6E+ZjkXaDAKiqOhk9rpazni0bNsGXwmftTPk9jy2wn+j6JHODD/WH/",
  "SCnSfvKkLIjy4Hk7BuCgB174C0ydan7J+KgXLkOwgCAxxB68t2tezldwo74ZpXgn",
  "F49opzMvQ9prEwIAWOE+kV9iK6gx/AckSMtHIHpUesoPDkldpmFHlB2qpf1vsFTZ",
  "5kD6DmGl+2GIVK01aChy2lk8pLv0yUMu18v44sLkO5M44TkGPJD9qG09wrvVG2wp",
  "OTVCn1n5pP8P+HRLcgzbUB3OlZVfdFurn6EZwtyL4ZD9kdkQ4EZE/9inKcp3c1h4",
  "xwIDAQAB",
].join("");

const PROD_PUBLIC_KEY = [
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+xApdTIb4ua+DgZKQ54",
  "iBsD82ybyhGCLRETONW4Jgbb3A8DUM1LqBk6r/CmTOCHqLalTQHNigvP3R5zkDNX",
  "iRJz6gA4MJ/+8K0+mnEE2RISQzN+Qu65TNd6svb+INm/kMaftY4uIXr6y6kchtTJ",
  "dwnQhcKdAL2v7h7IFnkVelQsKxDdb2PqX8xX/qwd01iXvMcpCCaXovUwZsxH2QN5",
  "ZKBTseJivbhUeyJCco4fdUyxOMHe2ybCVhyvim2uxAl1nkvL5L8RCWMCAV55LLo0",
  "9OhmLahz/DYNu13YLVP6dvIT09ZFBYU6Owj1NxdinTynlJCFS9VYwBgmftosSE1U",
  "dwIDAQAB",
].join("");

const PAST_WINDOW_MS = 45 * 60 * 1000;
const FUTURE_WINDOW_MS = 60 * 1000;
const seen = new Set();

function pemToDer(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function parseHeader(header) {
  const out = { t: "", v1: "" };
  for (const pair of header.split(",")) {
    const i = pair.indexOf("=");
    if (i < 0) continue;
    const k = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (k === "t" || k === "v1") out[k] = v;
  }
  return out;
}

async function verifyWith(signedInput, signatureB64, publicKeyB64) {
  const key = await crypto.subtle.importKey(
    "spki",
    pemToDer(publicKeyB64),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sig = pemToDer(signatureB64);
  return crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    sig,
    new TextEncoder().encode(signedInput)
  );
}

async function verifyEvent(rawBody, header) {
  if (!header) throw new Error("missing X-Waffo-Signature");
  const parts = parseHeader(header);
  if (!parts.t || !parts.v1) throw new Error("malformed signature header");

  const timestampMs = Number(parts.t);
  if (!Number.isFinite(timestampMs)) throw new Error("invalid timestamp");
  const age = Date.now() - timestampMs;
  if (age > PAST_WINDOW_MS || age < -FUTURE_WINDOW_MS) {
    throw new Error("webhook timestamp outside tolerance window");
  }

  // Signature input is `${t}.${rawBody}` with t in milliseconds.
  const signedInput = parts.t + "." + rawBody;
  if (await verifyWith(signedInput, parts.v1, TEST_PUBLIC_KEY)) return "test";
  if (await verifyWith(signedInput, parts.v1, PROD_PUBLIC_KEY)) return "prod";
  throw new Error("invalid webhook signature");
}

function reply(text, status) {
  return new Response(text, {
    status: status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function onRequest(context) {
  const request = context.request;
  if (request.method !== "POST") return reply("Method Not Allowed", 405);

  const raw = await request.text();
  let environment;
  try {
    environment = await verifyEvent(raw, request.headers.get("x-waffo-signature"));
  } catch (err) {
    console.warn("rejected webhook:", String(err));
    return reply("Invalid signature", 401);
  }

  let event;
  try {
    event = JSON.parse(raw);
  } catch (_) {
    return reply("Invalid payload", 400);
  }

  const eventId = event.id || (event.data && event.data.id) || null;
  const eventType = event.eventType || event.event || "unknown";
  if (eventId) {
    if (seen.has(eventId)) return reply("OK (duplicate)", 200);
    seen.add(eventId);
    // Bound memory in long-lived isolates.
    if (seen.size > 500) seen.delete(seen.values().next().value);
  }

  // No user audio or credentials are logged. Order state lives in Waffo;
  // a KV-backed entitlement store is the next step before gating features.
  console.log(JSON.stringify({
    source: "waffo",
    environment: environment,
    eventType: eventType,
    eventId: eventId,
    orderId: (event.data && event.data.orderId) || null,
    status: (event.data && event.data.status) || null,
  }));

  return reply("OK", 200);
}
