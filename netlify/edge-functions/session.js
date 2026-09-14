/* ------------------------------------------------------------------
   POST /api/session
   ------------------------------------------------------------------
   The browser sends the Entra access token it just obtained. We verify
   it with Microsoft (Graph /me), confirm the address is @vts.edu, and
   hand back an HttpOnly cookie.

   Why a cookie: a plain <a href="/files/w9.pdf"> download cannot carry
   an Authorization header. The cookie travels automatically, so ordinary
   links keep working while the files stay protected.
   ------------------------------------------------------------------ */

const ALLOWED_DOMAINS = ["vts.edu"];
const SESSION_HOURS = 8;

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + b64url(mac);
}

export default async (request, context) => {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const secret = Netlify.env.get("VTS_SESSION_SECRET");
  if (!secret) {
    return new Response(
      JSON.stringify({ error: "VTS_SESSION_SECRET is not set on this site" }),
      { status: 500, headers: { "content-type": "application/json" } }
    );
  }

  const auth = request.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "No bearer token" }), {
      status: 401, headers: { "content-type": "application/json" },
    });
  }

  // Verify the token by using it. If Microsoft accepts it, it is genuine,
  // unexpired, and issued for this application.
  const me = await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: { authorization: auth },
  });
  if (!me.ok) {
    return new Response(JSON.stringify({ error: "Token rejected by Microsoft" }), {
      status: 401, headers: { "content-type": "application/json" },
    });
  }

  const profile = await me.json();
  const email = String(profile.mail || profile.userPrincipalName || "").toLowerCase();
  const ok = ALLOWED_DOMAINS.some((d) => email.endsWith("@" + d));

  if (!ok) {
    return new Response(JSON.stringify({ error: "Not a vts.edu account" }), {
      status: 403, headers: { "content-type": "application/json" },
    });
  }

  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  const token = await sign({ email, exp }, secret);

  return new Response(JSON.stringify({ ok: true, email }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie":
        `vts_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`,
    },
  });
};

export const config = { path: "/api/session" };
