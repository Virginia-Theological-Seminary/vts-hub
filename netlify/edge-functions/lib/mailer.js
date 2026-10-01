/* ------------------------------------------------------------------
   Mail delivery
   ------------------------------------------------------------------
   Password resets and email verification both have to get a link to
   the user by a channel other than the browser that asked for it —
   otherwise anyone who knew an address could take the account. That
   channel is email, and this module is the only place that knows how
   email leaves the site.

   Three deliveries, chosen in this order:

     "outbox"  the local dev server captures every message and shows it
               at /__dev/outbox, the way Mailpit would. Only
               dev-server.mjs installs this; it is never deployed.

     "email"   Resend (https://resend.com), over its HTTPS API. Needs
               RESEND_API_KEY and MAIL_FROM in the environment, and the
               sending domain verified in Resend (IT adds the DNS
               records Resend shows). Nothing is installed: one fetch().

     "log"     neither of the above is configured, so the message is
               written to the function log for the development team to
               pass on. Crude, but honest and secure: the link never
               goes back to the browser that requested it.

   Swapping Resend for another provider is the body of sendViaResend()
   — every transactional mail API is a POST with a key and a JSON body.
   ------------------------------------------------------------------ */

import { env } from "./runtime.js";

const RESEND_ENDPOINT = "https://api.resend.com/emails";

function resendConfigured() {
  return Boolean(env("RESEND_API_KEY") && env("MAIL_FROM"));
}

/* Which delivery is in effect, so the pages can tell the user where to
   look. */
export function mailDelivery() {
  if (Array.isArray(globalThis.__vtsDevOutbox)) return "outbox";
  if (resendConfigured()) return "email";
  return "log";
}

async function sendViaResend(message) {
  const response = await fetch(RESEND_ENDPOINT, {
    method: "POST",
    headers: {
      authorization: "Bearer " + env("RESEND_API_KEY"),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: env("MAIL_FROM"),
      to: [message.to],
      subject: message.subject,
      text: message.text,
    }),
  });

  if (!response.ok) {
    /* The provider's reason goes to the log; the caller gets a plain
       failure. Never the API key, never the message body. */
    let detail = "";
    try {
      detail = (await response.text()).slice(0, 300);
    } catch {
      /* nothing more to say */
    }
    console.error("[vts-mail] Resend rejected the message:", response.status, detail);
    throw new Error("mail provider rejected the message");
  }
}

async function deliver(message) {
  if (Array.isArray(globalThis.__vtsDevOutbox)) {
    globalThis.__vtsDevOutbox.push({ ...message, sentAt: new Date().toISOString() });
    return;
  }

  if (resendConfigured()) {
    await sendViaResend(message);
    return;
  }

  /* Logged on purpose: this is the delivery channel, not a leak. It is
     the one place a link is ever written down server-side, and it
     stops the moment RESEND_API_KEY and MAIL_FROM are set. */
  console.log(
    "[vts-mail] to=" + message.to + " subject=" + JSON.stringify(message.subject) + "\n" +
      message.text
  );
}

/* Throws if the provider refuses the message. Callers decide whether
   that is fatal: a sign-up cannot proceed without its verification
   mail; a forgot-password request must answer the same way regardless. */
export async function sendMail({ to, subject, text }) {
  await deliver({ to, subject, text });
}

/* ---------------- startup preflight ---------------- */

function fromDomain() {
  const match = /@([A-Za-z0-9.-]+)>?\s*$/.exec(String(env("MAIL_FROM", "")));
  return match ? match[1].toLowerCase() : "";
}

/* Can a message from this server actually reach somebody who is not
   the mail account's own owner?

   This is the question the whole sign-up design turns on. Email
   confirmation is the simplest way to prove an address belongs to the
   person typing it — but only if mail genuinely leaves the building.
   While it does not, requiring confirmation would lock everybody out
   rather than protect anything.

   Returns { usable, reason, detail }. `usable` is deliberately
   pessimistic: anything unproven is treated as "no".

   The answer is cached, because it is asked at startup and then by
   every sign-up. Restarting re-asks it, which is how a newly published
   set of DNS records takes effect. */
let cached = null;

export async function mailCapability({ refresh = false } = {}) {
  if (cached && !refresh) return cached;

  const delivery = mailDelivery();

  if (delivery === "outbox") {
    /* Not usable, and deliberately so. The local outbox captures
       messages; it does not deliver them. Treating it as delivery would
       make the development server behave unlike the server it stands
       in for, which is the one thing a development server must not do.
       To work on the confirmation flow locally, pin the policy with
       VTS_SIGNUP_POLICY=email and read the link in the outbox. */
    cached = {
      usable: false,
      reason: "outbox",
      detail: "captured locally at /__dev/outbox — delivered to nobody",
    };
    return cached;
  }

  if (delivery === "log") {
    cached = {
      usable: false,
      reason: "no-provider",
      detail: "no mail provider configured — links would go to this log only",
    };
    return cached;
  }

  const domain = fromDomain();

  if (domain === "resend.dev") {
    cached = {
      usable: false,
      reason: "test-sender",
      detail:
        "MAIL_FROM uses Resend's test sender, which Resend delivers ONLY to the address " +
        "that owns the Resend account; every other recipient is refused",
    };
    return cached;
  }

  try {
    const response = await fetch("https://api.resend.com/domains", {
      headers: { authorization: "Bearer " + env("RESEND_API_KEY") },
    });
    if (!response.ok) {
      cached = {
        usable: false,
        reason: "key-rejected",
        detail: "Resend rejected the API key (HTTP " + response.status + ")",
      };
      return cached;
    }

    const domains = (await response.json()).data || [];
    /* MAIL_FROM may be on the verified domain or a subdomain of it. */
    const match = domains.find((d) => domain === d.name || domain.endsWith("." + d.name));

    if (!match) {
      cached = {
        usable: false,
        reason: "domain-missing",
        detail:
          domain + " is not added in Resend — sending from it is refused. Add it under " +
          "Domains and publish the DNS records it shows",
      };
    } else if (match.status !== "verified") {
      cached = {
        usable: false,
        reason: "domain-unverified",
        detail:
          match.name + " is in Resend but its status is '" + match.status +
          "' — its DNS records are not published, so sending is refused",
      };
    } else {
      cached = {
        usable: true,
        reason: "verified",
        detail: "Resend domain " + match.name + " verified — mail can reach any address",
      };
    }
  } catch (err) {
    /* Unreachable is not the same as broken, but it is not proof
       either, so it counts as unusable until it answers. */
    cached = {
      usable: false,
      reason: "unreachable",
      detail: "could not reach Resend to check the sending domain (" + err.message + ")",
    };
  }

  return cached;
}

/* Human-readable lines for the startup log. */
export async function mailPreflight() {
  const capability = await mailCapability();
  if (capability.reason === "outbox") return [];
  return [(capability.usable ? "" : "WARNING: ") + capability.detail];
}
