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

/* Answers, at startup, the question Bug 2 turned on: "will a message
   to someone other than the account owner actually leave this server?"
   Returns human-readable notes for the startup log. Never fatal —
   Resend being briefly unreachable must not stop the site — and never
   includes the key. */
export async function mailPreflight() {
  const notes = [];
  const delivery = mailDelivery();

  if (delivery === "outbox") return notes;
  if (delivery === "log") {
    notes.push("WARNING: no mail provider configured — links go to this log only");
    return notes;
  }

  const domain = fromDomain();
  if (domain === "resend.dev") {
    notes.push(
      "WARNING: MAIL_FROM uses Resend's test sender — Resend delivers it ONLY to the " +
        "address that owns the Resend account. Every other recipient is refused (403). " +
        "Verify a domain in Resend and set MAIL_FROM to an address on it."
    );
    return notes;
  }

  try {
    const response = await fetch("https://api.resend.com/domains", {
      headers: { authorization: "Bearer " + env("RESEND_API_KEY") },
    });
    if (!response.ok) {
      notes.push("WARNING: Resend rejected the API key (HTTP " + response.status + ")");
      return notes;
    }
    const domains = (await response.json()).data || [];
    /* MAIL_FROM may be on the verified domain or a subdomain of it. */
    const match = domains.find((d) => domain === d.name || domain.endsWith("." + d.name));
    if (!match) {
      notes.push(
        "WARNING: " + domain + " is not added in Resend — sending from it will be refused. " +
          "Add it under Domains and publish the DNS records."
      );
    } else if (match.status !== "verified") {
      notes.push(
        "WARNING: " + match.name + " is in Resend but its status is '" + match.status +
          "' — the DNS records are not (yet) published, so sending will be refused."
      );
    } else {
      notes.push("Resend domain " + match.name + " verified — mail can reach any address");
    }
  } catch (err) {
    notes.push("note: could not reach Resend to check the sending domain (" + err.message + ")");
  }
  return notes;
}
