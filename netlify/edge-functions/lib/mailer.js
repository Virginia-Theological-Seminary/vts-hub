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
