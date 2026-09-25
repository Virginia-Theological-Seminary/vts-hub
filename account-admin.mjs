/* ------------------------------------------------------------------
   Account administration
   ------------------------------------------------------------------
   Not published and not served: only site/ is. A command-line tool for
   whoever has access to the server, for the one case the self-service
   flow cannot cover.

       npm run account -- --list
       npm run account -- --invite someone@vts.edu
       npm run account -- --verify someone@vts.edu
       npm run account -- --code   someone@vts.edu
       npm run account -- --delete someone@vts.edu

   WHY THIS EXISTS
   Resetting a password needs the recovery code issued at sign-up, and
   only a hash of that code is stored — so a lost code genuinely cannot
   be recovered or re-sent by anybody, which is what makes it worth
   something as proof of ownership. Somebody locked out that way needs a
   human with server access. Without this tool, that means hand-editing
   database rows, which is worse in every way.

   WHAT --code DOES, AND WHY IT IS SHAPED THIS WAY
   It issues a NEW recovery code and prints it. The administrator passes
   that to the person — in the corridor, over the phone, however they
   normally verify who they are talking to — and the person sets their
   own password at /reset.

   The administrator therefore never chooses, sees or types anyone's
   password. That is deliberate: the fewer people who have ever held a
   password, the better, and it keeps the last step in the account
   holder's hands.

   Confirming identity is the human's job here. The tool cannot do it,
   and pretending otherwise would be the same mistake as letting anyone
   reset an account by knowing its address.

   Retires with Microsoft Entra, where forgotten passwords are
   Microsoft's business.
   ------------------------------------------------------------------ */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

/* Same .env handling as the migration runner, so both commands behave
   the same way on the server. */
async function loadEnv() {
  try {
    const raw = await readFile(path.join(root, ".env"), "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (!match) continue;
      const value = match[2].trim().replace(/^["']|["']$/g, "");
      if (!(match[1] in process.env)) process.env[match[1]] = value;
    }
  } catch {
    /* no .env — the environment must carry the values */
  }
}

function usage() {
  console.log(`
  VTS Hub — account administration

    npm run account -- --invite someone@vts.edu
        Issue an invitation so that address can create an account.
        Without one, sign-up is refused: the @vts.edu rule only checks
        the shape of an address, not that the person owns it.

    npm run account -- --list
        Every account: address, role, whether it can sign in, and when
        it was created.

    npm run account -- --verify someone@vts.edu
        Confirm their address by hand, for somebody who signed up while
        confirmation was required and never received the link. Only do
        this when you know the address is theirs.

    npm run account -- --code someone@vts.edu
        Issue a NEW recovery code and print it. The previous code stops
        working. Give the code to the account holder; they set their own
        password at /reset. You never handle their password.

    npm run account -- --delete someone@vts.edu
        Remove the account. They can sign up again with the same
        address. Cannot be undone.

  Confirm who you are talking to before issuing a code. This tool
  cannot check that, and a code handed to the wrong person is a
  handed-over account.

  Connection: VTS_AUTH_STORE and VTS_DB_HOST / PORT / NAME / USER /
  PASSWORD, from the environment or a .env file in this directory.
`);
}

function parseArgs(argv) {
  const opts = {};
  const next = () => argv.shift();
  while (argv.length) {
    const arg = next();
    switch (arg) {
      case "--list": opts.list = true; break;
      case "--invite": opts.invite = next(); break;
      case "--verify": opts.verify = next(); break;
      case "--code": opts.code = next(); break;
      case "--delete": opts.remove = next(); break;
      case "--yes": case "-y": opts.yes = true; break;
      case "--help": case "-h": opts.help = true; break;
      default:
        if (arg.startsWith("--")) {
          console.error("  Unknown option: " + arg);
          opts.help = true;
        }
    }
  }
  /* npm passes `npm run account -- --code x` through intact, but
     `npm run account --code=x` arrives as an npm_config_ variable. */
  if (!opts.invite && process.env.npm_config_invite) opts.invite = process.env.npm_config_invite;
  if (!opts.verify && process.env.npm_config_verify) opts.verify = process.env.npm_config_verify;
  if (!opts.code && process.env.npm_config_code) opts.code = process.env.npm_config_code;
  if (!opts.remove && process.env.npm_config_delete) opts.remove = process.env.npm_config_delete;
  if (process.env.npm_config_list) opts.list = true;
  return opts;
}

const load = (rel) => import(pathToFileURL(path.join(root, rel)).href);

async function main() {
  await loadEnv();
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || (!opts.list && !opts.code && !opts.remove && !opts.invite && !opts.verify)) {
    return usage();
  }

  const store = await load("netlify/edge-functions/lib/user-store.js");
  const { normalizeEmail, isVtsEmail } = await load("netlify/edge-functions/lib/validation.js");

  let kind;
  try {
    kind = await store.ensureStore();
  } catch (err) {
    console.error("\n  Cannot reach the account store: " + err.message + "\n");
    process.exit(1);
  }
  if (kind === "memory") {
    console.error(
      "\n  The account store is in memory, so this tool would be editing a copy" +
        "\n  that disappears when it exits. Set VTS_AUTH_STORE=mariadb and the" +
        "\n  VTS_DB_* variables to the values the server uses.\n"
    );
    process.exit(1);
  }

  if (opts.list) {
    const rows = await store.listUsers();
    console.log("\n  " + rows.length + " account(s) in " + kind + "\n");
    for (const user of rows) {
      /* An account that owes a confirmation cannot sign in, which is
         the first thing anyone runs this to find out. */
      const blocked = user.verificationPending && !user.emailVerifiedAt;
      console.log(
        "   " + String(user.email).padEnd(34) +
          String(user.role || "").padEnd(10) +
          (blocked ? "unconfirmed " : "            ") +
          String(user.createdAt || "").slice(0, 10)
      );
    }
    console.log("");
    return;
  }

  const target = normalizeEmail(opts.invite || opts.verify || opts.code || opts.remove);
  if (!isVtsEmail(target)) {
    console.error("\n  Not a VTS address: " + JSON.stringify(target) + "\n");
    process.exitCode = 1;
    return;
  }

  if (opts.invite) {
    if (await store.findUserByEmail(target)) {
      console.error(
        "\n  " + target + " already has an account. Use --code to issue them a" +
          "\n  recovery code instead.\n"
      );
      process.exitCode = 1;
      return;
    }

    /* A code issued while sign-up is not asking for one would do
       nothing at all, and the administrator would have no way to tell.
       Resolved the same way the server resolves it, so the two agree. */
    const { signupPolicy } = await load(
      "netlify/edge-functions/lib/providers/development-auth.js"
    );
    const policy = await signupPolicy();
    if (!policy.invitation) {
      console.error(
        "\n  Sign-up is not asking for invitations at the moment, so a code" +
          "\n  issued now would do nothing. " + target + " can sign up at /signup" +
          "\n  and confirm the address from the link sent to it." +
          "\n\n  (" + policy.source + ": " + policy.reason + ")\n"
      );
      process.exitCode = 1;
      return;
    }

    const { generateInviteCode, hashInviteCode } = await load(
      "netlify/edge-functions/lib/invite.js"
    );
    const invite = generateInviteCode();
    await store.putInvite(target, {
      codeHash: await hashInviteCode(invite),
      issuedAt: new Date().toISOString(),
    });

    console.log(`
  Invitation for ${target}

      ${invite}

  Give this to them, having confirmed who they are. It works only for
  that address and only once. Any earlier invitation for them has been
  replaced.
`);
    return;
  }

  const user = await store.findUserByEmail(target);
  if (!user) {
    console.error("\n  No account for " + target + "\n");
    process.exitCode = 1;
    return;
  }

  if (opts.verify) {
    if (user.emailVerifiedAt && !user.verificationPending) {
      console.log("\n  " + target + " is already confirmed. Nothing to do.\n");
      return;
    }
    await store.updateUser(target, {
      emailVerifiedAt: Date.now(),
      verificationPending: false,
    });
    console.log(
      "\n  Confirmed " + target + " by hand. They can sign in with the password" +
        "\n  they chose at sign-up.\n"
    );
    return;
  }

  if (opts.remove) {
    await store.deleteUser(target);
    console.log("\n  Removed " + target + ". They can sign up again with the same address.\n");
    return;
  }

  const { generateRecoveryCode, hashRecoveryCode } = await load(
    "netlify/edge-functions/lib/recovery-code.js"
  );
  const code = generateRecoveryCode();
  await store.updateUser(target, { recoveryCodeHash: await hashRecoveryCode(code) });

  console.log(`
  New recovery code for ${target}

      ${code}

  Their previous code no longer works. Give this to them, having
  confirmed who they are, and ask them to go to /reset and set a new
  password with it. It can be used once; using it issues them another.
`);
}

main()
  .catch((err) => {
    console.error("\n  " + (err && err.message ? err.message : String(err)) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    /* Without this the database pool holds the process open and the
       command looks like it has hung. */
    try {
      const store = await load("netlify/edge-functions/lib/user-store.js");
      await store.closeStore();
    } catch {
      /* nothing to close */
    }
  });
