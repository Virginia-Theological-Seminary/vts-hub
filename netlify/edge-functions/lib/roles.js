/* ------------------------------------------------------------------
   Roles
   ------------------------------------------------------------------
   The hub does not yet vary by role — every tile is shown to everyone —
   so this is the smallest thing that will carry forward: a fixed
   vocabulary and a safe default.

   These names line up with the Entra security groups planned for the
   portal (Students / Faculty / Staff / Alumni), so when Entra takes
   over, the groups claim maps onto the same words and nothing
   downstream has to change.
   ------------------------------------------------------------------ */

export const ROLES = ["student", "faculty", "staff", "alumni", "admin"];

/* Everyone who signs up through the public form gets this, and there is
   no second option: development-auth.js assigns DEFAULT_ROLE itself and
   never reads a role from the request body. `admin` is therefore not
   reachable from the sign-up form, and no email address grants
   privilege by virtue of its spelling. Elevation is an out-of-band act
   — editing the stored record — and under Entra it becomes group
   membership, which is IT's to decide, not the applicant's. */
export const DEFAULT_ROLE = "student";
