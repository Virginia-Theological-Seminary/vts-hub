/* ------------------------------------------------------------------
   VTS Hub — content
   ------------------------------------------------------------------
   Every tile on the site comes from this file. To add, remove or
   re-point a tile, edit here only — no other file needs touching.

   Each item:
     title   — label shown on the tile
     icon    — key into the icon set in icons.js
     kind    — "doc"      a document we host under /files/ (protected)
               "link"     a page on this site or vts.edu
               "external" a third-party system with its own log-in
     href    — destination; null means "not supplied yet"
     note    — small grey line under the title (optional)
     meta    — file type, shown on document tiles (optional)
     status  — "ready"   href is live
               "pending" still to be supplied
   ------------------------------------------------------------------ */

window.VTS_SECTIONS = [
  {
    id: "worship",
    title: "Worship & Chapel",
    blurb:
      "Internal-facing worship resources for faculty and staff. Public-facing " +
      "items (worship schedule, preacher links, SoundCloud recordings, faculty " +
      "photographs) stay on vts.edu and remain with Communications.",
    icon: "chapel",
    items: [
      {
        title: "Ministry Scheduler Pro",
        icon: "calendar",
        kind: "external",
        href: "https://secure.rotundasoftware.com/30/kiosk/VTS/",
        status: "ready",
        note: "Chapel serving rota — separate log-in",
      },
      {
        title: "Worship Planning Team Handbook",
        icon: "book",
        kind: "doc",
        href: "files/worship/worship-planning-team-handbook-2025-2026.docx",
        status: "ready",
        note: "2025–2026 edition",
        meta: "Word",
      },
      {
        title: "Daily Intercessions",
        icon: "prayer",
        kind: "doc",
        href: "files/worship/daily-intercessions.docx",
        status: "ready",
        note: "Current form of the daily prayers",
        meta: "Word",
      },
      {
        title: "Lectionary",
        icon: "index",
        kind: "doc",
        href: "files/worship/lectionary-spring-2026.pdf",
        status: "ready",
        note: "Spring 2026",
        meta: "PDF",
      },
      {
        title: "Psalms Reference",
        icon: "music",
        kind: "doc",
        href: "files/worship/psalms-elw-to-bcp.pdf",
        status: "ready",
        note: "ELW-to-BCP psalm concordance",
        meta: "PDF",
      },
      {
        title: "Scripture Reference Index",
        icon: "index",
        kind: "doc",
        href: "files/worship/levas-ii-scriptural-reference-index.pdf",
        status: "ready",
        note: "Lift Every Voice and Sing II",
        meta: "PDF",
      },
      {
        title: "Prayer Requests",
        icon: "prayer",
        kind: "link",
        href: null,
        status: "pending",
        note: "Submission link still needed",
      },
      {
        title: "Links for Worship",
        icon: "link",
        kind: "link",
        href: null,
        status: "pending",
      },
      {
        title: "Policy Documents",
        icon: "policy",
        kind: "doc",
        href: null,
        status: "pending",
        note: "Chapel and worship policies",
      },
      {
        title: "Customaries",
        icon: "scroll",
        kind: "doc",
        href: null,
        status: "pending",
      },
    ],
  },

  {
    id: "finance",
    title: "Finance Office",
    blurb: "Forms and policies for expenses, travel, payments and tax.",
    icon: "finance",
    items: [
      {
        title: "Expense Report",
        icon: "receipt",
        kind: "external",
        href: "https://www.cognitoforms.com/VTS5/VirginiaTheologicalSeminaryExpenseReport",
        status: "ready",
        note: "Submit online via Cognito Forms",
      },
      {
        title: "Travel Policy",
        icon: "policy",
        kind: "doc",
        href: "files/finance/seminary-travel-policy-fy2022-23.pdf",
        status: "ready",
        note: "FY2022–23",
        meta: "PDF",
      },
      {
        title: "Vendor ACH / EFT Authorization",
        icon: "bank",
        kind: "doc",
        href: "files/finance/vendor-ach-eft-authorization.pdf",
        status: "ready",
        meta: "PDF",
      },
      {
        title: "W-9",
        icon: "form",
        kind: "doc",
        href: "files/finance/w-9-editable.pdf",
        status: "ready",
        note: "Fillable form",
        meta: "PDF",
      },
      {
        title: "Sales Tax Exemption Certificate",
        icon: "tax",
        kind: "doc",
        href: "files/finance/sales-tax-exemption.pdf",
        status: "ready",
        note: "Valid to 14 March 2028",
        meta: "PDF",
      },
      {
        title: "Check Authorization Form",
        icon: "check",
        kind: "doc",
        href: null,
        status: "pending",
      },
      {
        title: "Travel Expense Report",
        icon: "plane",
        kind: "doc",
        href: null,
        status: "pending",
      },
    ],
  },

  {
    id: "hr",
    title: "Human Resources",
    blurb: "Employee benefits, handbooks and staff programmes.",
    icon: "people",
    items: [
      {
        title: "Employee Benefits Manual",
        icon: "medical",
        kind: "doc",
        href: "files/hr/employee-benefits-manual-fy2022-23.pdf",
        status: "ready",
        note: "Medical, dental, EAP, life, pension and leave — FY2022–23",
        meta: "PDF",
      },
      {
        title: "Staff Handbook",
        icon: "book",
        kind: "doc",
        href: "files/hr/staff-handbook-fy2022-23.pdf",
        status: "ready",
        note: "FY2022–23",
        meta: "PDF",
      },
      {
        title: "Faculty Handbook",
        icon: "book",
        kind: "doc",
        href: null,
        status: "pending",
      },
      {
        title: "Shared Interest Program",
        icon: "share",
        kind: "doc",
        href: null,
        status: "pending",
        note: "Not covered by the Benefits Manual",
      },
    ],
  },

  {
    id: "systems",
    title: "Systems & Log-ins",
    blurb:
      "Third-party systems that keep their own separate credentials. " +
      "Signing in here does not sign you in to these.",
    icon: "key",
    items: [
      {
        title: "Maintenance Requests",
        icon: "wrench",
        kind: "external",
        href: "https://v1-identity.dudesolutions.io/app/login/username",
        status: "ready",
        note: "Dude Solutions — facilities and work orders",
      },
      {
        title: "Microsoft 365",
        icon: "microsoft",
        kind: "external",
        href: "https://www.office.com/",
        status: "ready",
        note: "Email, Teams, OneDrive and SharePoint",
      },
      {
        title: "Paycom",
        icon: "paycom",
        kind: "external",
        href: null,
        status: "pending",
        note: "Payroll, timesheets and benefits enrolment",
      },
      {
        title: "Brightspace",
        icon: "brightspace",
        kind: "external",
        href: null,
        status: "pending",
        note: "Learning management system",
      },
      {
        title: "Populi",
        icon: "populi",
        kind: "external",
        href: null,
        status: "pending",
        note: "Student information system",
      },
      {
        title: "Website Editor",
        icon: "edit",
        kind: "external",
        href: null,
        status: "pending",
        note: "vts.edu content editing",
      },
    ],
  },
];

/* Items deliberately NOT brought across from the hub, per the brief.
   Kept here so the decision is recorded rather than looking like an omission. */
window.VTS_EXCLUDED = [
  "Faculty photographs — already on vts.edu",
  "Preacher links — already on vts.edu",
  "Worship schedule — already on vts.edu",
  "SoundCloud recordings — managed by Communications",
];
