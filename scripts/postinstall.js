#!/usr/bin/env node
// Postinstall hook — friendly nudge. Skipped silently in CI.
if (process.env.CI || process.env.NODE_ENV === 'production') process.exit(0);
const lines = [
  "",
  "  +-------------------------------------------------------------------------+",
  "  |  + nhost-security installed                                                       ",
  "  |                                                                          ",
  "  |  Run it now (creds never persisted):                                     ",
  "  |    npx nhost-security --endpoint https://x.hasura.app --secret $ADMIN_SECRET",
  "  |                                                                          ",
  "  |  No-install version (browser):                                           ",
  "  |    https://apify.com/renzomacar/nhost-security-auditor",
  "  |                                                                          ",
  "  |  Want me to run it for you and send back a written report? \9, 24h:    ",
  "  |    https://perufitlife.github.io/supabase-security-skill/                ",
  "  +-------------------------------------------------------------------------+",
  ""
].join("\n");
process.stdout.write(lines);
