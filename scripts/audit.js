#!/usr/bin/env node
// Nhost (Hasura) Security Auditor — pure Node.js, no deps.
//
// Usage:
//   HASURA_ENDPOINT=https://my.hasura.app HASURA_ADMIN_SECRET=xxx node audit.js
//   node audit.js --endpoint URL --secret SECRET [--no-probe] [--html report.html]
//
// Endpoint = your Hasura URL (Nhost: https://<subdomain>.hasura.<region>.nhost.run)

import { writeFileSync } from "node:fs";

const UA = "nhost-security/0.1";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  anonymous_role_table_select: {
    severity: "critical",
    title: "Table has SELECT permission for `anonymous` role with wide filter",
    explain: "Hasura `anonymous` role applies when no auth header is sent. SELECT permissions with empty/{}/permissive filter let any unauthenticated request read every row in this table.",
  },
  anonymous_role_table_insert_or_mutation: {
    severity: "critical",
    title: "Table has INSERT/UPDATE/DELETE for `anonymous` role",
    explain: "Mutation permissions for the anonymous role let unauthenticated requests modify or destroy rows. Almost never intentional outside specific writeable endpoints (signup forms, etc).",
  },
  user_role_no_row_filter: {
    severity: "high",
    title: "User role has SELECT/UPDATE/DELETE without row-level filter",
    explain: "A `user` role permission with empty filter `{}` lets every signed-up user touch every row of the table, ignoring ownership. Tighten with `{ user_id: { _eq: \"X-Hasura-User-Id\" } }`.",
  },
  permission_select_all_columns: {
    severity: "medium",
    title: "Table SELECT permission exposes all columns (no column restriction)",
    explain: "When `columns: '*'` (or no allowlist) is used, the role can read every column including potentially sensitive ones (password_hash, internal_notes, etc).",
  },
  graphql_introspection_public: {
    severity: "medium",
    title: "GraphQL introspection enabled for anonymous role",
    explain: "Anonymous schema introspection lets attackers map your entire data model + permission structure without auth. Disable for `anonymous` in production.",
  },
};

async function hasura(endpoint, secret, body) {
  const r = await fetch(`${endpoint}/v1/metadata`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Hasura-Admin-Secret": secret,
      "User-Agent": UA,
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Metadata API ${r.status}: ${await r.text().then(t => t.slice(0, 200))}`);
  return r.json();
}

async function probeAnonGraphql(endpoint, tableName) {
  // Anonymous GET via GraphQL — try a SELECT with limit 1
  const query = `query { ${tableName}(limit: 1) { __typename } }`;
  try {
    const r = await fetch(`${endpoint}/v1/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ query }),
    });
    const status = r.status;
    if (!r.ok) {
      return { confirmed: false, status, reason: `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      if (parsed.errors) {
        return { confirmed: false, status, reason: `graphql error: ${parsed.errors[0]?.message?.slice(0, 60)}` };
      }
      const rows = parsed.data?.[tableName] || [];
      row_count = rows.length;
      if (rows[0] && typeof rows[0] === "object") columns = Object.keys(rows[0]);
    } catch { /* non-JSON */ }
    return {
      confirmed: row_count > 0,
      status,
      sample: { row_count, columns: columns.slice(0, 8), bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}

async function probeIntrospection(endpoint) {
  const query = `{ __schema { queryType { name } } }`;
  try {
    const r = await fetch(`${endpoint}/v1/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ query }),
    });
    if (!r.ok) return { confirmed: false, status: r.status };
    const data = await r.json();
    const enabled = !!data?.data?.__schema;
    return { confirmed: enabled, status: r.status };
  } catch (e) {
    return { confirmed: false, status: 0, reason: e.message };
  }
}

export async function audit(opts) {
  const { endpoint, secret, activeProbe = true } = opts;
  if (!endpoint || !secret) throw new Error("audit() requires { endpoint, secret }");

  const findings = [];

  // Pull metadata: tables + their permissions per role
  const metadata = await hasura(endpoint, secret, { type: "export_metadata", args: {} });
  const sources = metadata.sources || metadata.metadata?.sources || [];

  let probed = 0;
  let confirmed = 0;
  let totalTables = 0;

  for (const source of sources) {
    const tables = source.tables || [];
    totalTables += tables.length;

    for (const t of tables) {
      const tableName = t.table?.name || t.table?.table || t.table;
      if (!tableName) continue;

      const checkPerms = (perms, role, action) => {
        if (!perms) return;
        for (const p of perms) {
          if (p.role !== role) continue;
          const filter = p.permission?.filter || p.permission?.check;
          const isOpen = !filter || JSON.stringify(filter) === "{}";

          // CRITICAL: anonymous role with any open permission
          if (role === "anonymous") {
            const checkKey = action === "select"
              ? "anonymous_role_table_select"
              : "anonymous_role_table_insert_or_mutation";
            const finding = {
              check: checkKey,
              ...CHECKS[checkKey],
              target: `${tableName} (${action})`,
              details: {
                table: tableName,
                role,
                action,
                filter,
                columns: p.permission?.columns,
                source: source.name,
              },
              fix_sql: `// Hasura console: Data → ${tableName} → Permissions → anonymous → ${action}
// Either DELETE this row entirely, or restrict the filter to a specific column check.
// Anonymous role should usually only have SELECT on tiny public tables (e.g. landing page content).`,
            };
            if (activeProbe && action === "select" && isOpen) {
              // Probe later (need full list of suspect tables)
              finding._probe_pending = true;
            }
            findings.push(finding);
          }

          // HIGH: user role with empty filter (no row-level scoping)
          if (role === "user" && (action === "select" || action === "update" || action === "delete") && isOpen) {
            findings.push({
              check: "user_role_no_row_filter",
              ...CHECKS.user_role_no_row_filter,
              target: `${tableName} (${role}/${action})`,
              details: { table: tableName, role, action, filter, columns: p.permission?.columns, source: source.name },
              fix_sql: `// Hasura console: Data → ${tableName} → Permissions → ${role} → ${action}
// Row filter, change from {} to:
//   { user_id: { _eq: "X-Hasura-User-Id" } }
// (assumes a user_id column scoping records to their owner)`,
            });
          }

          // MEDIUM: SELECT with all columns
          if (action === "select" && (p.permission?.columns === "*" || (Array.isArray(p.permission?.columns) && p.permission.columns.length === 0))) {
            findings.push({
              check: "permission_select_all_columns",
              ...CHECKS.permission_select_all_columns,
              target: `${tableName} (${role}/select all-columns)`,
              details: { table: tableName, role, columns: p.permission.columns, source: source.name },
              fix_sql: `// Hasura console: Data → ${tableName} → Permissions → ${role} → select
// Replace 'All columns' with explicit allowlist excluding sensitive fields.`,
            });
          }
        }
      };

      checkPerms(t.select_permissions, "anonymous", "select");
      checkPerms(t.select_permissions, "user", "select");
      checkPerms(t.insert_permissions, "anonymous", "insert");
      checkPerms(t.update_permissions, "anonymous", "update");
      checkPerms(t.delete_permissions, "anonymous", "delete");
      checkPerms(t.update_permissions, "user", "update");
      checkPerms(t.delete_permissions, "user", "delete");
    }
  }

  // Run probes for each anonymous_role_table_select with open filter
  if (activeProbe) {
    for (const f of findings) {
      if (f._probe_pending) {
        delete f._probe_pending;
        const probe = await probeAnonGraphql(endpoint, f.details.table);
        f.probe = probe;
        probed++;
        if (probe.confirmed) confirmed++;
      }
    }
    // Also probe introspection
    const intro = await probeIntrospection(endpoint);
    if (intro.confirmed) {
      findings.push({
        check: "graphql_introspection_public",
        ...CHECKS.graphql_introspection_public,
        target: "graphql:__schema",
        details: { endpoint: `${endpoint}/v1/graphql` },
        probe: intro,
        fix_sql: `// Hasura env vars (in Nhost dashboard or self-host config):
// HASURA_GRAPHQL_DISABLE_APIS=metadata,pgdump  // disable admin APIs in prod
// HASURA_GRAPHQL_ENABLED_APIS=graphql           // restrict to GraphQL only
// To disable anonymous introspection specifically: configure roles in Hasura console -> Permissions -> Allow List + Introspection.`,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    nhost_endpoint: endpoint,
    scanned_at: new Date().toISOString(),
    scanned_by: "nhost-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    summary,
    n_sources: sources.length,
    n_tables: totalTables,
    findings,
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage: nhost-security [--endpoint URL --secret SECRET] [--no-probe] [--html report.html]\n\nEnv vars: HASURA_ENDPOINT (Nhost: https://<subdomain>.hasura.<region>.nhost.run), HASURA_ADMIN_SECRET\n\nDetects: anonymous role with open permissions, user role missing row-level filter, SELECT-all-columns leaks, public introspection.`);
    process.exit(1);
  }

  const flag = (k) => args.includes(k) ? args[args.indexOf(k) + 1] : null;
  const endpoint = flag("--endpoint") || process.env.HASURA_ENDPOINT;
  const secret = flag("--secret") || process.env.HASURA_ADMIN_SECRET;
  const activeProbe = !args.includes("--no-probe");

  if (!endpoint || !secret) {
    console.error("Error: provide --endpoint, --secret (or HASURA_ENDPOINT / HASURA_ADMIN_SECRET env vars)");
    process.exit(1);
  }

  const result = await audit({ endpoint, secret, activeProbe });

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
