#!/usr/bin/env node
// Nhost (Hasura) Security — KEYLESS DISCOVER MODE.
//
// Parses the user's repo statically to find Nhost/Hasura client SDK usage:
//   - useQuery(gql`query { users { ... } }`) — GraphQL queries
//   - nhost.graphql.request(...) calls
//   - HASURA_ENDPOINT / NHOST_BACKEND_URL env references
// Then probes the GraphQL endpoint anonymously to confirm leaks:
//   - POST /v1/graphql with no auth headers + simple { table { id } } query
//   - GET introspection __schema
// No admin secret, no JWT.
//
// Triggered by `nhost-security --discover [path]`

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const PATTERNS = {
  // gql`query { tableName(where: ...) { ... } }`  — extract top-level field names
  gql: /gql`[^`]*?\b(?:query|subscription)\s+\w*\s*\{[^`]*?\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(\{]/g,
  // gql`mutation { insert_tableName(...) }`
  gqlMutation: /gql`[^`]*?\bmutation\s+\w*\s*\{\s*(?:insert_|update_|delete_)?([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(\{]/g,
  // HASURA_ENDPOINT=https://my-app.hasura.us-east-1.nhost.run
  hasuraEndpointEnv: /HASURA_ENDPOINT\s*=\s*['"`]?(https?:\/\/[^\s'"`]+)/g,
  // NHOST_BACKEND_URL=https://my-app.nhost.run
  nhostBackendEnv: /NHOST_BACKEND_URL\s*=\s*['"`]?(https?:\/\/[^\s'"`]+)/g,
  // new NhostClient({ subdomain: 'foo', region: 'us-east-1' })
  subdomain: /subdomain\s*:\s*['"`]([a-z0-9-]+)['"`]/g,
  region: /region\s*:\s*['"`]([a-z0-9-]+)['"`]/g,
  // NEXT_PUBLIC_NHOST_SUBDOMAIN=foo
  subdomainEnv: /(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?NHOST_SUBDOMAIN\s*=\s*['"`]?([a-z0-9-]+)/g,
  regionEnv: /(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?NHOST_REGION\s*=\s*['"`]?([a-z0-9-]+)/g,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", ".turbo",
  "coverage", ".cache", ".vercel", "__pycache__"
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".graphql", ".gql",
  ".env", ".env.local", ".env.example", ".env.production"
]);

const GRAPHQL_INTERNAL = new Set([
  "query", "mutation", "subscription", "fragment", "on", "id", "where", "limit", "offset",
  "order_by", "distinct_on", "data", "object", "objects", "pk_columns", "_set", "_inc",
]);

function walk(dir, files = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, files);
    } else {
      const lower = e.name.toLowerCase();
      const hasExt = [...SCAN_EXTENSIONS].some(x => lower.endsWith(x));
      if (hasExt || lower.startsWith(".env")) files.push(p);
    }
  }
  return files;
}

function readSafe(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

export function staticScan(root) {
  const files = walk(root);
  const out = {
    endpoint: null,
    subdomain: null,
    region: null,
    tables: new Set(),
    sourceFiles: 0,
    envFiles: 0,
    rootDir: root,
  };

  for (const file of files) {
    const content = readSafe(file);
    if (!content) continue;
    const isEnv = file.toLowerCase().includes(".env");
    if (isEnv) out.envFiles++; else out.sourceFiles++;

    if (!out.endpoint && isEnv) {
      const m = PATTERNS.hasuraEndpointEnv.exec(content) || PATTERNS.nhostBackendEnv.exec(content);
      if (m) out.endpoint = m[1].replace(/[\s'"`].*$/, "");
    }
    if (!out.subdomain) {
      const m = PATTERNS.subdomain.exec(content);
      if (m) out.subdomain = m[1];
    }
    if (!out.subdomain && isEnv) {
      const m = PATTERNS.subdomainEnv.exec(content);
      if (m) out.subdomain = m[1].replace(/[\s'"`].*$/, "");
    }
    if (!out.region) {
      const m = PATTERNS.region.exec(content);
      if (m) out.region = m[1];
    }
    if (!out.region && isEnv) {
      const m = PATTERNS.regionEnv.exec(content);
      if (m) out.region = m[1].replace(/[\s'"`].*$/, "");
    }

    for (const m of content.matchAll(PATTERNS.gql)) {
      const name = m[1];
      if (!GRAPHQL_INTERNAL.has(name)) out.tables.add(name);
    }
    for (const m of content.matchAll(PATTERNS.gqlMutation)) {
      const name = m[1];
      if (!GRAPHQL_INTERNAL.has(name)) out.tables.add(name);
    }
  }

  // Resolve endpoint from subdomain+region if not directly set
  if (!out.endpoint && out.subdomain && out.region) {
    out.endpoint = `https://${out.subdomain}.hasura.${out.region}.nhost.run`;
  }

  return { ...out, tables: [...out.tables] };
}

async function probeAnonQuery(endpoint, tableName) {
  try {
    const r = await fetch(`${endpoint}/v1/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "nhost-security/0.2 (discover)" },
      body: JSON.stringify({
        query: `query { ${tableName}(limit: 1) { __typename } }`,
      }),
    });
    const body = await r.text();
    let leaked = false;
    let errored = false;
    let rowCount = 0;
    try {
      const j = JSON.parse(body);
      if (j.errors && j.errors.length) errored = true;
      if (j.data && Array.isArray(j.data[tableName])) {
        rowCount = j.data[tableName].length;
        leaked = rowCount > 0;
      } else if (j.data && j.data[tableName] === null) {
        // null = anonymous role lacks perms (locked)
      }
    } catch {}
    return {
      status: r.status,
      perms_open: leaked,
      anon_query_errored: errored,
      sample_rows: rowCount,
      body_preview: body.slice(0, 250),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

async function probeIntrospection(endpoint) {
  try {
    const r = await fetch(`${endpoint}/v1/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "nhost-security/0.2 (discover)" },
      body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
    });
    const body = await r.text();
    let success = false;
    try { success = JSON.parse(body)?.data?.__schema?.queryType?.name === "query_root"; } catch {}
    return { status: r.status, introspection_open: success, body_preview: body.slice(0, 200) };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

export async function discover({ root = process.cwd(), endpoint = null } = {}) {
  const scan = staticScan(root);
  const ep = endpoint || scan.endpoint;
  const findings = [];
  const probes = [];

  if (!ep) {
    return {
      mode: "discover",
      error: "No Nhost/Hasura endpoint detected. Pass --endpoint or set HASURA_ENDPOINT / NHOST_BACKEND_URL in .env, or NhostClient({subdomain, region}) in source.",
      files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
      tables_found: scan.tables,
    };
  }

  // Try introspection first
  const intro = await probeIntrospection(ep);
  if (intro.introspection_open) {
    findings.push({
      check: "graphql_introspection_anonymous",
      severity: "medium",
      title: `Anonymous GraphQL introspection enabled on ${ep}`,
      explain: "Anyone can map your entire schema and permission structure without auth. Disable for anonymous in Hasura console.",
      target: `${ep}/v1/graphql`,
      details: intro,
      probe: { confirmed: true },
    });
  }

  for (const tbl of scan.tables) {
    const p = await probeAnonQuery(ep, tbl);
    probes.push({ table: tbl, ...p });
    if (p.perms_open) {
      findings.push({
        check: "table_anonymous_select_open",
        severity: "critical",
        title: `Table \`${tbl}\` is queryable anonymously`,
        explain: `POST /v1/graphql with no auth headers returned ${p.sample_rows} rows of ${tbl}. Anonymous role has SELECT permission with permissive row filter.`,
        target: tbl,
        details: { http_status: p.status, sample_rows: p.sample_rows, body_preview: p.body_preview },
        fix: `// Hasura console: Data → ${tbl} → Permissions → anonymous → select
// Either REMOVE the anonymous role permission, or tighten the row filter:
//   { user_id: { _eq: "X-Hasura-User-Id" } }`,
        probe: { confirmed: true },
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    mode: "discover",
    scanned_at: new Date().toISOString(),
    scanned_by: "nhost-security v0.2 (discover)",
    root_dir: root,
    hasura_endpoint: ep,
    files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
    tables_found: scan.tables,
    probes,
    summary,
    findings,
  };
}
