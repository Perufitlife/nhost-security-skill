# Nhost / Hasura Security Auditor

> Audit any Hasura instance (or Nhost project) for permissive role permissions, missing row-level scoping, and public GraphQL leaks. Active probe confirms each leak by sending an anonymous GraphQL query and showing what comes back.

## Why this exists

Hasura's permission model is powerful but easy to leave too open. The patterns I see most often:

- **`anonymous` role with open SELECT permission** — any unauthenticated request can query the table. Often a leftover from local dev.
- **`user` role with empty filter `{}`** — any signed-up user can read/update/delete every row, ignoring ownership. Should usually be `{ user_id: { _eq: "X-Hasura-User-Id" } }`.
- **SELECT permission with all columns** — exposes sensitive columns (password_hash, internal_notes) the role doesn't actually need.
- **Public schema introspection** — anyone can map your entire data model + permission structure without auth.

## Install + run

```bash
HASURA_ENDPOINT=https://my.hasura.app \
HASURA_ADMIN_SECRET=$ADMIN_SECRET \
npx nhost-security --html report.html
```

For Nhost projects the endpoint is `https://<subdomain>.hasura.<region>.nhost.run`.

## What it checks

| # | Check | Severity |
|---|---|---|
| 1 | `anonymous` role has open SELECT permission | **CRITICAL** |
| 2 | `anonymous` role has INSERT/UPDATE/DELETE permission | **CRITICAL** |
| 3 | `user` role has SELECT/UPDATE/DELETE without row-level filter | HIGH |
| 4 | Permission exposes all columns (no allowlist) | MEDIUM |
| 5 | GraphQL introspection enabled for anonymous | MEDIUM |

## Active probe

For every suspect anonymous SELECT permission, the auditor sends an anonymous GraphQL query (`{ <table>(limit: 1) { __typename } }`) and reports `confirmed: true` if rows come back. For introspection, sends `{ __schema { queryType { name } } }` and reports if anonymous can read the schema.

`--no-probe` disables the live fetch.

## License + source

MIT. Open source: https://github.com/Perufitlife/nhost-security-skill

For Supabase, see https://github.com/Perufitlife/supabase-security-skill
For PocketBase, see https://github.com/Perufitlife/pocketbase-security-skill
For Appwrite, see https://github.com/Perufitlife/appwrite-security-skill
