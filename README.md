# convex-secret-manager

Convex component for **encrypted secret vaults** and **issued API key lifecycle**.

Combines the roles of [gaganref/convex-secret-store](https://www.convex.dev/components/convex-secret-store) and [gaganref/convex-api-keys](https://www.convex.dev/components/convex-api-keys) into one package with per-`ownerId` tenancy. Any Convex app can use it (SaaS orgs, agents, multi-tenant backends).

## Two modules

| Module | Use |
|--------|-----|
| **Vault** | Store user-supplied credentials (OpenAI, Venice, webhooks) encrypted at rest |
| **Issued keys** | Issue `sm_` machine tokens with hash-only storage, refresh, revoke, and audit |

## vs gaganref

| | gaganref (2 packages) | `convex-secret-manager` |
|--|----------------------|-------------------------|
| Path model | `namespace` + `name` | `ownerId` + `namespace` + `name` |
| Use case | Generic apps | Multi-tenant backends that issue keys too |
| Install | Two components | One component |
| Vault crypto | Envelope + KEK rotation | Envelope (`defineKeys`) + legacy single-key |
| Issued validate | Query (side-effect free) | Query |
| Sweeps | Hourly crons | Hourly crons (built-in) |

Use gaganref when you need only one concern. Use this package when one owner should hold both third-party credentials and issued machine tokens.

## Install

```bash
npm install convex-secret-manager
```

```ts
// convex/convex.config.ts
import { defineApp } from "convex/server";
import { v } from "convex/values";
import { defineKeys } from "convex-secret-manager";
import secretManager from "convex-secret-manager/convex.config.js";

const app = defineApp({
  env: {
    MY_APP_KEK_V1: v.string(),
  },
});

app.use(secretManager, {
  env: {
    SECRET_MANAGER_KEYS: defineKeys({
      1: process.env.MY_APP_KEK_V1!,
    }),
  },
});

export default app;
```

```ts
// convex/secrets.ts
import { SecretManager } from "convex-secret-manager";
import { components } from "./_generated/api.js";

export const secretManager = new SecretManager(components.secretManager);
```

Set on the Convex deployment:

```env
SECRET_MANAGER_KEYS=1:<kek-material>
# or legacy single key:
SECRET_MANAGER_ENCRYPTION_KEY=...
```

## Vault paths

```text
ownerId   = orgId | userId | deployment
namespace = providers | integrations | webhooks
name      = openai.apiKey
```

## Issued keys API (parity highlights)

- `issued.create` / `validate` (query) / `touch` / `revoke` / `revokeAll`
- `issued.refresh` — rotate with grace period
- `issued.update` / `getKey` / `list` (paginated + `effectiveStatus`)
- Hourly sweep crons for expired and idle keys
- `cleanupKeys` / `cleanupEvents` internal jobs

## Vault API (parity highlights)

- `vault.putPlaintext` — component-side envelope encryption with AAD
- `vault.getResult` — `{ ok, value } | { ok: false, reason }`
- `vault.update` — metadata/TTL without re-encrypt
- `vault.list` — paginated with `effectiveState`
- `auditEvents.listEvents` — paginated audit trail
- `vaultRotate.rotate` / `isRotationComplete` — KEK rotation drain
- `vaultCleanup.cleanupSecrets` — expired secret cleanup

## Example

See [`example/`](./example/) for a minimal Convex + Vite dashboard.

## License

MIT