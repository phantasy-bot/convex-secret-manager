# convex-secret-manager

Convex component for **encrypted secret vaults** and **issued API key lifecycle**.

Directory slug: `/secret-manager`

## Two modules

| Module | Use |
|--------|-----|
| **Vault** | Store user-supplied credentials (OpenAI, Venice, webhooks) encrypted at rest |
| **Issued keys** | Issue `sm_` machine tokens with hash-only storage, revoke, and audit |

Unlike `convex-api-keys` community components, the vault is first-class for third-party secrets.

## Install

```bash
npm install convex-secret-manager
```

```ts
// convex/convex.config.ts
import secretManager from "convex-secret-manager/convex.config.js";

const app = defineApp();
app.use(secretManager);
export default app;
```

```ts
// convex/secrets.ts
import { SecretManager } from "convex-secret-manager";
import { components } from "./_generated/api.js";

export const secretManager = new SecretManager(components.secretManager, {
  encryptionKey: process.env.SECRET_MANAGER_ENCRYPTION_KEY,
});
```

Set on the Convex deployment:

```env
SECRET_MANAGER_ENCRYPTION_KEY=...
```

Phantasy deployments may alias `PHANTASY_SECRET_ENCRYPTION_KEY`.

## Vault paths

```text
ownerId   = agentId | deployment | orgId
namespace = providers | integrations | party-quest | extensions
name      = venice.apiKey
```

## License

MIT