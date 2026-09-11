import { defineApp } from "convex/server";
import { v } from "convex/values";
import { defineKeys } from "convex-secret-manager";
import secretManager from "convex-secret-manager/convex.config.js";

const app = defineApp({
  env: {
    SECRET_MANAGER_ENCRYPTION_KEY: v.optional(v.string()),
  },
});

app.use(secretManager);
export default app;
