import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { components } from "./_generated/api";
import { SecretManager } from "convex-secret-manager";

const secretManager = new SecretManager(components.secretManager);

export const store = mutation({
  args: {
    ownerId: v.string(),
    namespace: v.string(),
    name: v.string(),
    plaintext: v.string(),
  },
  handler: async (ctx, args) => {
    return await secretManager.vault.store(ctx, args);
  },
});

export const get = query({
  args: {
    ownerId: v.string(),
    namespace: v.string(),
    name: v.string(),
  },
  handler: async (ctx, args) => {
    return await secretManager.vault.get(ctx, args);
  },
});
