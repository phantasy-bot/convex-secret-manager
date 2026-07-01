import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  vaultSecrets: defineTable({
    ownerId: v.string(),
    namespace: v.string(),
    name: v.string(),
    ciphertext: v.string(),
    preview: v.string(),
    version: v.number(),
    metadata: v.optional(v.any()),
    updatedAt: v.number(),
    createdAt: v.number(),
  }).index("by_owner_namespace_name", ["ownerId", "namespace", "name"]),

  vaultSecretVersions: defineTable({
    ownerId: v.string(),
    namespace: v.string(),
    name: v.string(),
    version: v.number(),
    ciphertext: v.string(),
    preview: v.string(),
    rotatedAt: v.number(),
    actorId: v.optional(v.string()),
  }).index("by_secret_version", ["ownerId", "namespace", "name", "version"]),

  issuedKeys: defineTable({
    ownerId: v.string(),
    namespace: v.string(),
    name: v.string(),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    tokenLast4: v.string(),
    status: v.union(v.literal("active"), v.literal("revoked"), v.literal("disabled")),
    permissions: v.optional(v.record(v.string(), v.array(v.string()))),
    metadata: v.optional(v.any()),
    expiresAt: v.optional(v.number()),
    maxIdleMs: v.optional(v.number()),
    lastUsedAt: v.optional(v.number()),
    graceExpiresAt: v.optional(v.number()),
    replacedKeyId: v.optional(v.id("issuedKeys")),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_hash", ["tokenHash"])
    .index("by_owner", ["ownerId", "namespace"])
    .index("by_owner_status", ["ownerId", "namespace", "status"]),

  auditEvents: defineTable({
    ownerId: v.string(),
    namespace: v.string(),
    action: v.string(),
    targetName: v.string(),
    actorId: v.optional(v.string()),
    metadata: v.optional(v.any()),
    createdAt: v.number(),
  }).index("by_owner_time", ["ownerId", "createdAt"]),
});