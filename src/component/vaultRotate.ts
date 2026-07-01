import { v } from "convex/values";
import { internalMutation, internalQuery } from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import { activeKeyVersion, parseDefinedKeys } from "../crypto/defineKeys.js";
import { buildAad, decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { writeAuditEvent } from "./audit.js";
import { resolveFallbackKey, resolveKeysSerialized } from "./lib/vaultCrypto.js";

const BATCH_SIZE = 100;

export const isRotationComplete = internalQuery({
  args: {},
  returns: v.boolean(),
  handler: async (ctx) => {
    const activeVersion = activeKeyVersion(parseDefinedKeys(resolveKeysSerialized()));
    if (!activeVersion) {
      return true;
    }
    const stale = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_key_version", (q) => q.eq("keyVersion", activeVersion - 1))
      .first();
    if (stale) {
      return false;
    }
    const anyStale = await ctx.db.query("vaultSecrets").collect();
    return !anyStale.some(
      (record) => record.keyVersion !== undefined && record.keyVersion < activeVersion,
    );
  },
});

export const rotate = internalMutation({
  args: { cursor: v.optional(v.string()) },
  returns: v.object({
    rotated: v.number(),
    skipped: v.number(),
    isDone: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const keysSerialized = resolveKeysSerialized();
    const activeVersion = activeKeyVersion(parseDefinedKeys(keysSerialized));
    if (!activeVersion) {
      return { rotated: 0, skipped: 0, isDone: true };
    }

    const result = await ctx.db.query("vaultSecrets").paginate({
      numItems: BATCH_SIZE,
      cursor: args.cursor ?? null,
    });

    let rotated = 0;
    let skipped = 0;
    for (const record of result.page) {
      if (!record.keyVersion || record.keyVersion >= activeVersion) {
        continue;
      }
      try {
        const plaintext = await decryptSecret(
          record.ciphertext,
          buildAad(record.ownerId, record.namespace, record.name),
          keysSerialized,
          resolveFallbackKey(),
        );
        const encrypted = await encryptSecret(
          plaintext,
          buildAad(record.ownerId, record.namespace, record.name),
          keysSerialized,
          resolveFallbackKey(),
        );
        await ctx.db.patch(record._id, {
          ciphertext: encrypted.ciphertext,
          keyVersion: encrypted.keyVersion,
          updatedAt: Date.now(),
        });
        await writeAuditEvent(ctx, {
          ownerId: record.ownerId,
          namespace: record.namespace,
          action: "vault.rotate",
          targetName: record.name,
          metadata: { from: record.keyVersion, to: encrypted.keyVersion },
        });
        rotated += 1;
      } catch {
        skipped += 1;
      }
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).vaultRotate.rotate, {
        cursor: result.continueCursor,
      });
    }

    return { rotated, skipped, isDone: result.isDone };
  },
});