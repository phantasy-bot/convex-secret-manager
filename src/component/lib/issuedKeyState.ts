import type { Doc } from "../_generated/dataModel.js";

export type IssuedEffectiveStatus =
  | "active"
  | "revoked"
  | "disabled"
  | "expired"
  | "idle_timeout";

export function isExpired(expiresAt: number | undefined, now: number): boolean {
  return typeof expiresAt === "number" && expiresAt <= now;
}

export function isIdle(
  lastUsedAt: number | undefined,
  maxIdleMs: number | undefined,
  now: number,
): boolean {
  if (!maxIdleMs || !lastUsedAt) {
    return false;
  }
  return lastUsedAt + maxIdleMs <= now;
}

export function effectiveIssuedStatus(
  record: Pick<
    Doc<"issuedKeys">,
    "status" | "expiresAt" | "maxIdleMs" | "lastUsedAt"
  >,
  now = Date.now(),
): IssuedEffectiveStatus {
  if (record.status === "revoked") {
    return "revoked";
  }
  if (record.status === "disabled") {
    return "disabled";
  }
  if (isExpired(record.expiresAt, now)) {
    return "expired";
  }
  if (isIdle(record.lastUsedAt, record.maxIdleMs, now)) {
    return "idle_timeout";
  }
  return "active";
}

export function validateIssuedRecord(
  record: Doc<"issuedKeys"> | null,
  now = Date.now(),
):
  | {
      ok: true;
      keyId: Doc<"issuedKeys">["_id"];
      ownerId: string;
      namespace: string;
      name: string;
      permissions?: Record<string, string[]>;
      metadata?: unknown;
    }
  | { ok: false; reason: string } {
  if (!record) {
    return { ok: false, reason: "not_found" };
  }
  if (record.status === "revoked") {
    return { ok: false, reason: "revoked" };
  }
  if (record.status === "disabled") {
    return { ok: false, reason: "disabled" };
  }
  if (isExpired(record.expiresAt, now)) {
    return { ok: false, reason: "expired" };
  }
  if (isIdle(record.lastUsedAt, record.maxIdleMs, now)) {
    return { ok: false, reason: "idle_timeout" };
  }
  return {
    ok: true,
    keyId: record._id,
    ownerId: record.ownerId,
    namespace: record.namespace,
    name: record.name,
    permissions: record.permissions,
    metadata: record.metadata,
  };
}