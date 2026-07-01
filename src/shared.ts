import { v } from "convex/values";

export const SECRET_PREFIX = "enc:v1";

export const vaultStoreArgs = {
  ownerId: v.string(),
  namespace: v.string(),
  name: v.string(),
  ciphertext: v.string(),
  preview: v.string(),
  actorId: v.optional(v.string()),
  metadata: v.optional(v.any()),
};

export const vaultPathArgs = {
  ownerId: v.string(),
  namespace: v.string(),
  name: v.string(),
};

export const vaultNamespaceArgs = {
  ownerId: v.string(),
  namespace: v.string(),
  actorId: v.optional(v.string()),
};

export const issuedCreateArgs = {
  ownerId: v.string(),
  namespace: v.string(),
  name: v.string(),
  tokenHash: v.string(),
  tokenPrefix: v.string(),
  tokenLast4: v.string(),
  actorId: v.optional(v.string()),
  permissions: v.optional(v.record(v.string(), v.array(v.string()))),
  metadata: v.optional(v.any()),
  expiresAt: v.optional(v.number()),
  maxIdleMs: v.optional(v.number()),
};

export const issuedValidateArgs = {
  tokenHash: v.string(),
};

export const issuedKeyIdArgs = {
  keyId: v.id("issuedKeys"),
  ownerId: v.string(),
  actorId: v.optional(v.string()),
};

export type VaultRecord = {
  ownerId: string;
  namespace: string;
  name: string;
  ciphertext: string;
  preview: string;
  version: number;
  metadata?: unknown;
  updatedAt: number;
  createdAt: number;
};

export type IssuedKeyRecord = {
  _id: string;
  ownerId: string;
  namespace: string;
  name: string;
  tokenPrefix: string;
  tokenLast4: string;
  status: "active" | "revoked" | "disabled";
  permissions?: Record<string, string[]>;
  metadata?: unknown;
  expiresAt?: number;
  maxIdleMs?: number;
  lastUsedAt?: number;
  createdAt: number;
  updatedAt: number;
};