/* eslint-disable */
import type * as audit from "../audit.js";
import type * as auditEvents from "../auditEvents.js";
import type * as crons from "../crons.js";
import type * as issuedCleanup from "../issuedCleanup.js";
import type * as issuedKeys from "../issuedKeys.js";
import type * as issuedSweep from "../issuedSweep.js";
import type * as vault from "../vault.js";
import type * as vaultCleanup from "../vaultCleanup.js";
import type * as vaultRotate from "../vaultRotate.js";
import type { ApiFromModules, FilterApi, FunctionReference } from "convex/server";
import { anyApi, componentsGeneric } from "convex/server";

const fullApi: ApiFromModules<{
  audit: typeof audit;
  auditEvents: typeof auditEvents;
  crons: typeof crons;
  issuedCleanup: typeof issuedCleanup;
  issuedKeys: typeof issuedKeys;
  issuedSweep: typeof issuedSweep;
  vault: typeof vault;
  vaultCleanup: typeof vaultCleanup;
  vaultRotate: typeof vaultRotate;
}> = anyApi as never;

export const api: FilterApi<typeof fullApi, FunctionReference<never, "public">> =
  anyApi as never;

export const internal: FilterApi<typeof fullApi, FunctionReference<never, "internal">> =
  anyApi as never;

export const components = componentsGeneric as never;