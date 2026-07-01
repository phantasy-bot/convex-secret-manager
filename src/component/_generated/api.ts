/* eslint-disable */
import type * as audit from "../audit.js";
import type * as issuedKeys from "../issuedKeys.js";
import type * as vault from "../vault.js";
import type { ApiFromModules, FilterApi, FunctionReference } from "convex/server";
import { anyApi, componentsGeneric } from "convex/server";

const fullApi: ApiFromModules<{
  audit: typeof audit;
  issuedKeys: typeof issuedKeys;
  vault: typeof vault;
}> = anyApi as never;

export const api: FilterApi<typeof fullApi, FunctionReference<never, "public">> =
  anyApi as never;

export const internal: FilterApi<typeof fullApi, FunctionReference<never, "internal">> =
  anyApi as never;

export const components = componentsGeneric as never;