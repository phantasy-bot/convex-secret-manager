export type KeyVersionMap = Record<number, string>;

export function defineKeys(keys: KeyVersionMap): string {
  const entries = Object.entries(keys)
    .map(([version, value]) => [Number(version), value.trim()] as const)
    .filter(([, value]) => value.length > 0)
    .sort(([a], [b]) => a - b);

  if (entries.length === 0) {
    throw new Error("defineKeys requires at least one key version");
  }

  for (const [version, value] of entries) {
    if (!Number.isInteger(version) || version < 1) {
      throw new Error(`Invalid key version: ${version}`);
    }
    if (value.length < 16) {
      throw new Error(`Key version ${version} must be at least 16 characters`);
    }
  }

  return entries.map(([version, value]) => `${version}:${value}`).join(",");
}

export function parseDefinedKeys(serialized: string | undefined): Map<number, string> {
  const map = new Map<number, string>();
  const normalized = serialized?.trim();
  if (!normalized) {
    return map;
  }

  for (const part of normalized.split(",")) {
    const separator = part.indexOf(":");
    if (separator <= 0) {
      continue;
    }
    const version = Number(part.slice(0, separator));
    const material = part.slice(separator + 1).trim();
    if (Number.isInteger(version) && version >= 1 && material) {
      map.set(version, material);
    }
  }
  return map;
}

export function activeKeyVersion(keys: Map<number, string>): number {
  let max = 0;
  for (const version of keys.keys()) {
    if (version > max) {
      max = version;
    }
  }
  return max;
}