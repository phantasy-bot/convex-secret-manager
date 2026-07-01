export function effectiveVaultState(record: {
  expiresAt?: number;
}): "active" | "expired" {
  if (record.expiresAt && record.expiresAt <= Date.now()) {
    return "expired";
  }
  return "active";
}