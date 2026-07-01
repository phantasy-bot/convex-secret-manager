import { ConvexError } from "convex/values";

export const SECRET_MANAGER_ERROR_CODES = [
  "invalid_argument",
  "not_found",
  "expired",
  "key_unavailable",
  "decryption_failed",
  "value_too_large",
  "already_revoked",
] as const;

export type SecretManagerErrorCode = (typeof SECRET_MANAGER_ERROR_CODES)[number];

export type SecretManagerErrorData = {
  code: SecretManagerErrorCode;
  message: string;
};

export function secretManagerError(
  code: SecretManagerErrorCode,
  message: string,
): ConvexError<SecretManagerErrorData> {
  return new ConvexError({ code, message });
}

export function isSecretManagerError(
  error: unknown,
): error is ConvexError<SecretManagerErrorData> {
  return (
    error instanceof ConvexError &&
    typeof error.data === "object" &&
    error.data !== null &&
    "code" in error.data &&
    typeof (error.data as SecretManagerErrorData).code === "string"
  );
}