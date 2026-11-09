/**
 * Keeper Secrets Manager (KSM) SDK service — the only place that talks to Keeper.
 *
 * Mirrors onepassword-service: a stateless `config + keeper:// ref → value`
 * function. The caller sends the (decrypted) KSM config with each call; this
 * service never reads our database. Refs use KSM notation, e.g.
 * `keeper://<record-uid>/field/password`.
 */
import {
  getNotationResults,
  getSecrets,
  initializeStorage,
  inMemoryStorage,
  loadJsonConfig,
  type KeyValueStorage,
} from "@keeper-security/secrets-manager-core";

import { logger } from "../lib/logger";
import { ServiceError } from "./errors";

const errMessage = (err: unknown): string =>
  err instanceof Error ? err.message : String(err);

/** A one-time token looks like `US:` / `EU:` followed by url-safe base64. */
const ONE_TIME_TOKEN = /^[A-Za-z]{2,}:[\w-]+$/;

/** Keys every usable KSM config carries (the rest are optional / SDK-managed). */
const REQUIRED_CONFIG_KEYS = [
  "hostname",
  "clientId",
  "privateKey",
  "appKey",
] as const;

const badConfig = (reason: string): ServiceError =>
  new ServiceError(
    "BAD_REQUEST",
    `invalid keepersecurity KSM config: ${reason}`,
  );

/**
 * Accepts the KSM config as raw JSON or base64-encoded JSON, and checks it has
 * the keys the SDK needs so a wrong paste fails here with a readable reason
 * instead of deep inside the SDK.
 */
const toStorage = (config: string): KeyValueStorage => {
  const trimmed = config.trim();
  if (ONE_TIME_TOKEN.test(trimmed)) {
    throw badConfig(
      "this looks like a one-time token, not a configuration; connect with a one-time token instead",
    );
  }

  const json = trimmed.startsWith("{")
    ? trimmed
    : Buffer.from(trimmed, "base64").toString("utf8");

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw badConfig("expected JSON or base64-encoded JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badConfig("expected a JSON object");
  }
  const missing = REQUIRED_CONFIG_KEYS.filter(
    (k) => typeof (parsed as Record<string, unknown>)[k] !== "string",
  );
  if (missing.length > 0) {
    throw badConfig(`missing ${missing.join(", ")}`);
  }

  return loadJsonConfig(json);
};

/**
 * Bind a one-time token (e.g. `US:xxxx`) to a reusable KSM config. A one-time
 * token is single-use: the SDK registers this client with Keeper and the
 * returned config is the only thing that can be used afterwards, so the caller
 * must persist it.
 */
export const bindOneTimeToken = async (token: string): Promise<string> => {
  try {
    const store: Record<string, string> = {};
    const storage = inMemoryStorage(store);
    await initializeStorage(storage, token.trim());
    // First call performs the binding; it also proves the app can read records.
    await getSecrets({ storage });
    return JSON.stringify(store);
  } catch (err) {
    logger.warn(
      { err: errMessage(err) },
      "keepersecurity one-time token bind failed",
    );
    throw new ServiceError(
      "BAD_REQUEST",
      `keepersecurity one-time token could not be bound (already used or expired?): ${errMessage(err)}`,
    );
  }
};

/** Validate a KSM config with a cheap connectivity check (list accessible records). */
export const validateConfig = async (config: string): Promise<void> => {
  const storage = toStorage(config);
  try {
    await getSecrets({ storage });
  } catch (err) {
    logger.warn(
      { err: errMessage(err) },
      "keepersecurity config validation failed",
    );
    throw new ServiceError(
      "BAD_REQUEST",
      `keepersecurity config validation failed: ${errMessage(err)}`,
    );
  }
};

/** Resolve a `keeper://<uid>/field/<name>` reference to its secret value. */
export const resolveSecret = async (
  config: string,
  keepersecurityRef: string,
): Promise<string> => {
  const storage = toStorage(config);
  try {
    const results = await getNotationResults({ storage }, keepersecurityRef);
    if (results.length === 0) throw new Error("no value found");
    // A multi-value field resolves to its first value.
    return String(results[0]);
  } catch (err) {
    logger.warn(
      { keepersecurityRef, err: errMessage(err) },
      "keepersecurity resolve failed",
    );
    throw new ServiceError(
      "BAD_REQUEST",
      `cannot resolve ${keepersecurityRef}: ${errMessage(err)}`,
    );
  }
};
