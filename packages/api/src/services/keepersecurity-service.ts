/**
 * Keeper Secrets Manager (KSM) SDK service — the only place that talks to Keeper.
 *
 * Mirrors onepassword-service: a stateless `config + keeper:// ref → value`
 * function, plus the picker's record/field listing. The caller sends the
 * (decrypted) KSM config with each call; this service never reads our
 * database. Refs use KSM notation, e.g. `keeper://<record-uid>/field/password`.
 */
import {
  getFolders,
  getNotationResults,
  getSecrets,
  type KeeperFolder,
  type KeeperRecord,
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

// ── Picker (browse records → fields) ─────────────────────────────────────
// Field VALUES never leave this process: the SDK decrypts whole records, but
// only titles, types and the notation that addresses each field reach the
// caller.

export interface KeeperSecurityRecord {
  uid: string;
  title: string;
  type: string;
  /** Folder path (`Shared / Team`), when the record sits in a shared folder. */
  folder?: string;
}

export interface KeeperSecurityField {
  /** Full `keeper://` reference that resolves exactly this value. */
  ref: string;
  label: string;
  fieldType: string;
}

/** A value a secret could actually inject: a non-blank string or a number. */
const hasValue = (v: unknown): boolean =>
  typeof v === "number" || (typeof v === "string" && v.trim() !== "");

/** A field as it sits in a decrypted record (`data.fields` / `data.custom`). */
interface RawField {
  type?: unknown;
  label?: unknown;
  value?: unknown;
}

/**
 * Field types that cannot be injected as a credential: references to other
 * records/files, and one-time-code fields (whose stored value is the
 * `otpauth://` seed URL, not a code).
 */
const UNPICKABLE_FIELD_TYPES = new Set([
  "fileRef",
  "cardRef",
  "addressRef",
  "recordRef",
  "oneTimeCode",
  "otp",
  "passkey",
]);

/** Notation reserves `/ [ ] \`; a literal one is backslash-escaped. */
export const escapeNotation = (text: string): string =>
  text.replace(/[/[\]\\]/g, (c) => `\\${c}`);

/** `keyPair` → `Key Pair`, for fields with no label of their own. */
const humanize = (type: string): string =>
  type
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase());

const asString = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * The parameter that addresses `field` unambiguously within `list`.
 *
 * KSM notation matches `field/<x>` against a field's type OR its label and
 * refuses when more than one field matches, so a record with two `text` fields
 * cannot address either by type. Prefer the label (what the user named it),
 * fall back to the type; `null` when neither is unique.
 */
const uniqueSelector = (field: RawField, list: RawField[]): string | null => {
  const candidates = [asString(field.label), asString(field.type)].filter(
    Boolean,
  );
  for (const c of candidates) {
    const matches = list.filter(
      (x) => asString(x.type) === c || asString(x.label) === c,
    ).length;
    if (matches === 1) return c;
  }
  return null;
};

/**
 * Every value of a record a secret can reference, each with the notation that
 * resolves it. Object-valued fields (`keyPair`, `host`, `name`, …) expand to
 * one entry per string property, e.g. `field/keyPair[0][privateKey]`, since
 * the whole object would resolve to JSON rather than a usable credential.
 * Fields with no value are left out (a secret pointing at one would resolve
 * empty), though they still count when checking a selector is unique, since
 * Keeper's notation counts them too. Pure — exported for tests.
 */
export const listRecordFields = (
  record: Pick<KeeperRecord, "recordUid" | "data">,
): KeeperSecurityField[] => {
  const base = `keeper://${record.recordUid}`;
  const out: KeeperSecurityField[] = [];
  const sections: [string, unknown][] = [
    ["field", record.data?.fields],
    ["custom_field", record.data?.custom],
  ];

  for (const [selector, raw] of sections) {
    if (!Array.isArray(raw)) continue;
    const list = raw as RawField[];
    for (const field of list) {
      const type = asString(field.type);
      if (UNPICKABLE_FIELD_TYPES.has(type)) continue;
      const param = uniqueSelector(field, list);
      if (param === null) continue;

      const label = asString(field.label) || humanize(type || "field");
      const ref = `${base}/${selector}/${escapeNotation(param)}`;
      const values = Array.isArray(field.value) ? field.value : [];
      const first: unknown = values[0];

      if (
        first !== null &&
        typeof first === "object" &&
        !Array.isArray(first)
      ) {
        for (const [key, v] of Object.entries(first)) {
          if (typeof v !== "string" || !hasValue(v)) continue;
          out.push({
            ref: `${ref}[0][${escapeNotation(key)}]`,
            label: `${label} › ${humanize(key)}`,
            fieldType: type,
          });
        }
        continue;
      }

      if (!hasValue(first)) continue;
      out.push({ ref, label, fieldType: type });
    }
  }
  return out;
};

/** `Parent / Child` for a folder UID, walking up through `parentUid`. */
const folderPath = (
  uid: string | undefined,
  byUid: Map<string, KeeperFolder>,
): string | undefined => {
  const names: string[] = [];
  const seen = new Set<string>();
  let cur = uid ? byUid.get(uid) : undefined;
  while (cur && !seen.has(cur.folderUid)) {
    seen.add(cur.folderUid);
    if (cur.name) names.unshift(cur.name);
    cur = cur.parentUid ? byUid.get(cur.parentUid) : undefined;
  }
  return names.length > 0 ? names.join(" / ") : undefined;
};

/** List the records shared with the KSM application (picker step 1). */
export const listRecords = async (
  config: string,
): Promise<KeeperSecurityRecord[]> => {
  const storage = toStorage(config);
  try {
    // Folder names are cosmetic; an app or SDK that cannot list folders still
    // gets a usable record list.
    const [secrets, folders] = await Promise.all([
      getSecrets({ storage }),
      getFolders({ storage }).catch((err: unknown) => {
        logger.warn(
          { err: errMessage(err) },
          "keepersecurity folder listing failed; showing records without folders",
        );
        return [] as KeeperFolder[];
      }),
    ]);
    const byUid = new Map(folders.map((f) => [f.folderUid, f]));
    const seen = new Set<string>();
    const records: KeeperSecurityRecord[] = [];
    for (const r of secrets.records) {
      // A record shared both directly and via a folder (or as a shortcut)
      // comes back more than once.
      if (seen.has(r.recordUid)) continue;
      seen.add(r.recordUid);
      const folder = folderPath(r.innerFolderUid ?? r.folderUid, byUid);
      records.push({
        uid: r.recordUid,
        title: asString(r.data?.title) || r.recordUid,
        type: asString(r.data?.type),
        ...(folder ? { folder } : {}),
      });
    }
    return records.sort((a, b) => a.title.localeCompare(b.title));
  } catch (err) {
    logger.warn(
      { err: errMessage(err) },
      "keepersecurity record listing failed",
    );
    throw new ServiceError(
      "BAD_REQUEST",
      `cannot list keepersecurity records: ${errMessage(err)}`,
    );
  }
};

/** List one record's referenceable fields — labels and refs, never values. */
export const getRecordFields = async (
  config: string,
  recordUid: string,
): Promise<KeeperSecurityField[]> => {
  const storage = toStorage(config);
  let record: KeeperRecord | undefined;
  try {
    const secrets = await getSecrets({ storage }, [recordUid]);
    record = secrets.records.find((r) => r.recordUid === recordUid);
  } catch (err) {
    logger.warn(
      { recordUid, err: errMessage(err) },
      "keepersecurity record read failed",
    );
    throw new ServiceError(
      "BAD_REQUEST",
      `cannot read keepersecurity record: ${errMessage(err)}`,
    );
  }
  if (!record) {
    throw new ServiceError(
      "NOT_FOUND",
      "keepersecurity record not found or not shared with this application",
    );
  }
  return listRecordFields(record);
};
