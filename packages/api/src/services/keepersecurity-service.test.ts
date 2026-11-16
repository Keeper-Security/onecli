import { beforeEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
  getFolders: vi.fn(),
  getSecrets: vi.fn(),
  getNotationResults: vi.fn(),
  initializeStorage: vi.fn(),
  inMemoryStorage: vi.fn(),
  loadJsonConfig: vi.fn(),
}));

vi.mock("@keeper-security/secrets-manager-core", () => sdk);

import {
  accessDeniedMessage,
  bindOneTimeToken,
  escapeNotation,
  getRecordFields,
  keeperFailure,
  listRecordFields,
  listRecords,
  resolveSecret,
  validateConfig,
} from "./keepersecurity-service";
import { ServiceError } from "./errors";

const CONFIG = {
  hostname: "keepersecurity.com",
  clientId: "client-id",
  privateKey: "private-key",
  appKey: "app-key",
  serverPublicKeyId: "10",
};
const CONFIG_JSON = JSON.stringify(CONFIG);
const CONFIG_B64 = Buffer.from(CONFIG_JSON).toString("base64");
const REF = "keeper://uid123/field/password";

const rejection = async (p: Promise<unknown>): Promise<ServiceError> => {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(ServiceError);
    return err as ServiceError;
  }
  throw new Error("expected the call to reject");
};

beforeEach(() => {
  vi.clearAllMocks();
  sdk.loadJsonConfig.mockImplementation((json: string) => ({ json }));
});

describe("config parsing", () => {
  it.each([
    ["raw JSON", CONFIG_JSON],
    ["base64-encoded JSON", CONFIG_B64],
    ["JSON with surrounding whitespace", `\n  ${CONFIG_JSON}  \n`],
  ])("accepts %s", async (_name, config) => {
    sdk.getNotationResults.mockResolvedValue(["secret"]);
    await expect(resolveSecret(config, REF)).resolves.toBe("secret");
    expect(sdk.loadJsonConfig).toHaveBeenCalledOnce();
  });

  it("points a pasted one-time token at the right flow", async () => {
    const err = await rejection(
      resolveSecret("US:tpW8qZLAZklF_dfyYLtEr-6_JYLotWk-N5-zVhPq0DU", REF),
    );
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toMatch(/one-time token/);
    expect(sdk.getNotationResults).not.toHaveBeenCalled();
  });

  it("rejects input that is neither JSON nor base64 JSON, without echoing it", async () => {
    const err = await rejection(resolveSecret("not a config at all", REF));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toMatch(/JSON or base64-encoded JSON/);
    expect(err.message).not.toContain("not a config at all");
  });

  it("rejects JSON that is not an object", async () => {
    const asBase64 = Buffer.from("[1,2,3]").toString("base64");
    const err = await rejection(resolveSecret(asBase64, REF));
    expect(err.message).toMatch(/JSON object/);
  });

  it.each(["hostname", "clientId", "privateKey", "appKey"])(
    "rejects a config missing %s",
    async (key) => {
      const rest = Object.fromEntries(
        Object.entries(CONFIG).filter(([k]) => k !== key),
      );
      const err = await rejection(resolveSecret(JSON.stringify(rest), REF));
      expect(err.message).toContain(`missing ${key}`);
      expect(sdk.getNotationResults).not.toHaveBeenCalled();
    },
  );
});

describe("resolveSecret", () => {
  it("passes the reference straight to the SDK and returns the value", async () => {
    sdk.getNotationResults.mockResolvedValue(["hunter2"]);
    await expect(resolveSecret(CONFIG_JSON, REF)).resolves.toBe("hunter2");
    expect(sdk.getNotationResults).toHaveBeenCalledWith(
      { storage: { json: CONFIG_JSON } },
      REF,
    );
  });

  it("resolves a multi-value field to its first value", async () => {
    sdk.getNotationResults.mockResolvedValue(["first", "second"]);
    await expect(resolveSecret(CONFIG_JSON, REF)).resolves.toBe("first");
  });

  it("stringifies a non-string value", async () => {
    sdk.getNotationResults.mockResolvedValue([12345]);
    await expect(resolveSecret(CONFIG_JSON, REF)).resolves.toBe("12345");
  });

  it("treats an empty result as unresolvable", async () => {
    sdk.getNotationResults.mockResolvedValue([]);
    const err = await rejection(resolveSecret(CONFIG_JSON, REF));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toContain(REF);
  });

  it("surfaces Keeper's error text as BAD_REQUEST, naming the reference", async () => {
    sdk.getNotationResults.mockRejectedValue(
      new Error("Record uid123 has no fields matching the search criteria 'x'"),
    );
    const err = await rejection(resolveSecret(CONFIG_JSON, REF));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toContain(REF);
    expect(err.message).toContain("no fields matching");
  });

  it("maps access_denied to FORBIDDEN", async () => {
    sdk.getNotationResults.mockRejectedValue(new Error(ACCESS_DENIED_BODY));
    const err = await rejection(resolveSecret(CONFIG_JSON, REF));
    expect(err.code).toBe("FORBIDDEN");
    expect(err.message).toContain(
      "Unable to validate Keeper application access",
    );
  });

  it("never puts the resolved value in an error", async () => {
    sdk.getNotationResults.mockRejectedValue(new Error("boom"));
    const err = await rejection(resolveSecret(CONFIG_JSON, REF));
    expect(err.message).not.toContain("hunter2");
  });
});

// What the SDK throws when Keeper refuses the application: its error body,
// verbatim, as the Error message.
const ACCESS_DENIED_BODY = JSON.stringify({
  path: "https://keepersecurity.com/api/rest/sm/v1/get_secret, POST",
  additional_info: "",
  location: "default exception manager - api validation exception",
  error: "access_denied",
  message: "Unable to validate Keeper application access",
});

describe("keeperFailure", () => {
  it("reads the code and message out of a Keeper error body", () => {
    expect(keeperFailure(new Error(ACCESS_DENIED_BODY))).toEqual({
      code: "access_denied",
      message: "Unable to validate Keeper application access",
    });
  });

  it("prefers result_code, the newer field", () => {
    const body = JSON.stringify({ result_code: "throttled", error: "x" });
    expect(keeperFailure(new Error(body)).code).toBe("throttled");
  });

  it("falls back to the code when there is no message", () => {
    expect(
      keeperFailure(new Error(JSON.stringify({ error: "invalid_client" }))),
    ).toEqual({ code: "invalid_client", message: "invalid_client" });
  });

  it.each([
    ["plain text", "socket hang up"],
    ["a JSON array", "[1,2]"],
    // The SDK truncates error bodies at 1000 bytes, which can cut the JSON.
    ["truncated JSON", '{"error":"access_den'],
  ])("passes %s through as the message", (_name, text) => {
    expect(keeperFailure(new Error(text))).toEqual({ message: text });
  });
});

describe("validateConfig", () => {
  it("reports how many records the application can read", async () => {
    sdk.getSecrets.mockResolvedValue({
      // The same record shared directly and via a folder counts once.
      records: [{ recordUid: "a" }, { recordUid: "b" }, { recordUid: "a" }],
    });
    await expect(validateConfig(CONFIG_JSON)).resolves.toEqual({
      recordCount: 2,
    });
    expect(sdk.getSecrets).toHaveBeenCalledWith({
      storage: { json: CONFIG_JSON },
    });
  });

  // Keeper answers an application whose shares were removed with success and
  // nothing in it, not an error.
  it("reports zero records when nothing is shared", async () => {
    sdk.getSecrets.mockResolvedValue({ records: [] });
    await expect(validateConfig(CONFIG_JSON)).resolves.toEqual({
      recordCount: 0,
    });
  });

  it("passes on Keeper's access expiry and warnings", async () => {
    sdk.getSecrets.mockResolvedValue({
      records: [{ recordUid: "a" }],
      expiresOn: new Date("2026-12-01T00:00:00Z"),
      warnings: ["share expires soon"],
    });
    await expect(validateConfig(CONFIG_JSON)).resolves.toEqual({
      recordCount: 1,
      expiresOn: "2026-12-01T00:00:00.000Z",
      warnings: ["share expires soon"],
    });
  });

  // Keeper does not say why it refused, so the message passes on what it did
  // say rather than naming a cause.
  it("maps access_denied to FORBIDDEN, passing on Keeper's message", async () => {
    sdk.getSecrets.mockRejectedValue(new Error(ACCESS_DENIED_BODY));
    const err = await rejection(validateConfig(CONFIG_JSON));
    expect(err.code).toBe("FORBIDDEN");
    expect(err.message).toBe(
      accessDeniedMessage("Unable to validate Keeper application access"),
    );
    expect(err.message).not.toContain("{");
    expect(err.message).not.toMatch(/revoked/);
  });

  it("maps any other Keeper failure to BAD_REQUEST, with Keeper's message only", async () => {
    sdk.getSecrets.mockRejectedValue(
      new Error(JSON.stringify({ error: "bad_thing", message: "Nope" })),
    );
    const err = await rejection(validateConfig(CONFIG_JSON));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toBe("keepersecurity config validation failed: Nope");
  });

  it("keeps a plain-text failure's text", async () => {
    sdk.getSecrets.mockRejectedValue(new Error("access denied"));
    const err = await rejection(validateConfig(CONFIG_JSON));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toContain("access denied");
  });

  it("rejects a malformed config before calling Keeper", async () => {
    const err = await rejection(validateConfig("nope"));
    expect(err.code).toBe("BAD_REQUEST");
    expect(sdk.getSecrets).not.toHaveBeenCalled();
  });
});

describe("bindOneTimeToken", () => {
  it("binds the trimmed token and returns the config the SDK produced", async () => {
    let store: Record<string, string> = {};
    sdk.inMemoryStorage.mockImplementation((s: Record<string, string>) => {
      store = s;
      return { kind: "storage" };
    });
    sdk.initializeStorage.mockImplementation(async () => {
      Object.assign(store, CONFIG);
    });
    sdk.getSecrets.mockResolvedValue({ records: [] });

    const out = await bindOneTimeToken("  US:abc123  ");

    expect(sdk.initializeStorage).toHaveBeenCalledWith(
      { kind: "storage" },
      "US:abc123",
    );
    expect(sdk.getSecrets).toHaveBeenCalledWith({
      storage: { kind: "storage" },
    });
    expect(JSON.parse(out)).toEqual(CONFIG);
  });

  it("explains a token that was already used or expired", async () => {
    sdk.inMemoryStorage.mockReturnValue({});
    sdk.initializeStorage.mockRejectedValue(new Error("invalid token"));
    const err = await rejection(bindOneTimeToken("US:abc"));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toMatch(/already used or expired/);
  });

  it("does not return a config when the first Keeper call fails", async () => {
    sdk.inMemoryStorage.mockReturnValue({});
    sdk.initializeStorage.mockResolvedValue(undefined);
    sdk.getSecrets.mockRejectedValue(new Error("timed out"));
    const err = await rejection(bindOneTimeToken("US:abc"));
    expect(err.message).toContain("timed out");
  });
});

// ── Picker ────────────────────────────────────────────────────────────────

const UID = "qnXEdBFVi2Gm1UFehAsjew";

type Field = { type: string; label?: string; value?: unknown[] };
const record = (fields: Field[], custom: Field[] = []) => ({
  recordUid: UID,
  data: { title: "GitHub", type: "login", fields, custom },
});

/**
 * Resolve a ref against a record the way the SDK's `getNotationResults` does,
 * but offline: parse with the SDK's REAL parser (so escaping is checked against
 * Keeper's own rules), then apply its matching rule — a field matches when the
 * parameter equals its type OR its label, and more than one match is an error.
 */
const resolveOffline = async (
  rec: ReturnType<typeof record>,
  ref: string,
): Promise<unknown> => {
  const real = await vi.importActual<
    typeof import("@keeper-security/secrets-manager-core")
  >("@keeper-security/secrets-manager-core");
  const parsed = real.parseNotation(ref);
  expect(parsed[1]?.text?.[0]).toBe(UID);
  const selector = parsed[2]?.text?.[0];
  const param = parsed[2]?.parameter?.[0];
  const list = (
    selector === "custom_field" ? rec.data.custom : rec.data.fields
  ) as Field[];
  const matches = list.filter((f) => f.type === param || f.label === param);
  expect(matches, `${ref} must match exactly one field`).toHaveLength(1);
  const value = matches[0]?.value?.[Number(parsed[2]?.index1?.[0] || 0)];
  const prop = parsed[2]?.index2?.[0];
  return prop ? (value as Record<string, unknown>)[prop] : value;
};

describe("escapeNotation", () => {
  it("escapes the characters notation reserves", () => {
    expect(escapeNotation("a/b[c]d\\e")).toBe("a\\/b\\[c\\]d\\\\e");
  });

  it("leaves ordinary text alone", () => {
    expect(escapeNotation("API Key 2")).toBe("API Key 2");
  });
});

describe("listRecordFields", () => {
  it("addresses standard fields by type and custom fields by label", async () => {
    const rec = record(
      [
        { type: "login", value: ["octocat"] },
        { type: "password", value: ["hunter2"] },
      ],
      [{ type: "text", label: "API Key", value: ["ghp_123"] }],
    );
    const fields = listRecordFields(rec);
    expect(fields.map((f) => [f.label, f.ref])).toEqual([
      ["Login", `keeper://${UID}/field/login`],
      ["Password", `keeper://${UID}/field/password`],
      ["API Key", `keeper://${UID}/custom_field/API Key`],
    ]);
    for (const f of fields) {
      expect(await resolveOffline(rec, f.ref)).toBeTypeOf("string");
    }
  });

  it("uses the label when two fields share a type", async () => {
    const rec = record(
      [],
      [
        { type: "secret", label: "Prod", value: ["p"] },
        { type: "secret", label: "Staging", value: ["s"] },
      ],
    );
    const fields = listRecordFields(rec);
    expect(fields.map((f) => f.ref)).toEqual([
      `keeper://${UID}/custom_field/Prod`,
      `keeper://${UID}/custom_field/Staging`,
    ]);
    expect(await resolveOffline(rec, fields[1]!.ref)).toBe("s");
  });

  it("falls back to the type when a label collides with another field's type", async () => {
    // Label "password" would also match the field whose TYPE is password.
    const rec = record([
      { type: "password", value: ["real"] },
      { type: "text", label: "password", value: ["decoy"] },
    ]);
    const fields = listRecordFields(rec);
    // "password" now matches two fields, so the text field falls back to its
    // own (unique) type. The password field has no other selector, so it is
    // left out rather than offered with a reference that would fail.
    expect(fields.map((f) => f.ref)).toEqual([`keeper://${UID}/field/text`]);
    expect(await resolveOffline(rec, fields[0]!.ref)).toBe("decoy");
  });

  it("omits a field with no unique selector", () => {
    const rec = record(
      [],
      [
        { type: "text", value: ["a"] },
        { type: "text", value: ["b"] },
      ],
    );
    expect(listRecordFields(rec)).toEqual([]);
  });

  it("escapes reserved characters in a label so the SDK reads it back", async () => {
    const label = "token/v2 [prod]";
    const rec = record([], [{ type: "text", label, value: ["t"] }]);
    const [field] = listRecordFields(rec);
    expect(field?.label).toBe(label);
    expect(await resolveOffline(rec, field!.ref)).toBe("t");
  });

  it("expands an object value into one entry per string property", async () => {
    const rec = record([
      {
        type: "keyPair",
        value: [{ publicKey: "ssh-ed25519 AAA", privateKey: "-----BEGIN" }],
      },
    ]);
    const fields = listRecordFields(rec);
    expect(fields.map((f) => [f.label, f.ref])).toEqual([
      ["Key Pair › Public Key", `keeper://${UID}/field/keyPair[0][publicKey]`],
      [
        "Key Pair › Private Key",
        `keeper://${UID}/field/keyPair[0][privateKey]`,
      ],
    ]);
    expect(await resolveOffline(rec, fields[1]!.ref)).toBe("-----BEGIN");
  });

  it.each(["fileRef", "oneTimeCode", "otp", "recordRef", "passkey"])(
    "skips %s fields, which cannot be injected as a credential",
    (type) => {
      const rec = record([{ type, value: ["x"] }]);
      expect(listRecordFields(rec)).toEqual([]);
    },
  );

  it("leaves out fields with no value", () => {
    const rec = record([
      { type: "password", value: [] },
      { type: "login", value: [""] },
      { type: "url" },
      { type: "text", label: "Blank", value: ["   "] },
      { type: "email", value: ["dev@example.com"] },
    ]);
    expect(listRecordFields(rec).map((f) => f.label)).toEqual(["Email"]);
  });

  it("leaves out an object value's empty properties", () => {
    const rec = record([
      { type: "name", value: [{ first: "Ada", middle: "", last: "Lovelace" }] },
    ]);
    expect(listRecordFields(rec).map((f) => f.label)).toEqual([
      "Name › First",
      "Name › Last",
    ]);
  });

  it("still counts an empty field when checking a selector is unique", () => {
    // Keeper's notation would match both `text` fields, so neither can be
    // addressed by type — even though only one of them is shown.
    const rec = record(
      [],
      [
        { type: "text", value: [""] },
        { type: "text", value: ["shown?"] },
      ],
    );
    expect(listRecordFields(rec)).toEqual([]);
  });

  it("keeps a numeric value", () => {
    const rec = record([{ type: "pinCode", value: [1234] }]);
    expect(listRecordFields(rec)).toHaveLength(1);
  });

  it("never returns a value", () => {
    const rec = record(
      [{ type: "password", value: ["hunter2"] }],
      [{ type: "keyPair", label: "Deploy", value: [{ privateKey: "PRIV" }] }],
    );
    const json = JSON.stringify(listRecordFields(rec));
    expect(json).not.toContain("hunter2");
    expect(json).not.toContain("PRIV");
  });

  it("tolerates a record with no field lists", () => {
    expect(
      listRecordFields({ recordUid: UID, data: { title: "Empty" } }),
    ).toEqual([]);
  });
});

describe("listRecords", () => {
  const recs = [
    {
      recordUid: "b",
      folderUid: "sf",
      innerFolderUid: "sub",
      data: { title: "Stripe", type: "login" },
    },
    { recordUid: "a", data: { title: "Anthropic", type: "general" } },
    // Shared twice (directly and through a folder) — must appear once.
    { recordUid: "a", folderUid: "sf", data: { title: "Anthropic" } },
  ];

  it("lists each record once, sorted, with its folder path", async () => {
    sdk.getSecrets.mockResolvedValue({ records: recs });
    sdk.getFolders.mockResolvedValue([
      { folderUid: "sf", name: "Shared" },
      { folderUid: "sub", parentUid: "sf", name: "Payments" },
    ]);
    await expect(listRecords(CONFIG_JSON)).resolves.toEqual([
      { uid: "a", title: "Anthropic", type: "general" },
      {
        uid: "b",
        title: "Stripe",
        type: "login",
        folder: "Shared / Payments",
      },
    ]);
  });

  it("still lists records when folders cannot be read", async () => {
    sdk.getSecrets.mockResolvedValue({ records: recs });
    sdk.getFolders.mockRejectedValue(new Error("not supported"));
    const out = await listRecords(CONFIG_JSON);
    expect(out.map((r) => r.uid)).toEqual(["a", "b"]);
    expect(out.every((r) => r.folder === undefined)).toBe(true);
  });

  it("surfaces a Keeper failure as BAD_REQUEST", async () => {
    sdk.getSecrets.mockRejectedValue(new Error("access denied"));
    sdk.getFolders.mockResolvedValue([]);
    const err = await rejection(listRecords(CONFIG_JSON));
    expect(err.code).toBe("BAD_REQUEST");
    expect(err.message).toContain("access denied");
  });

  it("rejects a bad config before calling Keeper", async () => {
    await rejection(listRecords("nope"));
    expect(sdk.getSecrets).not.toHaveBeenCalled();
  });
});

describe("getRecordFields", () => {
  it("reads only the requested record", async () => {
    sdk.getSecrets.mockResolvedValue({
      records: [record([{ type: "password", value: ["x"] }])],
    });
    const fields = await getRecordFields(CONFIG_JSON, UID);
    expect(sdk.getSecrets).toHaveBeenCalledWith(
      { storage: { json: CONFIG_JSON } },
      [UID],
    );
    expect(fields.map((f) => f.ref)).toEqual([
      `keeper://${UID}/field/password`,
    ]);
  });

  it("answers NOT_FOUND for a record that is not shared", async () => {
    sdk.getSecrets.mockResolvedValue({ records: [] });
    const err = await rejection(getRecordFields(CONFIG_JSON, UID));
    expect(err.code).toBe("NOT_FOUND");
  });
});
