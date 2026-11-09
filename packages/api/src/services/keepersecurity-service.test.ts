import { beforeEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
  getSecrets: vi.fn(),
  getNotationResults: vi.fn(),
  initializeStorage: vi.fn(),
  inMemoryStorage: vi.fn(),
  loadJsonConfig: vi.fn(),
}));

vi.mock("@keeper-security/secrets-manager-core", () => sdk);

import {
  bindOneTimeToken,
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

  it("never puts the resolved value in an error", async () => {
    sdk.getNotationResults.mockRejectedValue(new Error("boom"));
    const err = await rejection(resolveSecret(CONFIG_JSON, REF));
    expect(err.message).not.toContain("hunter2");
  });
});

describe("validateConfig", () => {
  it("passes when Keeper accepts the config", async () => {
    sdk.getSecrets.mockResolvedValue({ records: [] });
    await expect(validateConfig(CONFIG_JSON)).resolves.toBeUndefined();
    expect(sdk.getSecrets).toHaveBeenCalledWith({
      storage: { json: CONFIG_JSON },
    });
  });

  it("maps a Keeper failure to BAD_REQUEST", async () => {
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
