// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { KeeperSecuritySetup } from "./keepersecurity-setup";

// The connect/manage page for Keeper. The unit is what the page shows for each
// connection state and what it hands to the pair/disconnect actions; the hooks
// that talk to the gateway are covered in use-keepersecurity.test.tsx.
const h = vi.hoisted(() => ({
  status: {
    loading: false,
    isPaired: false,
    isReady: false,
    status: null as { status_data: { last_error: string | null } } | null,
    fetchStatus: vi.fn(),
  },
  pair: vi.fn<(method: string, input: string) => Promise<boolean>>(),
  pairing: false,
  disconnect: vi.fn(),
  disconnecting: false,
  providers: [] as string[],
}));

vi.mock("@/hooks/use-vault-status", () => ({
  useVaultStatus: (provider: string) => {
    h.providers.push(provider);
    return h.status;
  },
  useVaultDisconnect: (_fetch: unknown, provider: string) => {
    h.providers.push(provider);
    return { disconnect: h.disconnect, disconnecting: h.disconnecting };
  },
}));
vi.mock("@/hooks/use-keepersecurity", () => ({
  useKeeperSecurityPair: () => ({ pair: h.pair, pairing: h.pairing }),
}));

// Radix's Select drives its listbox through pointer-capture and scroll APIs
// jsdom does not implement.
beforeAll(() => {
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.setPointerCapture ??= () => {};
  Element.prototype.releasePointerCapture ??= () => {};
  Element.prototype.scrollIntoView ??= () => {};
});

beforeEach(() => {
  h.status = {
    loading: false,
    isPaired: false,
    isReady: false,
    status: null,
    fetchStatus: vi.fn(),
  };
  h.pair.mockResolvedValue(true);
  h.pairing = false;
  h.disconnecting = false;
  h.providers = [];
});
afterEach(() => vi.clearAllMocks());

const connectButton = () =>
  screen.getByRole("button", {
    name: /^Connect Keeper|Connecting/,
  });

const TOKEN_LABEL = "One-time access token";

const chooseMethod = async (option: string) => {
  await userEvent.click(
    screen.getByRole("combobox", { name: "Connection method" }),
  );
  await userEvent.click(await screen.findByRole("option", { name: option }));
};

describe("KeeperSecuritySetup: not connected", () => {
  it("talks to the Keeper provider, not another vault's", () => {
    render(<KeeperSecuritySetup />);
    expect(new Set(h.providers)).toEqual(new Set(["keepersecurity"]));
  });

  it("offers a connect form, starting with the one-time access token method", () => {
    render(<KeeperSecuritySetup />);
    expect(screen.getAllByText(/^Connect Keeper/).length).toBeGreaterThan(0);
    expect(
      screen.getByRole("combobox", { name: "Connection method" }),
    ).toHaveTextContent("One-time access token");
    expect(screen.getByLabelText(TOKEN_LABEL)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("US:...")).toBeInTheDocument();
  });

  it("lists the three connection methods", async () => {
    render(<KeeperSecuritySetup />);
    await userEvent.click(
      screen.getByRole("combobox", { name: "Connection method" }),
    );
    expect(
      (await screen.findAllByRole("option")).map((o) => o.textContent),
    ).toEqual(["One-time access token", "Base64 string", "JSON configuration"]);
  });

  it("keeps Connect off until something is entered", async () => {
    render(<KeeperSecuritySetup />);
    expect(connectButton()).toBeDisabled();
    await userEvent.click(screen.getByLabelText(TOKEN_LABEL));
    await userEvent.paste("   ");
    expect(connectButton()).toBeDisabled();
    await userEvent.paste("US:abc");
    expect(connectButton()).toBeEnabled();
  });

  it("hands the method and the pasted text to pair, then clears the field", async () => {
    render(<KeeperSecuritySetup />);
    const field = screen.getByLabelText(TOKEN_LABEL);
    await userEvent.click(field);
    await userEvent.paste("US:abc123");
    await userEvent.click(connectButton());

    expect(h.pair).toHaveBeenCalledWith("one_time_token", "US:abc123");
    expect(field).toHaveValue("");
  });

  it.each([
    ["Base64 string", "Base64 configuration", "base64_config", "eyJhIjoiYiJ9"],
    ["JSON configuration", "JSON configuration", "json_config", '{"a":"b"}'],
  ])(
    "uses the %s method once chosen",
    async (option, fieldLabel, method, value) => {
      render(<KeeperSecuritySetup />);
      await chooseMethod(option);
      const field = screen.getByLabelText(fieldLabel);
      await userEvent.click(field);
      await userEvent.paste(value);
      await userEvent.click(connectButton());

      expect(h.pair).toHaveBeenCalledWith(method, value);
    },
  );

  it("keeps what was pasted when pairing fails, so it can be corrected", async () => {
    h.pair.mockResolvedValue(false);
    render(<KeeperSecuritySetup />);
    const field = screen.getByLabelText(TOKEN_LABEL);
    await userEvent.click(field);
    await userEvent.paste("US:abc123");
    await userEvent.click(connectButton());

    expect(h.pair).toHaveBeenCalledOnce();
    expect(field).toHaveValue("US:abc123");
  });

  it("masks the pasted credential", () => {
    render(<KeeperSecuritySetup />);
    expect(screen.getByLabelText(TOKEN_LABEL)).toHaveAttribute(
      "type",
      "password",
    );
  });

  it("explains that the token is used once and only the configuration is stored", () => {
    render(<KeeperSecuritySetup />);
    expect(screen.getByText(/The token is used\s+once/)).toBeInTheDocument();
  });

  it("shows the form's loading state while connecting", () => {
    h.pairing = true;
    render(<KeeperSecuritySetup />);
    expect(
      screen.getByRole("button", { name: /Connecting/ }),
    ).toBeInTheDocument();
  });

  it("shows a skeleton, not the form, while status loads", () => {
    h.status.loading = true;
    render(<KeeperSecuritySetup />);
    expect(screen.queryByText(/^Connect Keeper/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(TOKEN_LABEL)).not.toBeInTheDocument();
  });
});

describe("KeeperSecuritySetup: connected", () => {
  beforeEach(() => {
    h.status.isPaired = true;
    h.status.isReady = true;
  });

  it("shows Connected and no connect form", () => {
    render(<KeeperSecuritySetup />);
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.queryByLabelText(TOKEN_LABEL)).not.toBeInTheDocument();
  });

  it("tells the user how to use the connection", () => {
    render(<KeeperSecuritySetup />);
    expect(screen.getByText(/keeper:\/\//)).toBeInTheDocument();
  });

  it("shows Paired (not Connected) when stored but not yet confirmed live", () => {
    h.status.isReady = false;
    render(<KeeperSecuritySetup />);
    expect(screen.getByText("Paired")).toBeInTheDocument();
  });

  it("surfaces the last error and offers a refresh", async () => {
    h.status.status = {
      status_data: { last_error: "token decryption failed; re-pair to fix" },
    };
    render(<KeeperSecuritySetup />);
    expect(screen.getByText("Error")).toBeInTheDocument();
    expect(
      screen.getByText("token decryption failed; re-pair to fix"),
    ).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: /Refresh status/ }),
    );
    expect(h.status.fetchStatus).toHaveBeenCalledOnce();
  });

  it("asks for confirmation before disconnecting", async () => {
    render(<KeeperSecuritySetup />);
    await userEvent.click(screen.getByRole("button", { name: /^Disconnect$/ }));
    expect(h.disconnect).not.toHaveBeenCalled();
    expect(screen.getByText("Disconnect Keeper?")).toBeInTheDocument();
    expect(
      screen.getByText(/removes the stored Keeper configuration/),
    ).toBeInTheDocument();

    await userEvent.click(
      screen.getAllByRole("button", { name: "Disconnect" }).at(-1)!,
    );
    expect(h.disconnect).toHaveBeenCalledOnce();
  });

  it("can be cancelled without disconnecting", async () => {
    render(<KeeperSecuritySetup />);
    await userEvent.click(screen.getByRole("button", { name: /^Disconnect$/ }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(h.disconnect).not.toHaveBeenCalled();
  });
});
