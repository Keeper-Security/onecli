// @vitest-environment jsdom
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FOCUS_HANDOFF_MS, SecretDialog } from "./secret-dialog";
import type { SecretActions } from "./types";

// The Keeper mode of the secret dialog: a reference in place of a pasted value.
// The unit here is what the dialog offers and what it hands to the save
// actions. The server graph stays out (see secret-dialog.test.tsx).
const keepersecurity = vi.hoisted(() => ({ ready: true }));

vi.mock("@/lib/actions/secrets", () => ({ updateSecret: vi.fn() }));
vi.mock("@/hooks/use-keepersecurity", () => ({
  useKeeperSecurityReady: () => ({ isReady: keepersecurity.ready }),
}));
vi.mock("@/hooks/use-onepassword-picker", () => ({
  useOnePasswordReady: () => false,
}));
vi.mock("./onepassword-picker-dialog", () => ({
  OnePasswordPickerDialog: () => null,
}));
vi.mock("@/hooks/use-invalidate-cache", () => ({
  useInvalidateGatewayCache: () => vi.fn(),
}));
vi.mock("@/hooks/use-copy-to-clipboard", () => ({
  useCopyToClipboard: () => ({ copied: false, copy: vi.fn() }),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

window.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const REF = "keeper://qnXEdBFVi2Gm1UFehAsjew/field/password";
const REF_PLACEHOLDER = "keeper://<record-uid>/field/password";
const VALUE_PLACEHOLDER = "Paste your API key / Secret";

// Wait out the focus handoff so a paste doesn't land in the wrong field (the
// same reason secret-dialog.test.tsx does).
const renderDialog = async (
  props: Partial<Parameters<typeof SecretDialog>[0]>,
) => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  const view = render(
    <SecretDialog open onOpenChange={() => {}} {...props} />,
    { wrapper },
  );
  await act(
    () =>
      new Promise<void>((resolve) =>
        setTimeout(resolve, FOCUS_HANDOFF_MS + 20),
      ),
  );
  return view;
};

const createSpy = () =>
  vi.fn<SecretActions["createSecret"]>().mockResolvedValue({ id: "sec-1" });
const updateSpy = () =>
  vi.fn<SecretActions["updateSecret"]>().mockResolvedValue();
const actions = (overrides: Partial<SecretActions>): SecretActions => ({
  createSecret: createSpy(),
  deleteSecret: vi.fn<SecretActions["deleteSecret"]>(),
  updateSecret: updateSpy(),
  ...overrides,
});

const pasteInto = async (placeholder: string, text: string) => {
  await userEvent.click(screen.getByPlaceholderText(placeholder));
  await userEvent.paste(text);
};

const keepersecurityButton = () =>
  screen.queryByRole("button", { name: "Use a Keeper reference" });
const useKeeperSecurity = () =>
  userEvent.click(keepersecurityButton() as HTMLElement);
const addConnection = () =>
  screen.getByRole("button", { name: "Add connection" });

/** A generic connection's name and host, leaving the value to the test. */
const fillNameAndHost = async () => {
  await pasteInto("e.g. Airtable", "GitHub");
  await pasteInto("api.example.com", "api.github.com");
};

/** An existing secret, for edit mode. */
const keepersecuritySecret = {
  id: "s1",
  name: "GitHub",
  type: "generic",
  valueSource: "keepersecurity",
  keepersecurityRef: REF,
  hostPattern: "api.github.com",
  pathPattern: null,
  injectionConfig: {
    headerName: "Authorization",
    valueFormat: "Bearer {value}",
  },
  metadata: null,
};

beforeEach(() => {
  keepersecurity.ready = true;
});
afterEach(() => vi.clearAllMocks());

describe("SecretDialog: Keeper reference mode", () => {
  describe("availability", () => {
    it("offers the Keeper button when Keeper is connected", async () => {
      await renderDialog({ defaultType: "generic" });
      expect(keepersecurityButton()).toBeInTheDocument();
    });

    it("hides the Keeper button when Keeper is not connected", async () => {
      keepersecurity.ready = false;
      await renderDialog({ defaultType: "generic" });
      expect(keepersecurityButton()).not.toBeInTheDocument();
    });
  });

  describe("switching the value field", () => {
    it("swaps the pasted value for a reference field", async () => {
      await renderDialog({ defaultType: "generic" });
      expect(
        screen.getByPlaceholderText(VALUE_PLACEHOLDER),
      ).toBeInTheDocument();

      await useKeeperSecurity();

      expect(screen.getByPlaceholderText(REF_PLACEHOLDER)).toBeInTheDocument();
      expect(
        screen.queryByPlaceholderText(VALUE_PLACEHOLDER),
      ).not.toBeInTheDocument();
      expect(
        screen.getByText(/Resolved from Keeper at request time/),
      ).toBeInTheDocument();
    });

    it("lets you back out to a pasted value", async () => {
      await renderDialog({ defaultType: "generic" });
      await useKeeperSecurity();
      await userEvent.click(
        screen.getByRole("button", { name: "Remove Keeper reference" }),
      );
      expect(
        screen.getByPlaceholderText(VALUE_PLACEHOLDER),
      ).toBeInTheDocument();
      expect(
        screen.queryByPlaceholderText(REF_PLACEHOLDER),
      ).not.toBeInTheDocument();
    });

    it("describes where the value comes from, not 'paste a key'", async () => {
      await renderDialog({ defaultType: "generic" });
      expect(
        screen.getByText(/Paste an API key \/ Secret and where it goes/),
      ).toBeInTheDocument();
      await useKeeperSecurity();
      expect(
        screen.getByText("Reference a Keeper record and say where it goes."),
      ).toBeInTheDocument();
    });

    it("does not claim an Anthropic key is encrypted here when it comes from Keeper", async () => {
      await renderDialog({ defaultType: "anthropic" });
      expect(screen.getByText(/is encrypted and injected/)).toBeInTheDocument();
      await useKeeperSecurity();
      expect(
        screen.queryByText(/is encrypted and injected/),
      ).not.toBeInTheDocument();
      expect(
        screen.getByText(/fetched from Keeper when a request is made/),
      ).toBeInTheDocument();
    });
  });

  describe("validation", () => {
    it("blocks saving until the reference is well-formed", async () => {
      await renderDialog({ defaultType: "generic" });
      await fillNameAndHost();
      await useKeeperSecurity();

      // empty
      expect(addConnection()).toBeDisabled();

      // malformed: the hint turns into an error and Save stays off
      await pasteInto(REF_PLACEHOLDER, "not-a-reference");
      expect(addConnection()).toBeDisabled();
      expect(
        screen.getByText(/Use keeper:\/\/<record-uid>\/field/),
      ).toBeInTheDocument();
    });

    it.each([
      "keeper://uid",
      "keeper://uid/field",
      "op://vault/item/field",
      "https://example.com/a/b/c",
    ])("rejects %s", async (bad) => {
      await renderDialog({ defaultType: "generic" });
      await fillNameAndHost();
      await useKeeperSecurity();
      await pasteInto(REF_PLACEHOLDER, bad);
      expect(addConnection()).toBeDisabled();
    });

    it("enables saving for a valid reference", async () => {
      await renderDialog({ defaultType: "generic" });
      await fillNameAndHost();
      await useKeeperSecurity();
      await pasteInto(REF_PLACEHOLDER, REF);
      expect(addConnection()).toBeEnabled();
    });
  });

  describe("create", () => {
    it("saves the reference and no value", async () => {
      const createSecret = createSpy();
      await renderDialog({
        defaultType: "generic",
        secretActions: actions({ createSecret }),
      });
      await fillNameAndHost();
      await useKeeperSecurity();
      await pasteInto(REF_PLACEHOLDER, `  ${REF}  `);
      await userEvent.click(addConnection());

      await waitFor(() => expect(createSecret).toHaveBeenCalledTimes(1));
      const payload = createSecret.mock.calls[0]?.[0] as Record<
        string,
        unknown
      >;
      expect(payload).toMatchObject({
        name: "GitHub",
        type: "generic",
        valueSource: "keepersecurity",
        keepersecurityRef: REF, // trimmed
        hostPattern: "api.github.com",
        injectionConfig: {
          headerName: "Authorization",
          valueFormat: "Bearer {value}",
        },
      });
      expect(payload).not.toHaveProperty("value");
      expect(payload).not.toHaveProperty("opRef");
    });

    it("control: without Keeper, the pasted value is what gets saved", async () => {
      const createSecret = createSpy();
      await renderDialog({
        defaultType: "generic",
        secretActions: actions({ createSecret }),
      });
      await fillNameAndHost();
      await pasteInto(VALUE_PLACEHOLDER, "key-123");
      await userEvent.click(addConnection());

      await waitFor(() => expect(createSecret).toHaveBeenCalledTimes(1));
      const payload = createSecret.mock.calls[0]?.[0] as Record<
        string,
        unknown
      >;
      expect(payload).toMatchObject({ value: "key-123" });
      expect(payload).not.toHaveProperty("keepersecurityRef");
      expect(payload).not.toHaveProperty("valueSource");
    });

    it("saves an LLM key from Keeper without a value", async () => {
      const createSecret = createSpy();
      await renderDialog({
        defaultType: "anthropic",
        secretActions: actions({ createSecret }),
      });
      await useKeeperSecurity();
      await pasteInto(REF_PLACEHOLDER, REF);
      await userEvent.click(
        screen.getByRole("button", { name: /^Add (Secret|connection)$/ }),
      );

      await waitFor(() => expect(createSecret).toHaveBeenCalledTimes(1));
      const payload = createSecret.mock.calls[0]?.[0] as Record<
        string,
        unknown
      >;
      expect(payload).toMatchObject({
        type: "anthropic",
        valueSource: "keepersecurity",
        keepersecurityRef: REF,
      });
      expect(payload).not.toHaveProperty("value");
    });
  });

  describe("edit", () => {
    it("opens an existing Keeper secret on its reference", async () => {
      await renderDialog({ secret: keepersecuritySecret });
      expect(screen.getByPlaceholderText(REF_PLACEHOLDER)).toHaveValue(REF);
      expect(
        screen.queryByPlaceholderText(VALUE_PLACEHOLDER),
      ).not.toBeInTheDocument();
    });

    it("saves a changed reference, still as a Keeper secret", async () => {
      const updateSecret = updateSpy();
      await renderDialog({
        secret: keepersecuritySecret,
        secretActions: actions({ updateSecret }),
      });
      const field = screen.getByPlaceholderText(REF_PLACEHOLDER);
      await userEvent.clear(field);
      await userEvent.click(field);
      await userEvent.paste("keeper://AAAAAAAAAAAAAAAAAAAAAA/field/login");
      await userEvent.click(
        screen.getByRole("button", { name: "Save changes" }),
      );

      await waitFor(() => expect(updateSecret).toHaveBeenCalledTimes(1));
      const [id, payload] = updateSecret.mock.calls[0] as [
        string,
        Record<string, unknown>,
      ];
      expect(id).toBe("s1");
      expect(payload).toMatchObject({
        valueSource: "keepersecurity",
        keepersecurityRef: "keeper://AAAAAAAAAAAAAAAAAAAAAA/field/login",
      });
      expect(payload).not.toHaveProperty("value");
    });

    it("blocks saving an edit that empties the reference", async () => {
      await renderDialog({ secret: keepersecuritySecret });
      await userEvent.clear(screen.getByPlaceholderText(REF_PLACEHOLDER));
      expect(
        screen.getByRole("button", { name: "Save changes" }),
      ).toBeDisabled();
    });

    it("switches a Keeper secret back to a pasted value", async () => {
      const updateSecret = updateSpy();
      await renderDialog({
        secret: keepersecuritySecret,
        secretActions: actions({ updateSecret }),
      });
      await userEvent.click(
        screen.getByRole("button", { name: "Remove Keeper reference" }),
      );
      await pasteInto(VALUE_PLACEHOLDER, "now-plain");
      await userEvent.click(
        screen.getByRole("button", { name: "Save changes" }),
      );

      await waitFor(() => expect(updateSecret).toHaveBeenCalledTimes(1));
      const payload = updateSecret.mock.calls[0]?.[1] as Record<
        string,
        unknown
      >;
      expect(payload).toMatchObject({
        valueSource: "inline",
        value: "now-plain",
      });
      expect(payload).not.toHaveProperty("keepersecurityRef");
    });

    it("does not mistake a non-Keeper secret for one", async () => {
      await renderDialog({
        secret: {
          ...keepersecuritySecret,
          valueSource: "inline",
          keepersecurityRef: null,
        },
      });
      expect(
        screen.queryByPlaceholderText(REF_PLACEHOLDER),
      ).not.toBeInTheDocument();
    });
  });
});
