"use client";

import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { getGatewayFetchOptions } from "@/lib/gateway-auth";
import { getGatewayApiUrl } from "@/hooks/use-vault-status";
import { getStatus, listFields, listRecords } from "@/lib/api/keepersecurity";
import { queryKeys } from "@/lib/api/keys";

const PROVIDER = "keepersecurity";

// Record contents change rarely within a dialog session; cache briefly so the
// picker feels instant and doesn't re-hit Keeper on every reopen.
const STALE_TIME = 60_000;

/** A one-time token looks like `US:` / `EU:` followed by url-safe base64. */
const ONE_TIME_TOKEN = /^[A-Za-z]{2,}:[\w-]+$/;

/**
 * Pair with Keeper Secrets Manager. Accepts either a one-time token (bound to a
 * reusable config server-side; the token itself is never stored) or an existing
 * KSM config (base64 or JSON).
 */
export const useKeeperSecurityPair = (fetchStatus: () => Promise<void>) => {
  const [pairing, setPairing] = useState(false);

  const pair = useCallback(
    async (input: string): Promise<boolean> => {
      const trimmed = input.trim();
      if (!trimmed) {
        toast.error("Enter a one-time token or a KSM config");
        return false;
      }
      const body = ONE_TIME_TOKEN.test(trimmed)
        ? { one_time_token: trimmed }
        : { ksm_config: trimmed };

      setPairing(true);
      try {
        const { headers, credentials } = await getGatewayFetchOptions();
        const resp = await fetch(
          `${getGatewayApiUrl()}/v1/vault/${PROVIDER}/pair`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headers },
            credentials,
            body: JSON.stringify(body),
          },
        );
        if (resp.ok) {
          toast.success("Keeper connected successfully");
          await fetchStatus();
          return true;
        }
        const data = await resp.json().catch(() => ({}));
        toast.error(data.error ?? "Pairing failed");
        return false;
      } catch {
        toast.error("Failed to connect to Keeper");
        return false;
      } finally {
        setPairing(false);
      }
    },
    [fetchStatus],
  );

  return { pair, pairing };
};

/**
 * Whether Keeper is connected for this workspace. Deduped across every mounted
 * SecretDialog (one query key), and gated by `enabled` so closed dialogs don't
 * poll the gateway.
 */
export const useKeeperSecurityReady = (enabled: boolean) => {
  const query = useQuery({
    queryKey: queryKeys.keepersecurity.status(),
    queryFn: getStatus,
    enabled,
    staleTime: STALE_TIME,
  });
  return { isReady: query.data?.connected ?? false, ...query };
};

/** Records shared with the KSM application (picker step 1). */
export const useKeeperSecurityRecords = (enabled: boolean) =>
  useQuery({
    queryKey: queryKeys.keepersecurity.records(),
    queryFn: listRecords,
    enabled,
    staleTime: STALE_TIME,
  });

/** A record's referenceable fields (picker step 2). */
export const useKeeperSecurityFields = (recordUid: string | null) =>
  useQuery({
    queryKey: queryKeys.keepersecurity.fields(recordUid ?? ""),
    queryFn: () => listFields(recordUid as string),
    enabled: !!recordUid,
    staleTime: STALE_TIME,
  });
