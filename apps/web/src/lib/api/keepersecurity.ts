// Keeper Secrets Manager connection status, read from the gateway.
//
// There is no record picker: a Keeper secret is addressed by a
// `keeper://<record-uid>/field/<name>` reference the user supplies, so the only
// thing the dashboard needs from the gateway is whether Keeper is connected.
import { getGatewayApiUrl } from "@/hooks/use-vault-status";
import { getGatewayFetchOptions } from "@/lib/gateway-auth";

export interface KeeperSecurityConnectionStatus {
  connected: boolean;
}

export const getStatus = async (): Promise<KeeperSecurityConnectionStatus> => {
  const { headers, credentials } = await getGatewayFetchOptions();
  const resp = await fetch(
    `${getGatewayApiUrl()}/v1/vault/keepersecurity/status`,
    { headers, credentials },
  );
  if (!resp.ok) {
    const data = (await resp.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error ?? `Request failed (${resp.status})`);
  }
  return resp.json() as Promise<KeeperSecurityConnectionStatus>;
};
