"use client";

import { useState } from "react";
import {
  Unlink,
  Link as LinkIcon,
  AlertCircle,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@onecli/ui/components/alert-dialog";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import { Label } from "@onecli/ui/components/label";
import { Skeleton } from "@onecli/ui/components/skeleton";
import { SecretInput } from "@/components/secret-input";
import {
  useVaultStatus,
  useVaultDisconnect,
  type KeeperSecurityStatusData,
} from "@/hooks/use-vault-status";
import { useKeeperSecurityPair } from "@/hooks/use-keepersecurity";

export const KeeperSecuritySetup = () => {
  const { status, loading, isPaired, isReady, fetchStatus } =
    useVaultStatus<KeeperSecurityStatusData>("keepersecurity");
  const { pair, pairing } = useKeeperSecurityPair(fetchStatus);
  const { disconnect, disconnecting } = useVaultDisconnect(
    fetchStatus,
    "keepersecurity",
  );
  const [token, setToken] = useState("");

  const handlePair = async () => {
    const success = await pair(token);
    if (success) setToken("");
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-36" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-9 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (isPaired) {
    const lastError = status?.status_data?.last_error ?? null;
    const hasError = !!lastError;

    return (
      <div className="space-y-6">
        {/* Connection status */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Connection</CardTitle>
              <Badge
                variant="outline"
                className={
                  hasError
                    ? "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400"
                    : "border-brand/20 bg-brand/5 text-brand dark:border-brand/30 dark:bg-brand/10"
                }
              >
                <span
                  className={`mr-1.5 inline-block size-1.5 rounded-full ${hasError ? "bg-red-500" : "bg-brand"}`}
                />
                {hasError ? "Error" : isReady ? "Connected" : "Paired"}
              </Badge>
            </div>
            <CardDescription>
              Pick Keeper as the value source when adding a secret and give it a{" "}
              <code>keeper://</code> reference. The value is resolved on-demand;
              nothing is stored on the server.
            </CardDescription>
          </CardHeader>
          {hasError && (
            <CardContent>
              <div className="bg-destructive/10 text-destructive flex items-start gap-2 rounded-md border border-red-200 p-3 text-sm dark:border-red-900">
                <AlertCircle className="mt-0.5 size-4 shrink-0" />
                <div className="grid gap-1.5">
                  <span>{lastError}</span>
                  <button
                    type="button"
                    onClick={fetchStatus}
                    className="text-muted-foreground hover:text-foreground flex w-fit items-center gap-1 text-xs underline-offset-2 hover:underline"
                  >
                    <RefreshCw className="size-3" />
                    Refresh status
                  </button>
                </div>
              </div>
            </CardContent>
          )}
        </Card>

        {/* Danger zone */}
        <Card>
          <CardHeader>
            <CardTitle>Disconnect</CardTitle>
            <CardDescription>
              Remove the connection to Keeper. Secrets that source their value
              from Keeper will stop resolving until you reconnect.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" className="w-fit" size="sm">
                  <Unlink className="size-3.5" />
                  Disconnect
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Disconnect Keeper?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This removes the stored Keeper configuration. Secrets will
                    no longer be resolved until you reconnect.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    variant="destructive"
                    onClick={disconnect}
                    disabled={disconnecting}
                  >
                    {disconnecting ? "Disconnecting..." : "Disconnect"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Not paired — connect form
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Keeper Security</CardTitle>
        <CardDescription>
          Paste a one-time token or a Secrets Manager configuration to resolve
          secrets on-demand.{" "}
          {/* TODO: Add a link of keepersecurity onecli gitbook docs link below */}
          <a
            href="https://docs.keeper.io/keeperpam/secrets-manager/integrations"
            target="_blank"
            rel="noopener noreferrer"
            className="text-foreground inline-flex items-center gap-0.5 underline underline-offset-2 hover:no-underline"
          >
            Setup guide
            <ExternalLink className="size-3" />
          </a>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="keepersecurity-token">
            One-time token or configuration
          </Label>
          <SecretInput
            id="keepersecurity-token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="US:... or a base64 / JSON config"
          />
          <p className="text-muted-foreground text-xs">
            Create a Secrets Manager application in Keeper, share the records
            you need with it, and generate a one-time token. The token is used
            once; only the resulting configuration is stored, encrypted.
          </p>
        </div>
        <Button
          onClick={handlePair}
          loading={pairing}
          disabled={!token.trim()}
          className="w-fit"
        >
          <LinkIcon className="size-3.5" />
          {pairing ? "Connecting..." : "Connect Keeper Security"}
        </Button>
      </CardContent>
    </Card>
  );
};
