# Vault Integration

Connect an external password manager to OneCLI so the gateway can inject credentials on-demand, without storing them on the server. Three providers are supported, with two different models:

- **[Bitwarden](https://bitwarden.com)** (via the [Agent Access SDK](https://github.com/bitwarden/agent-access)) — an on-demand fallback: when no server-stored secret matches a request, the gateway asks your vault for a credential by domain.
- **[1Password](https://1password.com)** (via a Service Account) — a value source for explicit secrets: a secret can reference `op://vault/item/field` instead of storing an encrypted value, and the gateway resolves the reference at request time.
- **[Keeper Secrets Manager](https://docs.keeper.io/en/keeperpam/secrets-manager/about)** — a value source like 1Password: a secret can reference `keeper://<record-uid>/field/<name>` instead of storing an encrypted value, and the gateway resolves the reference at request time.

Most of this page covers the Bitwarden flow; see [1Password](#1password) and [Keeper Secrets Manager](#keeper-secrets-manager) below for their setup.

## How It Works

1. You pair your Bitwarden desktop app with the OneCLI gateway (one-time setup)
2. When an agent makes an HTTPS request and no server-stored secret matches, the gateway asks your Bitwarden vault for a credential
3. Bitwarden searches by domain/URI and returns the match through an encrypted channel
4. The gateway injects the credential as a header (e.g. `x-api-key` for Anthropic, `Authorization: Bearer` for others) and forwards the request
5. The credential is cached in memory for 60 seconds, then discarded

Credentials never hit disk or the database. The vault is a fallback; server-stored secrets always take priority.

## Prerequisites

- OneCLI running locally (`pnpm dev`) or via Docker
- [Bitwarden Agent Access CLI](https://github.com/bitwarden/agent-access/releases) (`aac`) installed
- A Bitwarden account with credentials stored as login items (the password field is used for injection)

## Setup

### 1. Start the `aac` listener

```bash
aac listen --psk
```

This generates a pairing code (two 64-character hex strings joined by `_`). Keep this terminal open.

### 2. Pair in the web dashboard

Open **http://localhost:10254**, pick your workspace, then go to **Connections** > **Vaults** > **Bitwarden**. Paste the pairing code and click **Connect Vault**.

The gateway establishes an encrypted Noise protocol session with your Bitwarden app through a WebSocket relay.

### 3. Test it

```bash
# Use your agent's access token
curl -x http://x:YOUR_AGENT_TOKEN@localhost:10255 https://httpbin.org/headers
```

If your Bitwarden vault has a login item with `httpbin.org` as the URI, the password will be injected as `Authorization: Bearer <password>`.

## Credential Matching

The gateway asks Bitwarden for credentials by domain. Bitwarden matches against the URI field of your vault items. The injection rule depends on the host:

| Host                | Header          | Format           |
| ------------------- | --------------- | ---------------- |
| `api.anthropic.com` | `x-api-key`     | Raw value        |
| Everything else     | `Authorization` | `Bearer <value>` |

To use this with Anthropic, store your API key as the password in a Bitwarden login item with URI `api.anthropic.com`.

## Environment Variables

| Variable              | Default                     | Description                                              |
| --------------------- | --------------------------- | -------------------------------------------------------- |
| `BITWARDEN_PROXY_URL` | `wss://ap.lesspassword.dev` | WebSocket relay for the Bitwarden Remote Access protocol |

## Session Behavior

- Sessions are restored from the database on first credential request after a gateway restart, not at startup.
- Sessions unused for 30 minutes are evicted from memory. The next request restores them from the database automatically.
- If a session can't be restored (e.g. the Bitwarden app was reinstalled), disconnect in the UI and pair again with a new code.

## 1Password

1Password connects with a [Service Account](https://developer.1password.com/docs/service-accounts/) token instead of app pairing, and it is not a hostname-matched fallback: it supplies values for secrets you explicitly point at it. A secret with an `op://vault/item/field` reference is resolved through the 1Password SDK at request time, so the value never sits in the OneCLI database.

Setup: **Connections** > **Vaults** > **1Password**, paste a Service Account token, then create secrets that reference vault items (the UI has a vault/item/field picker backed by `GET /v1/vault/onepassword/{vaults,items,fields}`).

## Keeper Secrets Manager

Keeper works like 1Password: it is not a hostname-matched fallback, it supplies values for secrets you explicitly point at it. A secret with a `keeper://<record-uid>/field/<name>` reference is resolved through the Keeper Secrets Manager SDK at request time, so the value never sits in the OneCLI database. The connection itself is stored encrypted, per workspace.

Setup:

1. In Keeper, create a Secrets Manager application dedicated to OneCLI, share the records it should read (read-only), and generate a one-time access token.
2. **Connections** > **External Vaults** > **Keeper**, paste the one-time token (or an existing Secrets Manager configuration) and connect. A one-time token is single-use: OneCLI binds it to a reusable configuration, stores only that configuration (encrypted), and discards the token.
3. Create a secret (**Custom** or **LLMs** tab), click the Keeper button next to the value field, then pick a record and a field (or choose **Enter a reference manually**). Attach the secret to an agent as for any other secret. To point an existing secret at a different field, edit it and click **Change**.

References use Keeper's [notation](https://docs.keeper.io/en/keeperpam/secrets-manager/about/keeper-notation): `keeper://<record-uid>/field/password` reads a standard field, `keeper://<record-uid>/custom_field/<label>` a custom one.

The picker (backed by `GET /v1/vault/keepersecurity/records` and `GET /v1/vault/keepersecurity/records/{recordUid}/fields`) lists the records shared with the Secrets Manager application, with their folder path, and builds the reference for you. Only titles, labels and references leave the API; field values never do. The reference always uses the record UID (titles are not unique), and the picked record and field names are saved with the secret for display. Keeper matches `field/<x>` against a field's type _or_ its label and fails when more than one field matches, so the picker addresses each field by a selector that is unique in its record (the label, else the type) and leaves out a field that has none (for example, two unlabeled `text` fields). Fields with object values, such as `keyPair` or `host`, are offered per property (`field/keyPair[0][privateKey]`). File, record-reference and one-time-code fields are not offered, nor are fields with no value.

When typing a reference by hand, copy the record UID from Keeper. A record title also works in Keeper's notation, but prefer the UID. OneCLI accepts the `field`, `custom_field` and `file` forms (a record, a selector and a name); Keeper's two-part short forms (`/title`, `/notes`, `/type`) are not accepted. The record must be shared with the Secrets Manager application.

Pairing and status are served on the provider-generic routes (`/v1/vault/keepersecurity/{pair,status}`); `pair` takes either `{ "one_time_token": "US:..." }` or `{ "ksm_config": "<base64 or JSON>" }`.

Behavior worth knowing:

- Resolved values are cached in memory for about 60 seconds, so a rotated value can lag by that long. A failed lookup is cached briefly (about 30 seconds) so a broken reference does not hammer Keeper.
- If a reference cannot be resolved (wrong record or field, record not shared, Keeper unreachable, connection removed), the gateway skips that secret and sends the request without a credential. It never falls back to another value. The reason is in the gateway log; the log records the reference, never the value. The last reference that failed is also shown on the Keeper connection page, and an agent whose request then fails upstream is told to check Keeper or reconnect it (with a link to that page), not to re-enter the key.
- If OneCLI can't use the connection, for whatever reason (the application's access expired or was revoked, its device was removed, Keeper or the internal API is unreachable, the stored configuration no longer decrypts), the connection page shows **Can't connect** with the possible reasons and the detail; if it persists, disconnect and connect again with a new configuration. OneCLI can't always tell these causes apart, so it doesn't name one. When Keeper itself refuses the application (`access_denied`), the gateway also stops serving values it cached before, and it backs off Keeper for about 60 seconds between attempts after any such failure.
- If the application is still accepted but nothing is shared with it any more (shares removed or expired), Keeper returns an empty list rather than an error; the connection page shows **No records shared**. Share the records with the application again; no reconnect is needed.
- When Keeper sets an expiry on the application's access, the connection page shows the date, and warns within a week of it. Warnings Keeper attaches to its responses are shown too.
- The Keeper connection page and its card on the Vaults tab re-check status every minute while visible and when the tab regains focus, so a revocation shows without a reload.
- If the stored configuration can no longer be decrypted (for example `SECRET_ENCRYPTION_KEY` changed), the connection reports `token decryption failed; re-pair to fix`. Connect again with a new one-time token.
- Keeper secrets are workspace-scoped; an organization-level secret has no single connection to resolve through.

## Architecture

The vault system is provider-agnostic: each provider implements the `VaultProvider` trait, and pairing/status/disconnect are served on provider-generic routes.

```
Browser ──► Gateway /v1/vault/:provider/pair   (pairing / connecting)
Agent   ──► Gateway CONNECT host:443            (credential injection)
              │
              ├─ DB secrets matched? ──► inject from DB (op:// and keeper:// values resolve via their vaults)
              └─ No match + Bitwarden paired? ──► ask Bitwarden ──► inject
```

Key files:

| File                          | Role                                                                     |
| ----------------------------- | ------------------------------------------------------------------------ |
| `vault/mod.rs`                | `VaultProvider` trait + `VaultService` orchestrator                      |
| `vault/bitwarden.rs`          | Bitwarden provider (sessions, pairing, caching)                          |
| `vault/bitwarden_db.rs`       | DB-backed identity + session storage                                     |
| `vault/onepassword.rs`        | 1Password provider (Service Account session, `op://` cache)              |
| `vault/onepassword_api.rs`    | Bridge to the Node 1Password SDK service                                 |
| `vault/keepersecurity.rs`     | Keeper provider (KSM config session, `keeper://` cache)                  |
| `vault/keepersecurity_api.rs` | Bridge to the Node Keeper Secrets Manager SDK service (resolve + picker) |
| `vault/api.rs`                | REST endpoints for pair/status/disconnect + the 1P picker                |
