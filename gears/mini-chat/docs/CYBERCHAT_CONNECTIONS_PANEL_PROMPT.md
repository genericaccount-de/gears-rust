# LLM Implementation Prompt — CyberChat "Connections" Panel (MCP per-user OAuth)

> Copy everything below the line into the implementing model. It is self-contained:
> it specifies the feature, every backend endpoint, request/response shapes, the full
> OAuth handshake the UI must drive, error handling, and UX requirements. The panel
> lives in a **separate frontend repository** (CyberChat web client); the backend
> (mini-chat gear) already implements every endpoint referenced here.

---

## Role

You are a senior frontend engineer. Implement a **"Connections"** settings panel in the
CyberChat web client that lets an end user connect/disconnect their personal account to
corporate **MCP (Model Context Protocol) servers** that require interactive per-user
OAuth 2.0 (authorization-code) consent. Until a user connects such a server, its tools
are hidden from that user's chats; after connecting, the tools become available.

Use the existing CyberChat stack and conventions (framework, design system, auth/session
handling, HTTP client, i18n, state management). Do **not** introduce a new HTTP client or
auth mechanism — reuse whatever already attaches the platform bearer token to requests.

## Background you need

- Each MCP server is registered centrally by an admin. Some servers use machine auth
  (no user action needed); others use **interactive OAuth** and require each user to grant
  consent once, in their browser.
- The backend never exposes secrets. For interactive OAuth it only orchestrates the
  handshake with the gateway (OAGW), which owns dynamic client registration, PKCE, the
  CSRF `state`, the token exchange, and the per-user token store. The frontend only:
  1. asks the backend to **begin** a connection (gets an `authorization_url` + `state`),
  2. sends the user's browser to that URL,
  3. captures the `code` + `state` from the OAuth redirect callback,
  4. asks the backend to **complete** the connection with `{ state, code }`,
  5. shows/refreshes **status**, and offers **disconnect**.

## API — base, auth, format

- **Base path**: all endpoints are under the mini-chat gear API base, versioned `v1`.
  Treat the base as configurable (e.g. `${MINI_CHAT_BASE}` → typically `/mini-chat`).
  Full path example: `POST ${MINI_CHAT_BASE}/v1/mcp-servers/{id}/connection:authorize`.
- **Auth**: send the same platform bearer token used by all other CyberChat API calls
  (`Authorization: Bearer <token>`). All endpoints require an authenticated, licensed
  (`ai_chat`) user. `{id}` is the MCP server UUID.
- **Content type**: `application/json` for request/response bodies (except `204` responses,
  which have no body).
- **Errors**: RFC 9457 `application/problem+json`. Handle at least:
  `401` (re-auth), `403` (`insufficient_permissions` / `feature_not_licensed`),
  `404` (server not found), `400` (`invalid_request`, e.g. server is not an
  interactive-OAuth server or has no provisioned upstream), `502`
  (`mcp_server_unavailable` — gateway/upstream problem; show retry).

## Endpoints

### 1. List MCP servers (discover which ones need a connection)

```
GET ${MINI_CHAT_BASE}/v1/mcp-servers
200 OK → { "items": McpServerInfo[] }
```

`McpServerInfo`:

```jsonc
{
  "id": "uuid",
  "name": "GitHub Tools",
  "description": "Search issues, PRs, and repos",
  "enabled": true,
  "auto_attach": false,
  "priority": 20,
  "source": "config",            // "config" | "hub" | "api"
  "trust_level": "trusted",      // "trusted" | "restricted" | "untrusted"
  "health_status": "healthy",    // "unknown" | "healthy" | "degraded" | "unhealthy"
  "requires_user_connection": true, // <-- KEY: true = interactive OAuth, show Connect UI
  "last_refreshed_at": "2026-01-01T00:00:00Z" // optional (RFC 3339)
}
```

The Connections panel MUST list only servers where `requires_user_connection === true`.
(Other servers need no user action and must not appear in this panel.)

### 2. Get the caller's connection status for a server (live)

```
GET ${MINI_CHAT_BASE}/v1/mcp-servers/{id}/connection
200 OK → { "connected": boolean, "expires_at_unix": number | null }
```

- This is a **live** check against the gateway (not cached) — safe to call to render the
  panel and to refresh right after connecting/disconnecting.
- `expires_at_unix` (when present) is the access-token expiry in Unix seconds; you may show
  it as "connected, renews automatically" — the backend/gateway refreshes tokens silently.

### 3. Begin a connection (start the OAuth handshake)

```
POST ${MINI_CHAT_BASE}/v1/mcp-servers/{id}/connection:authorize
Body: { "redirect_uri": "https://<cyberchat-host>/mcp/oauth/callback" }
200 OK → { "authorization_url": "https://auth.example.com/authorize?...", "state": "opaque-csrf-string" }
```

- `redirect_uri` MUST be an absolute URL to a CyberChat route you control (the OAuth
  callback page). It must be pre-registered/allowed for the target authorization server;
  coordinate the exact value with the deployment. Use a single stable callback route.
- Persist the returned `state` (see handshake below). Then navigate the user's browser to
  `authorization_url`.

### 4. Complete a connection (exchange the callback result)

```
POST ${MINI_CHAT_BASE}/v1/mcp-connections:complete
Body: { "state": "<from step 3, echoed back on the callback>", "code": "<from the callback query>" }
204 No Content
```

- Note this endpoint is **not** server-scoped — the `state` identifies the pending
  authorization. Send exactly the `state` you received in step 3 and the `code` from the
  OAuth redirect.

### 5. Disconnect (revoke the caller's token)

```
DELETE ${MINI_CHAT_BASE}/v1/mcp-servers/{id}/connection
204 No Content
```

## The connection handshake (frontend flow)

Implement a popup-based flow (preferred) or a full-page redirect flow. Popup keeps the
panel state intact.

**Connect (popup variant):**

1. User clicks **Connect** on a server row (`server.id`).
2. `POST .../{id}/connection:authorize` with `{ redirect_uri }` where `redirect_uri` is your
   fixed callback route, e.g. `https://<host>/mcp/oauth/callback`.
3. Store a mapping so the callback can correlate: save `{ state → server.id }` in
   `sessionStorage` (and optionally the `code_flow` origin). Never trust `state` you didn't
   originate — reject unknown `state` on the callback.
4. Open `authorization_url` in a popup window (`window.open(authorization_url, "mcp_oauth", ...)`).
   Keep a reference to the popup.
5. The authorization server redirects the popup to
   `${redirect_uri}?code=<code>&state=<state>` (or `?error=...&error_description=...`).
6. The **callback page** (`/mcp/oauth/callback`):
   - parses `code`, `state`, `error` from `window.location.search`;
   - if `error` present → post the failure back to the opener and close;
   - looks up `state` in `sessionStorage` to confirm it is one we started; if unknown →
     abort with a CSRF error;
   - `POST .../mcp-connections:complete` with `{ state, code }`;
   - on `204` → signal success to the opener window (e.g. `window.opener.postMessage(...)`)
     and `window.close()`.
7. The panel (opener) receives the success message, clears the stored `state`, and
   **re-fetches status** for that server (`GET .../{id}/connection`) to flip the row to
   "Connected".

**Full-page redirect variant** (if popups are undesirable): same steps, but navigate the
whole tab to `authorization_url`, and on the callback route complete the exchange, then
route back to the Connections panel and refresh status. Persist any panel context you need
across the redirect in `sessionStorage`.

**Disconnect:**

1. User clicks **Disconnect** → `DELETE .../{id}/connection`.
2. On `204`, re-fetch status; flip the row to "Not connected".
3. Optionally confirm with a dialog ("Tools from this server will stop working in your chats").

## UX requirements

- **Panel content**: a list of connectable servers (only `requires_user_connection === true`).
  Each row shows: `name`, `description`, a status badge (Connected / Not connected), and a
  primary action (Connect / Disconnect). Optionally surface `health_status` (e.g. a warning
  chip when `unhealthy`/`degraded`) — a server can be healthy but still not connected by you.
- **Loading & optimistic state**: show spinners on the row during begin/complete/revoke;
  disable the button while a handshake is in flight; guard against double-clicks.
- **Status source of truth**: always reconcile with `GET .../{id}/connection` after any
  mutation rather than assuming success flips the badge.
- **Propagation note**: the status endpoint reflects the connection immediately, but a
  freshly connected server's tools may take up to ~30s to appear in an active chat (the
  chat-time tool resolver caches per-user connection state briefly). Consider a subtle
  hint ("Tools will be available shortly") after connecting.
- **Empty state**: if no servers require a connection, show a friendly empty state.
- **Errors**: map `502 mcp_server_unavailable` to a retryable "Service temporarily
  unavailable" message; `403` to "You don't have permission / feature not enabled";
  `400` to "This server can't be connected" (misconfigured/non-interactive); popup blocked
  → instruct the user to allow popups or offer the redirect fallback.
- **Security**: validate `state` on the callback (must match one you initiated); never log
  `code`; only ever send `code`/`state` to the `complete` endpoint over the authenticated
  session.

## Acceptance criteria

- The panel lists only interactive-OAuth servers and shows each one's live connection
  status.
- A user can connect a server end-to-end (begin → browser consent → callback → complete)
  and see the badge flip to Connected without a manual page reload.
- A user can disconnect and see the badge flip to Not connected.
- CSRF `state` is generated by the backend, round-tripped unchanged, validated on the
  callback, and cleared after use.
- All backend error statuses render actionable, localized messages; in-flight actions are
  guarded against duplicate submission.
- No secrets, tokens, or authorization codes are persisted client-side beyond the transient
  `state` needed to correlate the callback.

## Quick reference (verb / path / body / response)

| # | Verb | Path (under `${MINI_CHAT_BASE}`) | Request body | Success |
|---|------|-----------------------------------|--------------|---------|
| 1 | GET | `/v1/mcp-servers` | — | `200 { items: McpServerInfo[] }` |
| 2 | GET | `/v1/mcp-servers/{id}/connection` | — | `200 { connected, expires_at_unix? }` |
| 3 | POST | `/v1/mcp-servers/{id}/connection:authorize` | `{ redirect_uri }` | `200 { authorization_url, state }` |
| 4 | POST | `/v1/mcp-connections:complete` | `{ state, code }` | `204` |
| 5 | DELETE | `/v1/mcp-servers/{id}/connection` | — | `204` |
