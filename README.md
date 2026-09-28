# oidc-demo — OAuth2 vs OIDC in Go 1.26

Learn the difference hands-on: **OAuth2 = Authorization** (`what can the app do?`), **OIDC = Authentication** (`who is the user?`) — using the most popular Go libraries and a local mock IdP so it works offline.

---

## Core Concepts

### Actors — a story before the table

Imagine a **vault** holding a document you want. You're too busy to get it yourself, so you send **your assistant** to the building. But the building has rules: the assistant can't just walk in and grab the document — it must first get a **permission slip** from the front-office, and the front-office only prints that slip after confirming *who you are* and *what exactly the assistant is allowed to take*.

Now map that story to the players:

| Actor | Plain-English job | Analogy | In this demo |
|---|---|---|---|
| **The User** | The person who owns the data and must click "allow" | You | you, running the command |
| **Client** | Your app that wants to act *on the user's behalf* | Your assistant | the `oidc-demo` CLI |
| **Authorization Server (AS)** | Checks what the app may do, hands out the permission slip (`access_token`) | The front-office | `serve` (mock) |
| **Resource Server / API** | Holds the actual data the app wants | The vault | also `serve` in this demo |
| **Identity Provider (IdP)** | Knows *who* the user really is, issues the identity proof | The passport office | the same `serve`, OIDC side |

Three things worth spelling out:

1. **Client ≠ the thing being accessed.** It's the *app asking*, not the server that answers. Common mix-up.
2. **AS and IdP are usually the same product.** Google, Azure AD, Keycloak and our mock all play both roles — they hand out the permission slip **and** the passport. That's why the terminology blends (you'll see "Authorization Server / IdP" used interchangeably).
3. **Resource Server sits outside OIDC.** It only cares about the `access_token` permission slip; it never sees the `id_token` passport. That's why the same mock server runs both sides: one server, three hats. In real life they're separate services (e.g. Google = AS+IdP, your own API = resource server).

### The two questions

- **OAuth2 answers:** *May this app call this API on the user's behalf, and for what?* → **Authorization**
- **OIDC answers:** *Who is the user?* → **Authentication**

OIDC is a thin identity layer **on top of** OAuth2. It reuses the same flows, then adds an `id_token`.

### Scopes — what the client may do

Scopes are permission strings the client asks for. The user (or policy) decides which are granted.

| Scope | Grants |
|---|---|
| `read` / `write` | API access only — pure OAuth2 |
| `openid` | **The switch that turns OAuth2 into OIDC** |
| `profile` | name, picture, etc. |
| `email` | email + email_verified |

> No `openid` scope → **no `id_token`**, no identity. That's plain OAuth2.

### The two tokens (do not confuse them)

| Token | Answers | Format | Send to |
|---|---|---|---|
| `access_token` | *What may I do?* | JWT **or opaque** — both legal | API / userinfo |
| `id_token` | *Who am I?* | **Always a JWT** | Your app only — never to an API |

> Using an `access_token` as a login credential is a common and dangerous mistake. It is not proof of identity.

### Security helpers used in both flows

- **`state`** — random value echoed back on redirect. Stops CSRF / login-swapping.
- **`PKCE`** (RFC 7636) — client sends a hash of a secret, later proves it holds the secret. Stops code interception on public clients.
- **`nonce`** — OIDC only. Binds the `id_token` to this specific login attempt, stops replay.
- **`JWKS`** — the IdP's public keys. Let you verify JWT signatures without shared secrets.

---

## Flow 1 — OAuth2 Authorization Code + PKCE

**Goal:** get permission to call an API. No identity involved.

```
User            Client (CLI)                 Authorization Server          API
 |                  |                               |                      |
 |--run cli-------->|                               |                      |
 |                  | generate code_verifier         |                      |
 |                  | challenge = SHA256(verifier)   |                      |
 |                  |---GET /authorize?client_id---->|                      |
 |                  |    &redirect_uri &state        |                      |
 |                  |    &scope=read&write           |                      |
 |                  |    &code_challenge------------->|                      |
 |<--open browser---|                               | (user logs in &       |
 |                  |                               |  consents)            |
 |                  |<--302 redirect_uri?code=X&state---|                  |
 |                  |---POST /token------------------>|                      |
 |                  |    grant_type=authorization_code|                      |
 |                  |    code=X & code_verifier       |                      |
 |                  |    (server hashes verifier,     |                      |
 |                  |     compares to challenge)      |                      |
 |                  |<--{access_token, scope}---------|                      |
 |                  |                                                           |
 |                  |---GET /api/resource, Authorization: Bearer <at>------->|
 |                  |<--200 OK data------------------------------------------|
```

Steps in code: `cmd/oauth.go` `newOAuthAuthorizeCmd` → `token.GenerateVerifier` → `oauth2.Config.AuthCodeURL` → local callback server → `oauth2.Config.Exchange`.

**Result:** `access_token` only. **No `id_token`** — that is correct, and it is the key difference from OIDC.

Other OAuth2 flows in this demo:
- **Client Credentials** (`oauth client-credentials`) — machine-to-machine, no user, no browser. Subject is the app itself.
- **Manual exchange** (`oauth token`) — swap a code you already have, with the verifier.

---

## Flow 2 — OIDC Authorization Code + PKCE

**Goal:** the *same* flow, but with `openid` in the scope, so you get a verified identity.

```
User            Client (CLI)                    IdP                       API
 |                  |                              |                       |
 |--run login------>|                              |                       |
 |                  |---GET /.well-known/---------->|  (discovery: where are |
 |                  |   openid-configuration        |   auth/token/jwks?)    |
 |                  |<--{issuer, auth, token, jwks}--|                       |
 |                  |                              |                       |
 |                  | generate verifier + nonce     |                       |
 |                  |---GET /authorize?scope=openid profile email------------>|
 |                  |    &code_challenge &nonce----->|                       |
 |<--login & consent|                              |                       |
 |                  |<--302 ?code=X&state&----------|                       |
 |                  |---POST /token----------------->|                       |
 |                  |<--{access_token, id_token}----|                       |
 |                  |                              |                       |
 |                  |---GET /jwks (cache)---------->|  (public signing key) |
 |                  | VERIFY id_token:              |                       |
 |                  |   signature, iss, aud,        |                       |
 |                  |   exp, nonce match            |                       |
 |                  |                              |                       |
 |                  |  LOGIN SUCCESSFUL -> sub=user-123, email=...            |
 |                  |                                                           |
 |                  |---GET /userinfo, Bearer <access_token>----------------->|
 |                  |<--{sub, name, email}-----------------------------------|
```

Steps in code: `cmd/oidc.go` `newOIDCLoginCmd` → `oidc.NewProvider` (discovery) → `provider.Verifier` → `AuthCodeURL` + nonce → `Exchange` → `verifier.Verify(ctx, rawIDToken)` → `provider.UserInfo`.

**The step plain OAuth2 does not have:** verifying the `id_token`. `go-oidc` checks signature via JWKS plus `iss` (must be our issuer), `aud` (must be our client ID), `exp` (not expired), and that `nonce` matches what we sent.

---

## Differences at a glance

| | OAuth2 | OIDC |
|---|---|---|
| Purpose | Authorization | Authentication |
| Question | What may I do? | Who am I? |
| Built on | — | OAuth2 (adds a layer) |
| Scope needed | any (`read`, `write`) | **`openid`** |
| Token returned | `access_token` (JWT or opaque) | `access_token` **+ `id_token`** (always JWT) |
| Verifies identity | No | Yes — signature, `iss`, `aud`, `exp`, `nonce` |
| `nonce` | Not used | Used |
| Discovery | Not required | `/.well-known/openid-configuration` |
| Extra endpoint | — | `/userinfo` |
| Without the other | works standalone | **impossible** — needs OAuth2 |

### Observe this in the demo

| Flow | Scope | `id_token`? | `access_token`? | Proves identity? |
|---|---|---|---|---|
| `oauth authorize` | `read write` | No | Yes | No — authorization only |
| `oauth client-credentials` | `read` | No | Yes | No — machine identity |
| `oidc login` | `openid profile email` | **Yes (JWT)** | Yes | Yes — verified via JWKS |

**Key takeaway:** if you receive an `id_token`, you are doing OIDC. If not, you only have authorization.

---

## Quick Start (offline, 2 terminals)

```bash
# terminal 1 — mock IdP (Authorization Server + OIDC Provider)
make serve          # or: go run . serve --port 8085
# discovery: http://localhost:8085/.well-known/openid-configuration
# jwks:      http://localhost:8085/jwks

# terminal 2 — OAuth2 (no identity, no id_token)
go run . oauth authorize --provider http://localhost:8085 --port 8086
# → prints Authorize URL → open in browser → callback → prints access_token

# terminal 2 — OIDC (identity, has id_token + userinfo)
go run . oidc login --provider http://localhost:8085 --port 8087
# → discovery via go-oidc → PKCE → code → exchange → verify id_token via JWKS → call userinfo
```

---

## Commands

```
oidc-demo serve                                 # mock IdP
oidc-demo oauth authorize        --provider --port --scopes --client-id
oidc-demo oauth token            --provider --code --verifier --redirect-url
oidc-demo oauth client-credentials --provider --scopes
oidc-demo oauth verify           --token --jwks-url
oidc-demo oidc login             --provider --port --scopes (must include openid)
oidc-demo oidc verify            --issuer --id-token --client-id
oidc-demo oidc userinfo          --provider --access-token
```

### OAuth2 examples

```bash
# Client Credentials (machine-to-machine, no user, no browser)
go run . oauth client-credentials --provider http://localhost:8085 --scopes "read write"

# Manual code exchange (after oauth authorize prints the code)
go run . oauth token --provider http://localhost:8085 --code <code> --verifier <verifier>

# Verify an access_token via JWKS
go run . oauth verify --token <access_token> --jwks-url http://localhost:8085/jwks
```

### OIDC examples

```bash
# Full login — discovery + PKCE + id_token verification + userinfo
go run . oidc login --provider http://localhost:8085 --port 8087

# Verify an id_token offline (fetches JWKS via discovery)
go run . oidc verify --issuer http://localhost:8085 --id-token <id_token> --client-id demo-client

# Call userinfo
go run . oidc userinfo --provider http://localhost:8085 --access-token <access_token>
```

### Real IdP

Point `--provider` at any OIDC-compliant issuer (Google, Azure AD, Keycloak, Zitadel). The client code is provider-agnostic thanks to discovery:

```bash
go run . oidc login --provider https://accounts.google.com --client-id <your-id> --port 8087
```

---

## Mock IdP Endpoints

`oidc-demo serve` implements the minimum needed for both flows:

| Endpoint | Purpose |
|---|---|
| `/.well-known/openid-configuration` | OIDC Discovery — where the other URLs live |
| `/jwks` | Public keys for verifying JWT signatures |
| `/authorize` | Issues a one-time `code` and stores `state`/`nonce`/`code_challenge` |
| `/token` | Exchanges `code` (+ PKCE verifier) for tokens; also handles `client_credentials` |
| `/userinfo` | Returns the user profile for a valid `access_token` |

One RSA key pair is generated at startup; all tokens are RS256-signed with `kid: demo-kid-1`.

---

## Makefile

```bash
make help      # list all targets
make build     # build bin/oidc-demo with -trimpath and ldflags
make check     # fmt + vet + test
make cover     # coverage report
make clean     # remove bin/ and coverage files
```

---

## Project Layout

```
.
├── main.go                 # entry point — delegates to cmd.Execute()
├── cmd/
│   ├── root.go             # root command, groups, persistent flags
│   ├── serve.go            # mock IdP server
│   ├── oauth.go            # oauth authorize/token/client-credentials/verify
│   └── oidc.go             # oidc login/verify/userinfo (go-oidc)
├── internal/
│   ├── provider/server.go  # mock AS + OP: discovery, JWKS, /authorize, /token, /userinfo
│   └── token/keys.go       # RSA key, JWT sign, PKCE helpers
├── Makefile
├── oauth-oidc.md           # brief corrected overview
├── CODE-FLOW.md            # request-by-request data path from main.go
└── go.mod                  # Go 1.26
```

- **`CODE-FLOW.md`** — line-by-line data path for both flows.
- **`oauth-oidc.md`** — short conceptual summary.
