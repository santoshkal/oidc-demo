# CODE-FLOW.md — How the Code Interacts from `main.go`

## 1. Entry: `main.go:1`

```go
func main() { cmd.Execute() }
```
`main.go` does **nothing** else. It delegates to `cmd.Execute()` and exits with code 1 on error, printing via `os.Stderr`. All behavior lives in `cmd/` — this keeps `main` trivial and testable.

## 2. Command Tree Wiring: `cmd/root.go`

`rootCmd = &cobra.Command{Use:"oidc-demo", SilenceUsage:true, SilenceErrors:true}`

* `init()` registers **groups before commands** (`AddGroup` → `AddCommand`), as cobra requires.
* Groups: `provider` (serve), `oauth` (OAuth2), `oidc` (OIDC).
* Global `PersistentFlags: --verbose` — inherited by every subcommand.
* Helper `verbose(cmd, ...)` reads `PersistentFlags` and writes to `cmd.ErrOrStderr()`.

```
oidc-demo (root)
├── serve                        — internal/provider mock IdP
├── oauth
│   ├── authorize                — Auth Code + PKCE → token exchange
│   ├── token                    — manual code → token exchange
│   ├── client-credentials       — machine-to-machine
│   └── verify                   — access_token JWKS verify
└── oidc
    ├── login                    — discovery + PKCE + id_token verify + userinfo
    ├── verify                   — id_token verify via go-oidc
    └── userinfo                 — userinfo via go-oidc
```

All commands use **`RunE` (not `Run`)**, **`cmd.OutOrStdout()` / `cmd.ErrOrStderr()`** (not `os.Stdout`), and **`Args` validators** (`NoArgs`) — per the cobra skill rules. Each `Execute()` builds on the same tree; tests must recreate the tree per test.

## 3. Mock Provider: `internal/provider/server.go` + `internal/token/keys.go`

### Key Generation — `internal/token/keys.go:23`

```go
kp, _ := token.GenerateKeyPair() // 2048-bit RSA, kid="demo-kid-1"
jwks := kp.JWKS()                  // jose.JSONWebKeySet with RS256
kp.SignClaims(claims)             // jwt.NewWithClaims + header kid → SignedString
```

* `GenerateKeyPair` creates one RSA key at server start; `JWKS()` exposes the public part at `GET /jwks`.
* `NewAccessToken` / `NewIDToken` mint JWTs with `iss`, `aud`, `exp` (1h), `iat`, `jti`, plus `scope`/`client_id` or `email`/`name`/`nonce`.
* PKCE helpers: `GenerateVerifier` (32 random bytes, base64url), `ChallengeS256` (SHA256).

### Server — `internal/provider/server.go:18`

```go
srv, _ := provider.New("http://localhost:8085") // generates KeyPair
http.ListenAndServe(":8085", srv.Handler())
```

`Server.Handler()` returns a `ServeMux` with:

| Endpoint | Method | Role |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC Discovery doc (issuer, auth/token/userinfo/jwks URIs) |
| `/jwks` | GET | `jose.JSONWebKeySet` JSON |
| `/authorize` | GET | Validates `client_id`, `redirect_uri`, `response_type=code`; generates `code` (SHA256 of nano time), stores `codeEntry{challenge, nonce, scope, subject}` 5m TTL, `302` redirect to `redirect_uri?code=...&state=...` |
| `/token` | POST | Dispatches by `grant_type`: `authorization_code` (PKCE verify, mint `access_token` [+ `id_token` if `scope` contains `openid`]) or `client_credentials` (mint `access_token`) |
| `/userinfo` | GET | `Authorization: Bearer <access_token>` → verify JWT signature via RSA public key → return `{sub, email, name, email_verified}` |

In-memory `map[string]codeEntry` guarded by `sync.Mutex`; codes are single-use (deleted on exchange).

## 4. Data Path — OAuth2 `oauth authorize`

`cmd/oauth.go:newOAuthAuthorizeCmd` — **demonstrates OAuth2 = authorization only**

```
User runs: oidc-demo oauth authorize --provider http://localhost:8085 --port 8086
  │
  ├─ 4a. Generate PKCE: verifier → challenge = BASE64URL(SHA256(verifier))      [token/keys.go]
  ├─ 4b. Build oauth2.Config{AuthURL, TokenURL, RedirectURL=:8086/callback}     [golang.org/x/oauth2]
  ├─ 4c. authURL = Config.AuthCodeURL(state, S256ChallengeOption(verifier))      // adds code_challenge
  ├─ 4d. Print authURL → user opens browser → GET /authorize?code_challenge=...
  │       provider stores codeEntry{challenge} → 302 → http://localhost:8086/callback?code=...
  ├─ 4e. Local callback server: mux.HandleFunc("/callback") captures ?code, validates state, closes server
  ├─ 4f. Config.Exchange(ctx, code, VerifierOption(verifier))                   // POST /token grant_type=authorization_code&code_verifier=
  │       provider: verify PKCE (SHA256(verifier)==challenge), delete code, mint access_token via token.NewAccessToken
  └─ 4g. Print JSON {access_token, token_type:Bearer, expiry} + note "NO id_token — use oidc login"
```

`oauth token` is the same exchange step manually via `http.PostForm`; `oauth client-credentials` posts `grant_type=client_credentials`; `oauth verify` fetches `GET /jwks`, builds `jose.JSONWebKeySet`, `jwt.ParseWithClaims` with keyfunc matching `kid`.

## 5. Data Path — OIDC `oidc login`

`cmd/oidc.go:newOIDCLoginCmd` — **demonstrates OIDC = OAuth2 + identity, using go-oidc**

```
User runs: oidc-demo oidc login --provider http://localhost:8085 --port 8087
  │
  ├─ 5a. Discovery: oidc.NewProvider(ctx, issuer)                               [coreos/go-oidc/v3]
  │       GET /.well-known/openid-configuration → provider.Claims(&{AuthURL, TokenURL, JWKS URI})
  ├─ 5b. verifierJWT = provider.Verifier(&oidc.Config{ClientID})                // remote JWKS verifier
  ├─ 5c. Generate PKCE verifier, build oauth2.Config with discovered endpoints
  ├─ 5d. authURL = Config.AuthCodeURL(state, S256ChallengeOption(verifier), nonce)
  ├─ 5e. Callback server on :8087 captures code (same as 4e)
  ├─ 5f. Exchange: tok, _ = oauth2.Config.Exchange(ctx, code, VerifierOption(verifier))
  │       POST /token → provider mints access_token + id_token (because scope has openid, includes nonce)
  │       tok.Extra("id_token") extracts raw JWT string
  ├─ 5g. Verify id_token: verifierJWT.Verify(ctx, rawIDToken)                  [go-oidc]
  │       Fetches GET /jwks → caches → verifies RS256 signature, checks iss==issuer, aud==clientID, exp, iat, nonce
  │       idTok.Claims(&map) → verified claims {sub, email, name, nonce}
  └─ 5h. UserInfo: provider.UserInfo(ctx, StaticTokenSource(tok))               [go-oidc]
          GET /userinfo with Authorization: Bearer <access_token> → provider verifies access_token → returns userinfo JSON
```

`oidc verify` does `NewProvider` + `Verifier.Verify` alone; `oidc userinfo` does `Provider.UserInfo` with fallback manual `GET /userinfo`.

## 6. Serve Command: `cmd/serve.go`

```go
issuer := fmt.Sprintf("http://localhost:%d", port)
srv, _ := provider.New(issuer)
http.Server{Addr: ":"+port, Handler: srv.Handler()}.ListenAndServe()
```

Prints `issuer`, `discovery` and `jwks` URLs to `cmd.OutOrStdout()`. Blocking call; `Ctrl+C` stops. No `PersistentPreRunE` needed — stateless.

## 7. Error & Output Conventions

* Every command: `SilenceUsage:true` → usage not printed on runtime errors; `SilenceErrors:true` → `main.go` formats `Error: ...`.
* Output via `cmd.OutOrStdout()` → testable with `SetOut(buf)` + `SetArgs`.
* JSON output via `printJSON(cmd, v)` → `json.Encoder` with indent to `OutOrStdout`.

## 8. Library Seams (why these libraries)

* **cobra** owns the tree; **pflag** owns flags. No viper here (no config file layer).
* **golang.org/x/oauth2** owns `AuthCodeURL` / `Exchange` and PKCE options (`S256ChallengeOption`, `VerifierOption`) — it knows how to add `code_challenge`/`code_verifier` params.
* **coreos/go-oidc** owns discovery, JWKS caching, `id_token` verification (`Verify` checks signature + iss/aud/exp/nonce), and `UserInfo`.
* **golang-jwt/jwt** + **go-jose** own local JWT minting and JWKS serialization for the mock IdP.

Swap any real IdP by changing `--provider` — client code is provider-agnostic thanks to discovery.
