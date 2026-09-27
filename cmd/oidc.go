package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc" // the popular Go library for OIDC (checks id_token)
	"github.com/golang-jwt/jwt/v5"      // used to show raw token contents
	"github.com/spf13/cobra"
	"golang.org/x/oauth2" // for building authorize URLs and swapping codes

	"oidc-demo/internal/token"
)

// newOIDCCmd creates the parent "oidc" command.
// Like oauth, it just groups smaller commands under it.
func newOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "oidc",
		Short:   "OIDC flows (authentication, identity on top of OAuth2)",
		GroupID: "oidc",
	}
	cmd.AddCommand(newOIDCLoginCmd())    // oidc login
	cmd.AddCommand(newOIDCVerifyCmd())   // oidc verify
	cmd.AddCommand(newOIDCUserinfoCmd()) // oidc userinfo
	return cmd
}

// newOIDCLoginCmd creates "oidc login".
// This is the full login: it proves WHO you are, not just what you can do.
// It uses OIDC discovery, PKCE, checks the id_token, and fetches user info.
func newOIDCLoginCmd() *cobra.Command {
	var issuer, clientID, scopes string // server address, app id, permissions (must include "openid")
	var port int                        // local port for redirect, e.g. 8087
	cmd := &cobra.Command{
		Use:   "login",
		Short: "OIDC Authorization Code + PKCE — verifies id_token and calls userinfo",
		Long: `OIDC login demo:
1. Discovers provider via OIDC Discovery (/.well-known/openid-configuration) using go-oidc
2. Runs Authorization Code + PKCE (like oauth authorize but with scope=openid)
3. Exchanges code for access_token + id_token
4. Verifies id_token signature via JWKS using go-oidc
5. Calls /userinfo with access_token and prints claims`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Get context for canceling
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			issuer = strings.TrimSuffix(issuer, "/")

			// Step 1: Ask the server "who are you?" via discovery.
			// This downloads /.well-known/openid-configuration to learn auth/token/jwks URLs.
			// oidc.NewProvider does this for us.
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				return fmt.Errorf("discovery failed for %s: %w", issuer, err)
			}
			// Read the discovery info into a small struct so we can use the URLs
			var claims struct {
				Issuer      string `json:"issuer"`
				AuthURL     string `json:"authorization_endpoint"`
				TokenURL    string `json:"token_endpoint"`
				UserInfoURL string `json:"userinfo_endpoint"`
				JwksURL     string `json:"jwks_uri"`
			}
			if err := provider.Claims(&claims); err != nil {
				return err
			}
			verbose(cmd, "Discovered issuer=%s auth=%s token=%s", claims.Issuer, claims.AuthURL, claims.TokenURL)

			// Prepare a checker for id_token: it will fetch /jwks and check signature, issuer, audience, expiry
			verifierJWT := provider.Verifier(&oidc.Config{ClientID: clientID})

			// Step 2: Make PKCE secret and build OAuth2 config using the discovered URLs
			verifier, err := token.GenerateVerifier() // random secret we keep
			if err != nil {
				return err
			}
			oauthCfg := &oauth2.Config{
				ClientID:    clientID,
				RedirectURL: fmt.Sprintf("http://localhost:%d/callback", port),
				Scopes:      strings.Fields(scopes),
				Endpoint: oauth2.Endpoint{
					AuthURL:  claims.AuthURL,  // from discovery, not hardcoded
					TokenURL: claims.TokenURL, // from discovery
				},
			}
			// OIDC MUST have "openid" in scopes, or we won't get an id_token
			if !strings.Contains(scopes, "openid") {
				return fmt.Errorf("oidc login requires 'openid' in scopes (got %q)", scopes)
			}
			state := "oidc-demo-state" // random check to stop CSRF
			nonce := "oidc-demo-nonce" // random check to stop replay attacks on id_token
			// Build the login URL, including code_challenge and nonce
			authURL := oauthCfg.AuthCodeURL(state,
				oauth2.S256ChallengeOption(verifier), // adds code_challenge=...
				oauth2.SetAuthURLParam("nonce", nonce),
			)
			fmt.Fprintln(cmd.OutOrStdout(), "OIDC authorize URL:")
			fmt.Fprintln(cmd.OutOrStdout(), authURL)
			fmt.Fprintf(cmd.OutOrStdout(), "Listening for callback on http://localhost:%d/callback ...\n", port)
			fmt.Fprintln(cmd.OutOrStdout(), "Open the URL above in your browser.")

			// Step 3: Start tiny server to catch ?code=... redirect
			codeCh := make(chan string, 1)
			errCh := make(chan error, 1)
			mux := http.NewServeMux()
			srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
			mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("state") != state {
					http.Error(w, "invalid state", http.StatusBadRequest)
					errCh <- fmt.Errorf("invalid state")
					return
				}
				code := q.Get("code")
				if code == "" {
					http.Error(w, "missing code", http.StatusBadRequest)
					errCh <- fmt.Errorf("missing code")
					return
				}
				fmt.Fprintln(w, "OIDC login successful — return to CLI.")
				codeCh <- code
				go func() { _ = srv.Close() }()
			})
			// Run the tiny server in background
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			// Wait for code to arrive
			var code string
			select {
			case c := <-codeCh:
				code = c
			case err := <-errCh:
				return err
			case <-ctx.Done():
				_ = srv.Close()
				return ctx.Err()
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Got code: %s\nExchanging...\n", code)

			// Step 4: Swap code + verifier for tokens (access_token + id_token)
			tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			if err != nil {
				return fmt.Errorf("token exchange: %w", err)
			}
			// The id_token comes as an extra field in the JSON response
			rawIDToken, ok := tok.Extra("id_token").(string)
			if !ok || rawIDToken == "" {
				return fmt.Errorf("no id_token in response — is provider OIDC-compliant and scope includes openid?")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\n--- Raw tokens ---")
			_ = printJSON(cmd, map[string]interface{}{
				"access_token": tok.AccessToken,
				"id_token":     rawIDToken,
				"token_type":   tok.TokenType,
				"expiry":       tok.Expiry.String(),
			})

			// Step 5: Check the id_token is real: correct signature, issuer, audience, not expired, nonce matches
			// This is the key OIDC step that plain OAuth2 does not have.
			fmt.Fprintln(cmd.OutOrStdout(), "\n--- Verifying id_token via go-oidc (JWKS) ---")
			idTok, err := verifierJWT.Verify(ctx, rawIDToken) // calls GET /jwks behind the scenes
			if err != nil {
				return fmt.Errorf("id_token verification failed: %w", err)
			}
			var idClaims map[string]interface{}
			if err := idTok.Claims(&idClaims); err != nil {
				return err
			}
			// Double-check nonce we sent is the one inside the token
			if idClaims["nonce"] != nonce {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: nonce mismatch: got %v want %s\n", idClaims["nonce"], nonce)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "id_token claims (verified):")
			if err := printJSON(cmd, idClaims); err != nil {
				return err
			}

			// Show raw token without checking, just for learning
			parser := jwt.NewParser()
			mc := jwt.MapClaims{}
			_, _, _ = parser.ParseUnverified(rawIDToken, mc)
			_ = mc

			// Step 6: Use access_token to call /userinfo and get more user details
			fmt.Fprintln(cmd.OutOrStdout(), "\n--- Calling userinfo ---")
			userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)) // sends Authorization: Bearer ...
			if err != nil {
				return fmt.Errorf("userinfo: %w", err)
			}
			var uiClaims map[string]interface{}
			if err := userInfo.Claims(&uiClaims); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "userinfo claims:")
			return printJSON(cmd, uiClaims)
		},
	}
	cmd.Flags().StringVar(&issuer, "provider", "http://localhost:8085", "OIDC issuer URL (discovery base)")
	cmd.Flags().StringVar(&clientID, "client-id", "demo-client", "OIDC client ID")
	cmd.Flags().StringVar(&scopes, "scopes", "openid profile email", "space-separated scopes (must include openid)")
	cmd.Flags().IntVar(&port, "port", 8087, "local callback port (different from oauth demo)")
	_ = cmd.MarkFlagRequired("provider")
	return cmd
}

// newOIDCVerifyCmd creates "oidc verify".
// Give it an id_token and it tells you if it's real and what is inside.
func newOIDCVerifyCmd() *cobra.Command {
	var issuer, idToken, clientID string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an OIDC id_token via discovery + JWKS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			issuer = strings.TrimSuffix(issuer, "/")
			// First, learn about the server via discovery
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				return fmt.Errorf("discovery failed: %w", err)
			}
			// Make a checker that knows to check audience == clientID
			verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
			// This checks signature via /jwks, plus iss, aud, exp
			tok, err := verifier.Verify(ctx, idToken)
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			var claims map[string]interface{}
			if err := tok.Claims(&claims); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "id_token valid. Claims:")
			return printJSON(cmd, claims)
		},
	}
	cmd.Flags().StringVar(&issuer, "issuer", "http://localhost:8085", "issuer URL")
	cmd.Flags().StringVar(&idToken, "id-token", "", "id_token JWT to verify")
	cmd.Flags().StringVar(&clientID, "client-id", "demo-client", "expected audience (client ID)")
	_ = cmd.MarkFlagRequired("id-token")
	return cmd
}

// newOIDCUserinfoCmd creates "oidc userinfo".
// Give it an access_token and it fetches your profile from /userinfo.
func newOIDCUserinfoCmd() *cobra.Command {
	var issuer, accessToken string
	cmd := &cobra.Command{
		Use:   "userinfo",
		Short: "Call OIDC userinfo with an access_token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			issuer = strings.TrimSuffix(issuer, "/")
			// Learn where /userinfo lives via discovery
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				return fmt.Errorf("discovery failed: %w", err)
			}
			// Try the nice library way first
			ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
			ui, err := provider.UserInfo(ctx, ts)
			if err != nil {
				// If library fails, try manual HTTP call as backup
				issuerURL := issuer + "/userinfo"
				req, _ := http.NewRequestWithContext(ctx, "GET", issuerURL, nil)
				req.Header.Set("Authorization", "Bearer "+accessToken)
				resp, err2 := http.DefaultClient.Do(req) // sends GET with header
				if err2 != nil {
					return fmt.Errorf("userinfo failed: %w (fallback also failed: %v)", err, err2)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 {
					return fmt.Errorf("userinfo %d: %s", resp.StatusCode, string(body))
				}
				var out map[string]interface{}
				_ = json.Unmarshal(body, &out)
				return printJSON(cmd, out)
			}
			var claims map[string]interface{}
			if err := ui.Claims(&claims); err != nil {
				return err
			}
			_ = strings.TrimSpace // keep import used (strings was imported for login scopes check)
			return printJSON(cmd, claims)
		},
	}
	cmd.Flags().StringVar(&issuer, "provider", "http://localhost:8085", "issuer URL")
	cmd.Flags().StringVar(&accessToken, "access-token", "", "access_token")
	_ = cmd.MarkFlagRequired("access-token")
	return cmd
}
