package cmd

import (
	"context"       // lets us cancel work if needed
	"encoding/json" // to read and write JSON
	"fmt"
	"io"       // to read response bodies
	"net/http" // to make web requests
	"net/url"  // to build form data
	"strings"  // to split and join text

	"github.com/go-jose/go-jose/v4" // to read public keys (JWKS)
	"github.com/golang-jwt/jwt/v5"  // to check JWT signatures
	"github.com/spf13/cobra"        // to build commands
	"golang.org/x/oauth2"           // the popular Go library for OAuth2

	"oidc-demo/internal/token" // our helpers for PKCE and token creation
)

// newOAuthCmd creates the parent "oauth" command.
// It does not do work itself; it just holds 4 smaller commands inside it.
func newOAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "oauth",
		Short:   "OAuth2 flows (authorization, no identity)",
		GroupID: "oauth", // shows under "OAuth2 (Authorization):" in help
	}
	// AddCommand is how we say "these are the sub-buttons under oauth"
	cmd.AddCommand(newOAuthAuthorizeCmd())   // oauth authorize
	cmd.AddCommand(newOAuthTokenCmd())       // oauth token
	cmd.AddCommand(newOAuthClientCredsCmd()) // oauth client-credentials
	cmd.AddCommand(newOAuthVerifyCmd())      // oauth verify
	return cmd
}

// ----------------------------------------------------------------------------
// oauth authorize — Authorization Code + PKCE (the normal login with a browser)
// ----------------------------------------------------------------------------

// newOAuthAuthorizeCmd creates "oauth authorize".
// This shows OAuth2 in action: get permission to use an API, but NOT who you are.
func newOAuthAuthorizeCmd() *cobra.Command {
	var providerURL, clientID, scopes string // where the server is, app id, permissions
	var port int                             // local port to catch the redirect
	var noBrowser bool                       // we just print the URL, don't auto-open

	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Run Authorization Code flow with PKCE and print tokens",
		Long: `Demonstrates OAuth2 Authorization Code + PKCE.

1. Generates PKCE verifier/challenge
2. Builds /authorize URL and (optionally) opens browser
3. Starts local callback server on --port to capture ?code=
4. Exchanges code for access_token at /token
5. Prints token response JSON

For offline demo: first run 'oidc-demo serve --port 8085' then
  oidc-demo oauth authorize --provider http://localhost:8085 --port 8086`,
		Args: cobra.NoArgs, // no extra words after "authorize"
		// RunE is the real work: what happens when you type "oauth authorize"
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Get a context (used to cancel if user presses Ctrl+C)
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background() // make a fresh one if none exists
			}
			// Remove trailing "/" so "http://localhost:8085/" becomes "http://localhost:8085"
			providerURL = strings.TrimSuffix(providerURL, "/")
			// Make sure the provider is up before we print a URL the user cannot open
			if err := checkProviderReachable(providerURL); err != nil {
				return err
			}

			// Step 1: Make a secret string (verifier) and its scrambled version (challenge).
			// We send challenge to server, keep verifier private. This stops hackers stealing the code.
			verifier, err := token.GenerateVerifier() // calls our helper to make random secret
			if err != nil {
				return err
			}
			challenge := token.ChallengeS256(verifier) // scramble verifier with SHA256
			verbose(cmd, "PKCE verifier=%s challenge=%s", verifier[:8]+"...", challenge[:8]+"...")

			// Step 2: Build an OAuth2 config. This tells the library where to send requests.
			conf := &oauth2.Config{
				ClientID:    clientID,                                          // name of our app
				RedirectURL: fmt.Sprintf("http://localhost:%d/callback", port), // where server sends code back
				Scopes:      strings.Fields(scopes),                            // split "read write" into ["read","write"]
				Endpoint: oauth2.Endpoint{
					AuthURL:  providerURL + "/authorize", // login page
					TokenURL: providerURL + "/token",     // where to swap code for token
				},
			}

			// state is a random word to stop CSRF attacks (server sends it back, we check it)
			state := "oauth-demo-state"
			// AuthCodeURL builds the full URL like "http://.../authorize?client_id=...&code_challenge=..."
			authURL := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
			// Print it so user can click/open it
			fmt.Fprintln(cmd.OutOrStdout(), "Authorize URL:")
			fmt.Fprintln(cmd.OutOrStdout(), authURL)
			if !noBrowser {
				fmt.Fprintln(cmd.OutOrStdout(), "\nOpen the URL above in your browser to continue.")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Listening for callback on http://localhost:%d/callback ...\n", port)

			// Step 3: Start a tiny web server to wait for the redirect with ?code=...
			codeCh := make(chan string, 1) // will hold the code when it arrives
			errCh := make(chan error, 1)   // will hold any error
			mux := http.NewServeMux()      // mux is like a receptionist that routes URLs to functions
			srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
			// When browser visits /callback, this function runs
			mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query() // read ?code=...&state=...
				if q.Get("state") != state {
					http.Error(w, "invalid state", http.StatusBadRequest)
					errCh <- fmt.Errorf("invalid state")
					return
				}
				if ec := q.Get("error"); ec != "" {
					http.Error(w, "provider error: "+ec, http.StatusBadRequest)
					errCh <- fmt.Errorf("provider error: %s", ec)
					return
				}
				code := q.Get("code") // the one-time code from server
				if code == "" {
					http.Error(w, "missing code", http.StatusBadRequest)
					errCh <- fmt.Errorf("missing code")
					return
				}
				// Tell browser it worked
				fmt.Fprintln(w, "Authorization successful — you can close this tab and return to the CLI.")
				codeCh <- code                  // send code to main thread
				go func() { _ = srv.Close() }() // shut down the tiny server
			})
			// Start the tiny server in background
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			// Wait for either code, error, or cancel
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

			fmt.Fprintf(cmd.OutOrStdout(), "Got code: %s\n", code)
			fmt.Fprintln(cmd.OutOrStdout(), "Exchanging code for tokens...")

			// Step 4: Swap code + verifier for an access_token (call POST /token)
			tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			if err != nil {
				return fmt.Errorf("token exchange failed: %w", err)
			}
			// Print the token info: notice there is NO id_token — that's OAuth2, not OIDC
			return printJSON(cmd, map[string]interface{}{
				"access_token":  tok.AccessToken,
				"token_type":    tok.TokenType,
				"refresh_token": tok.RefreshToken,
				"expiry":        tok.Expiry.String(),
				"scope":         scopes,
				"note":          "OAuth2 has NO id_token — this is expected. Use 'oidc login' for identity.",
			})
		},
	}
	// Flags let user type "--provider http://..." etc.
	cmd.Flags().StringVar(&providerURL, "provider", "http://localhost:8085", "provider base URL (issuer)")
	cmd.Flags().StringVar(&clientID, "client-id", "demo-client", "OAuth2 client ID")
	cmd.Flags().StringVar(&scopes, "scopes", "read write", "space-separated scopes (no openid)")
	cmd.Flags().IntVar(&port, "port", 8086, "local callback port")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", true, "do not try to open browser (just print URL)")
	// No MarkFlagRequired: --provider already has a default, so it works without being typed
	return cmd
}

// newOAuthTokenCmd creates "oauth token".
// If you already have a code, this swaps it for tokens without needing a browser.
func newOAuthTokenCmd() *cobra.Command {
	var providerURL, clientID, code, verifier, redirectURL string
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Exchange authorization code for tokens (manual PKCE)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			providerURL = strings.TrimSuffix(providerURL, "/")
			// Build form data like a web form submission
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("client_id", clientID)
			form.Set("redirect_uri", redirectURL)
			if verifier != "" {
				form.Set("code_verifier", verifier) // prove we are the same app that started login
			}
			// Call http.PostForm to send POST to /token
			resp, err := http.PostForm(providerURL+"/token", form)
			if err != nil {
				return err
			}
			defer resp.Body.Close() // make sure we close the connection after
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				return fmt.Errorf("token endpoint %d: %s", resp.StatusCode, string(body))
			}
			var out map[string]interface{}
			if err := json.Unmarshal(body, &out); err != nil { // turn JSON string into Go map
				return err
			}
			_ = ctx
			return printJSON(cmd, out) // print result as pretty JSON
		},
	}
	cmd.Flags().StringVar(&providerURL, "provider", "http://localhost:8085", "provider base URL")
	cmd.Flags().StringVar(&clientID, "client-id", "demo-client", "client ID")
	cmd.Flags().StringVar(&code, "code", "", "authorization code")
	cmd.Flags().StringVar(&verifier, "verifier", "", "PKCE code_verifier (if used)")
	cmd.Flags().StringVar(&redirectURL, "redirect-url", "http://localhost:8086/callback", "redirect_uri used in authorize")
	_ = cmd.MarkFlagRequired("code")
	return cmd
}

// newOAuthClientCredsCmd creates "oauth client-credentials".
// This is for app-to-app, no person involved — like a backend service calling an API.
func newOAuthClientCredsCmd() *cobra.Command {
	var providerURL, clientID, clientSecret, scopes string
	cmd := &cobra.Command{
		Use:   "client-credentials",
		Short: "Client Credentials flow (machine-to-machine, no user)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			providerURL = strings.TrimSuffix(providerURL, "/")
			form := url.Values{}
			form.Set("grant_type", "client_credentials") // tell server: "I am an app, not a person"
			form.Set("client_id", clientID)
			if clientSecret != "" {
				form.Set("client_secret", clientSecret)
			}
			if scopes != "" {
				form.Set("scope", scopes)
			}
			// Send POST to /token and print what comes back
			resp, err := http.PostForm(providerURL+"/token", form)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				return fmt.Errorf("token endpoint %d: %s", resp.StatusCode, string(body))
			}
			var out map[string]interface{}
			_ = json.Unmarshal(body, &out)
			return printJSON(cmd, out)
		},
	}
	cmd.Flags().StringVar(&providerURL, "provider", "http://localhost:8085", "provider base URL")
	cmd.Flags().StringVar(&clientID, "client-id", "demo-client", "client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "client secret (optional for mock)")
	cmd.Flags().StringVar(&scopes, "scopes", "read write", "space-separated scopes")
	return cmd
}

// newOAuthVerifyCmd creates "oauth verify".
// Give it an access_token and it checks if the token is real by looking at the server's public key.
func newOAuthVerifyCmd() *cobra.Command {
	var tokenStr, jwksURL string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an access_token via JWKS (RS256)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Step 1: Download the public keys from the server
			resp, err := http.Get(jwksURL) // calls GET /jwks
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal(body, &jwks); err != nil {
				return fmt.Errorf("invalid JWKS: %w", err)
			}
			if len(jwks.Keys) == 0 {
				return fmt.Errorf("no keys in JWKS")
			}
			// Step 2: Check the JWT signature using the public key
			claims := jwt.MapClaims{} // will hold the token's data if valid
			parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
				// Make sure token was signed with RSA
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
				}
				// Find the right key by kid (key id)
				kid, _ := t.Header["kid"].(string)
				for _, k := range jwks.Keys {
					if k.KeyID == kid || kid == "" {
						return k.Key, nil
					}
				}
				return jwks.Keys[0].Key, nil
			})
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			if !parsed.Valid {
				return fmt.Errorf("invalid token")
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Token valid. Claims:")
			return printJSON(cmd, claims)
		},
	}
	cmd.Flags().StringVar(&tokenStr, "token", "", "access_token to verify")
	cmd.Flags().StringVar(&jwksURL, "jwks-url", "http://localhost:8085/jwks", "JWKS URL")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

// printJSON prints any Go value as pretty JSON to the command's output.
// We use cmd.OutOrStdout() so tests can capture the output.
func printJSON(cmd *cobra.Command, v interface{}) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ") // pretty indent with 2 spaces
	return enc.Encode(v)
}
