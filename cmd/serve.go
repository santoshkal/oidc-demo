package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"oidc-demo/internal/provider"
)

// newServeCmd creates the "serve" command.
// Think of this like a button: when you type "oidc-demo serve", this code runs.
// It starts a small fake login server on your own computer so you can try
// OAuth and OIDC without needing the internet.
func newServeCmd() *cobra.Command {
	var port int // which door (port) the server will listen on, e.g. 8085

	// This struct describes the command: its name, what it does, and what happens when you run it.
	cmd := &cobra.Command{
		Use:   "serve",                                   // you type: oidc-demo serve
		Short: "Start local mock OAuth2 + OIDC provider", // one-line help
		Long: `Starts a mock Authorization Server and OIDC Provider on localhost.

Exposes:
  /.well-known/openid-configuration
  /jwks
  /authorize
  /token
  /userinfo

Use this as --provider for oauth/oidc commands to run fully offline.`,
		GroupID: "provider",   // puts it under "Provider:" heading in help
		Args:    cobra.NoArgs, // this command takes no extra words after "serve"
		// RunE is the function that actually runs when you call "serve"
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Build the server address, like "http://localhost:8085"
			issuer := fmt.Sprintf("http://localhost:%d", port)

			// Call New() to make a new fake server.
			// New() makes a new secret key for signing and gets ready to remember codes.
			srv, err := provider.New(issuer)
			if err != nil {
				return err // if key creation fails, stop and show error
			}

			// Make a web server that will use our fake provider to answer requests
			addr := fmt.Sprintf(":%d", port)
			httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}

			// Print where the server is listening, so you know where to point the other commands
			fmt.Fprintf(cmd.OutOrStdout(), "Mock IdP listening on %s\n", issuer)
			fmt.Fprintf(cmd.OutOrStdout(), "Discovery: %s/.well-known/openid-configuration\n", issuer)
			fmt.Fprintf(cmd.OutOrStdout(), "JWKS:      %s/jwks\n", issuer)
			fmt.Fprintf(cmd.OutOrStdout(), "Press Ctrl+C to stop\n")

			// Start the server and keep it running. It will answer requests at /authorize, /token, etc.
			// ListenAndServe blocks (waits) until you stop it.
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	// This adds a flag: you can type "--port 9000" to pick a different port
	cmd.Flags().IntVar(&port, "port", 8085, "listen port")

	// We call context.Background() here just to keep the import used.
	// Context is like a cancel signal, but we don't need it for this simple server.
	_ = context.Background()
	return cmd
}
