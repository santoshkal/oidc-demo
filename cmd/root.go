// Package cmd
package cmd

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// rootCmd is the main command
var rootCmd = &cobra.Command{
	Use:   "oidc-demo",                          // name you type in terminal
	Short: "Demo CLI for OAuth2 and OIDC flows", // short help line
	Long: `oidc-demo — learn OAuth2 (authorization) vs OIDC (authentication) hands-on.

A local mock IdP is included (serve) so the demo works offline.
For real IdPs, point --provider or --issuer to your IdP URL.`,
	// don't print big help text on every small error
	SilenceUsage: true,
	// let main.go print errors nicely
	SilenceErrors: true,
}

// Execute starts the app. main.go calls this.
// It reads what you typed, finds the right command, and runs it.
func Execute() error {
	// cobra does the heavy lifting: parse args, find command, run it
	return rootCmd.Execute()
}

// init runs automatically when the program starts, before main().
// It builds the menu tree: which commands exist and how they are grouped.
func init() {
	// Make groups so help looks nice with headings
	rootCmd.AddGroup(
		&cobra.Group{ID: "provider", Title: "Provider:"},            // group for "serve"
		&cobra.Group{ID: "oauth", Title: "OAuth2 (Authorization):"}, // group for oauth commands
		&cobra.Group{ID: "oidc", Title: "OIDC (Authentication):"},   // group for oidc commands
	)

	// Add sub-commands to the main menu
	rootCmd.AddCommand(newServeCmd()) // adds "serve" button
	rootCmd.AddCommand(newOAuthCmd()) // adds "oauth" button (which itself has more buttons inside)
	rootCmd.AddCommand(newOIDCCmd())  // adds "oidc" button

	// Add a global flag "--verbose" that works for every command
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
}

// verbose prints a message only if user typed "--verbose".
// It checks if --verbose was set and writes to stderr (error output).
func verbose(cmd *cobra.Command, format string, args ...interface{}) {
	v, _ := cmd.Flags().GetBool("verbose") // check local flag
	if !v {
		v, _ = cmd.Root().PersistentFlags().GetBool("verbose") // also check global flag
	}
	if v {
		fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...) // print to error output
	}
}

// splitProviderURL pulls the scheme, host and port out of a provider URL.
// It also fills in the default port (443 for https, 80 for http) when the
// user did not write one, because net.Dial needs a "host:port" value.
func splitProviderURL(providerURL string) (scheme, hostPort string, err error) {
	raw := strings.TrimSpace(providerURL)
	if raw == "" {
		return "", "", errors.New("provider URL is empty")
	}

	scheme = "https"
	rest := raw
	switch {
	case strings.HasPrefix(raw, "https://"):
		rest = strings.TrimPrefix(raw, "https://")
	case strings.HasPrefix(raw, "http://"):
		scheme = "http"
		rest = strings.TrimPrefix(raw, "http://")
	}

	// drop any path, query or fragment: we only want the address
	rest = strings.SplitN(rest, "/", 2)[0]
	rest = strings.SplitN(rest, "?", 2)[0]
	rest = strings.SplitN(rest, "#", 2)[0]
	if rest == "" {
		return "", "", fmt.Errorf("invalid provider URL %q", providerURL)
	}

	// add the default port only if the user left it out
	if !strings.Contains(rest, ":") {
		if scheme == "https" {
			rest += ":443"
		} else {
			rest += ":80"
		}
	}
	return scheme, rest, nil
}

// isLocalProvider reports whether the provider points at this computer.
// Used to decide which hint makes sense: "start the mock IdP" only helps locally.
func isLocalProvider(providerURL string) bool {
	scheme, hostPort, err := splitProviderURL(providerURL)
	if err != nil {
		return false
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	// the loopback names and addresses all mean "this computer"
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return true
	}
	// anything in 127.0.0.0/8 is loopback too
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	_ = scheme
	return false
}

// providerHint builds the message we show when the provider cannot be reached.
// For a local address it points at the bundled mock IdP; for a remote one it
// gives real remote-issuer troubleshooting steps instead.
func providerHint(providerURL, cause string) string {
	if isLocalProvider(providerURL) {
		return fmt.Sprintf("cannot reach the provider at %s\n\n"+
			"Reason: %s\n\n"+
			"This demo ships with its own fake IdP. Start it in a second terminal, then retry:\n\n"+
			"    %s serve",
			providerURL, cause, rootCmd.Name())
	}
	return fmt.Sprintf("cannot reach the provider at %s\n\n"+
		"Reason: %s\n\n"+
		"Things to check:\n\n"+
		"  1. You have internet access and the host name is correct.\n"+
		"  2. A firewall or proxy is not blocking the connection.\n"+
		"  3. You can reach it from a browser:\n"+
		"       %s/.well-known/openid-configuration",
		providerURL, cause, strings.TrimSuffix(providerURL, "/"))
}

// checkProviderReachable pings the provider before starting a flow so that a
// missing server gives a clear message instead of a raw network error.
func checkProviderReachable(providerURL string) error {
	_, hostPort, err := splitProviderURL(providerURL)
	if err != nil {
		return err
	}

	// a short timeout keeps the check fast when nothing is there
	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		// turn the raw network error into one short sentence for the hint
		cause := "the connection was refused or the port is closed"
		switch {
		case isTimeout(err):
			cause = "the connection timed out (firewall, proxy, or no route to host)"
		case isDNSError(err):
			cause = "the host name could not be resolved (typo, or no DNS?)"
		}
		return errors.New(providerHint(providerURL, cause))
	}
	_ = conn.Close()
	return nil
}

// isTimeout reports whether the error was a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isDNSError reports whether the host name could not be found.
func isDNSError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "server misbehaving")
}
