// Package cmd
package cmd

import (
	"fmt"

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
