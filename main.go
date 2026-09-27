package main

import (
	"fmt"
	"os"

	"oidc-demo/cmd"
)

// These values get filled in at build time by the Makefile using -ldflags -X.
// If you just run "go build" they stay as the plain defaults below.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// main is the first function that runs when you start the program.
// Think of it as the front door: it just hands control to the cobra command tree.
func main() {
	// cmd.Execute() finds the right command, and runs it.
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
