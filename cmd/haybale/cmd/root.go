// Package cmd wires up haybale's cobra CLI.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "haybale",
	Short: "An authenticating git smart-HTTP proxy",
	Long:  "haybale proxies git smart-HTTP traffic to upstream git hosts, streaming pack data through without buffering or parsing it.",
}

// exitCodeDrainTimeoutExceeded is the exit code Execute uses when
// serveWithGracefulDrain returns ErrDrainTimeoutExceeded — deliberately
// distinct from exitCodeError (1) so on-call tooling keyed off exit code
// can tell an operator-configured drain cutoff apart from a genuine
// startup/runtime failure.
const exitCodeDrainTimeoutExceeded = 3

// exitCodeError is the exit code Execute uses for every other error
// rootCmd.Execute returns.
const exitCodeError = 1

// Execute runs the root command. Called from main().
func Execute() {
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	err := rootCmd.Execute()
	if err == nil {
		return
	}

	if errors.Is(err, ErrDrainTimeoutExceeded) {
		// Already logged in full (including the configured drainTimeout
		// value) as a Warn inside serveWithGracefulDrain, at the moment
		// the timeout fired — this is a deliberate, operator-configured
		// shutdown cutoff, not a crash, so it exits through its own
		// distinct path rather than the generic "Error:" + exit 1 below.
		os.Exit(exitCodeDrainTimeoutExceeded)
	}

	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(exitCodeError)
}
