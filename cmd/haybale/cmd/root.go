// Package cmd wires up haybale's cobra CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "haybale",
	Short: "An authenticating git smart-HTTP proxy",
	Long:  "haybale proxies git smart-HTTP traffic to upstream git hosts, streaming pack data through without buffering or parsing it.",
}

// Execute runs the root command. Called from main().
func Execute() {
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
