package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is overridden at build time via
// -ldflags="-X github.com/rxbynerd/haybale/cmd/haybale/cmd.version=...".
// Left as "dev" for local builds.
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the haybale version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
