package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/identity"
)

var tokenNewID string

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage haybale identity tokens",
}

var tokenNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Mint a new identity token",
	Long: "Mint a new cryptographically-random identity token for --id, printing the raw token " +
		"(to hand to the operator's sandbox, e.g. as HAYBALE_TOKEN) and the identities.yaml stanza " +
		"to add in its place. The raw token is shown once here and is never itself persisted — only " +
		"its SHA-256 digest is, in identities.yaml.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runTokenNew(cmd, tokenNewID)
	},
}

func init() {
	tokenNewCmd.Flags().StringVar(&tokenNewID, "id", "", "identity ID this token authenticates as (required)")
	if err := tokenNewCmd.MarkFlagRequired("id"); err != nil {
		// MarkFlagRequired only fails if "id" isn't a registered flag,
		// which the StringVar call directly above guarantees it is —
		// unreachable in practice, but panicking surfaces a programmer
		// error immediately rather than silently accepting --id as
		// optional.
		panic(err)
	}
	tokenCmd.AddCommand(tokenNewCmd)
	rootCmd.AddCommand(tokenCmd)
}

func runTokenNew(cmd *cobra.Command, id string) error {
	if id == "" {
		// MarkFlagRequired only enforces that --id was explicitly
		// passed, not that its value is non-empty (an operator running
		// `token new --id=""` would otherwise sail through it and mint
		// a token for a blank identity).
		return fmt.Errorf("--id is required")
	}

	token, digestHex, err := identity.NewToken()
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "token (save this now -- it will not be shown again):\n%s\n\n", token); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "add this stanza to identities.yaml:\n  - id: %s\n    tokenDigest: sha256:%s\n", id, digestHex); err != nil {
		return err
	}
	return nil
}
