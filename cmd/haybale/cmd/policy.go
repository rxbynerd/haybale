package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/config"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
)

var (
	policyCheckConfigPath string
	policyCheckID         string
	policyCheckRepo       string
	policyCheckVerb       string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect haybale's policy engine",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Dry-run a policy decision, without serving traffic",
	Long: "Loads --config's policy.yaml (via the exact same policy.Engine haybale serve uses) and " +
		"prints whether --id would be ALLOWed or DENYed to --verb --repo, and which rule (if any) " +
		"matched. No network call is made and no upstream credential is minted or checked — this " +
		"only evaluates policy, the same way it would apply against a real request.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runPolicyCheck(cmd, policyCheckConfigPath, policyCheckID, policyCheckRepo, policyCheckVerb)
	},
}

func init() {
	policyCheckCmd.Flags().StringVar(&policyCheckConfigPath, "config", "haybale.yaml", "path to haybale's YAML config file")
	policyCheckCmd.Flags().StringVar(&policyCheckID, "id", "", "identity ID to check (required)")
	policyCheckCmd.Flags().StringVar(&policyCheckRepo, "repo", "", "repo to check, as host/owner/repo (required)")
	policyCheckCmd.Flags().StringVar(&policyCheckVerb, "verb", "", `"read" or "write" (required)`)
	for _, name := range []string{"id", "repo", "verb"} {
		if err := policyCheckCmd.MarkFlagRequired(name); err != nil {
			// MarkFlagRequired only fails if name isn't a registered flag,
			// which the StringVar calls directly above guarantee it is —
			// unreachable in practice, but panicking surfaces a programmer
			// error immediately rather than silently accepting the flag as
			// optional.
			panic(err)
		}
	}
	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyCheck(cmd *cobra.Command, cfgPath, id, repoArg, verbArg string) error {
	repo, err := parsePolicyCheckRepo(repoArg)
	if err != nil {
		return err
	}
	verb, err := parsePolicyCheckVerb(verbArg)
	if err != nil {
		return err
	}

	// config.Load runs the full Validate() — identity/upstreams included,
	// not just policy.yaml — so a dry-run check is evaluated against
	// exactly the same policy.Engine `haybale serve` would build from
	// this same --config file, not a hand-parsed reimplementation of it.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	decision := cfg.Policy.Engine().Authorize(identity.Identity{ID: id}, repo, verb)

	result := "DENY"
	if decision.Allowed {
		result = "ALLOW"
	}
	matchedRule := "none (default deny)"
	if decision.Rule != nil {
		matchedRule = decision.Rule.String()
	}

	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "%s: identity=%s repo=%s/%s/%s verb=%s\nmatched rule: %s\nreason: %s\n",
		result, id, repo.Host, repo.Owner, repo.Name, verb.String(), matchedRule, decision.Reason); err != nil {
		return err
	}
	return nil
}

// parsePolicyCheckRepo parses --repo's "host/owner/repo" shape into a
// gitproto.Repo, stripping an optional trailing ".git" from the repo
// segment for parity with the URL shape gitproto.ParseRequest accepts
// from a real request.
func parsePolicyCheckRepo(raw string) (gitproto.Repo, error) {
	parts := strings.Split(raw, "/")
	if len(parts) != 3 {
		return gitproto.Repo{}, fmt.Errorf("--repo %q must be host/owner/repo", raw)
	}
	host, ownerSeg, nameSeg := parts[0], parts[1], parts[2]
	if host == "" || ownerSeg == "" || nameSeg == "" {
		return gitproto.Repo{}, fmt.Errorf("--repo %q must be host/owner/repo with no empty segment", raw)
	}
	name := strings.TrimSuffix(nameSeg, ".git")
	if name == "" {
		return gitproto.Repo{}, fmt.Errorf("--repo %q: repo segment must not be empty after stripping .git", raw)
	}
	return gitproto.Repo{Host: host, Owner: ownerSeg, Name: name}, nil
}

// parsePolicyCheckVerb parses --verb's "read"/"write" value into a
// gitproto.Verb.
func parsePolicyCheckVerb(raw string) (gitproto.Verb, error) {
	switch raw {
	case "read":
		return gitproto.Read, nil
	case "write":
		return gitproto.Write, nil
	default:
		return 0, fmt.Errorf(`--verb %q must be "read" or "write"`, raw)
	}
}
