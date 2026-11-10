package cmd

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/config"
)

var (
	cachePurgeConfigPath string
	cachePurgeRepo       string
	cachePurgeGroup      string
	cachePurgeRemote     bool
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage haybale's response cache",
}

var cachePurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Delete one repository's entries from the local cache directory",
	Long: "Loads --config and deletes every cache entry for --repo (or only its refs or pack " +
		"entries with --group) from cache.dir. The cache key named by cache.keyEnv must be set " +
		"to the key the entries were sealed under, because entries are addressed by a keyed " +
		"hash of the repository. The command is offline and safe to run while a server is " +
		"using the directory; the server treats a purged entry as a miss. Run it on every " +
		"replica that holds entries for the repository.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runCachePurge(cmd, cachePurgeConfigPath, cachePurgeRepo, cachePurgeGroup, cachePurgeRemote)
	},
}

func init() {
	cachePurgeCmd.Flags().StringVar(&cachePurgeConfigPath, "config", "haybale.yaml", "path to haybale's YAML config file")
	cachePurgeCmd.Flags().StringVar(&cachePurgeRepo, "repo", "", "repo to purge, as host/owner/repo (required)")
	cachePurgeCmd.Flags().StringVar(&cachePurgeGroup, "group", "", `entries to purge: "refs" or "pack" (default: both)`)
	cachePurgeCmd.Flags().BoolVar(&cachePurgeRemote, "remote", false, "purge the remote tier (not supported in this release)")
	if err := cachePurgeCmd.MarkFlagRequired("repo"); err != nil {
		// Unreachable: the StringVar call above registers "repo".
		panic(err)
	}
	cacheCmd.AddCommand(cachePurgeCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCachePurge(cmd *cobra.Command, cfgPath, repoArg, groupArg string, remote bool) error {
	if remote {
		return errors.New("--remote: purging the remote cache tier is not supported in this release")
	}
	groups, err := cache.ParseGroups(groupArg)
	if err != nil {
		return fmt.Errorf("--group: %w", err)
	}
	repo, err := parsePolicyCheckRepo(repoArg)
	if err != nil {
		return err
	}

	// config.Load validates structurally and never touches the filesystem
	// or the environment, so the purge stays offline.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	cc := cfg.Cache
	if !cc.Enabled {
		return errors.New("cache.enabled is false in the config: there is no cache to purge")
	}
	if cc.KeyEnv == "" {
		return errors.New("cache.keyEnv is not set: entries sealed under an ephemeral key cannot be addressed " +
			"by the purge command, and a local-only cache without keyEnv is cleared when the server restarts instead")
	}
	keyring, err := cc.LoadKeyring()
	if err != nil {
		return err
	}

	baseURL := upstreamBaseURL(cfg, repo.Host)
	if baseURL == nil {
		return fmt.Errorf("--repo %q: host %q is not a configured upstream", repoArg, repo.Host)
	}

	// The server hashes the same key and the same parsed base URL.
	repoHash := keyring.RepoHash(baseURL, repo)

	purged := 0
	for _, group := range groups {
		n, err := cache.PurgeDiskPrefix(cc.Dir, cache.RepoPrefix(group, repoHash))
		purged += n
		if err != nil {
			return fmt.Errorf("purge %s entries (%s purged so far): %w", group, pluralEntries(purged), err)
		}
	}

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "purged %s\n", pluralEntries(purged))
	return err
}

// pluralEntries renders a count of cache entries with the right number.
func pluralEntries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}

// upstreamBaseURL returns the parsed base URL of the upstream configured
// for host, or nil when there is none.
func upstreamBaseURL(cfg *config.Config, host string) *url.URL {
	for _, u := range cfg.Upstreams {
		if u.Host == host {
			return u.ParsedBaseURL()
		}
	}
	return nil
}
