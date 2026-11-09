package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/config"
)

// cachePurgeRemoteTimeout bounds the remote half of `haybale cache purge
// --remote`: writing the purge marker and deleting the remote objects.
const cachePurgeRemoteTimeout = 5 * time.Minute

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
	Short: "Delete one repository's entries from the cache",
	Long: "Loads --config and deletes every cache entry for --repo (or only its refs or pack " +
		"entries with --group) from cache.dir. The cache key named by cache.keyEnv must be set " +
		"to the key the entries were sealed under, because entries are addressed by a keyed " +
		"hash of the repository. The command is safe to run while a server is using the " +
		"directory; the server treats a purged entry as a miss.\n\n" +
		"Without --remote the command is offline and reaches only this directory, so run it " +
		"on every replica. With --remote it also writes the repository's purge marker to " +
		"cache.remote and deletes the repository's remote entries; every replica sharing the " +
		"remote tier then drops its older local entries at its next upstream refs request " +
		"for the repository.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runCachePurge(cmd, cachePurgeConfigPath, cachePurgeRepo, cachePurgeGroup, cachePurgeRemote)
	},
}

func init() {
	cachePurgeCmd.Flags().StringVar(&cachePurgeConfigPath, "config", "haybale.yaml", "path to haybale's YAML config file")
	cachePurgeCmd.Flags().StringVar(&cachePurgeRepo, "repo", "", "repo to purge, as host/owner/repo (required)")
	cachePurgeCmd.Flags().StringVar(&cachePurgeGroup, "group", "", `entries to purge: "refs" or "pack" (default: both)`)
	cachePurgeCmd.Flags().BoolVar(&cachePurgeRemote, "remote", false, "also purge cache.remote and write the purge marker other replicas honour")
	if err := cachePurgeCmd.MarkFlagRequired("repo"); err != nil {
		// Unreachable: the StringVar call above registers "repo".
		panic(err)
	}
	cacheCmd.AddCommand(cachePurgeCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCachePurge(cmd *cobra.Command, cfgPath, repoArg, groupArg string, remote bool) error {
	groups, err := cache.ParseGroups(groupArg)
	if err != nil {
		return fmt.Errorf("--group: %w", err)
	}
	repo, err := parsePolicyCheckRepo(repoArg)
	if err != nil {
		return err
	}

	// config.Load validates structurally and never touches the filesystem
	// or the environment, so without --remote the purge stays offline.
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

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	var remoteStore cache.BlobStore
	if remote {
		if remoteStore, err = cc.BuildRemote(ctx); err != nil {
			return fmt.Errorf("--remote: %w", err)
		}
		if remoteStore == nil {
			return errors.New("--remote: cache.remote is not configured")
		}
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

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "purged %s\n", pluralEntries(purged)); err != nil {
		return err
	}
	if remoteStore == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, cachePurgeRemoteTimeout)
	defer cancel()
	n, err := cache.PurgeRemote(ctx, remoteStore, keyring, repo, baseURL, groups, time.Now())
	if err != nil {
		return fmt.Errorf("--remote: purge the remote tier (%s deleted so far): %w", pluralEntries(n), err)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "purged %s from the remote tier and wrote the purge marker\n", pluralEntries(n))
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
