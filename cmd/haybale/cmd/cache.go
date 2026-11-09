package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"

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
	groups, err := parseCachePurgeGroups(groupArg)
	if err != nil {
		return err
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
	raw := os.Getenv(cc.KeyEnv)
	if raw == "" {
		return fmt.Errorf("environment variable %s (cache.keyEnv) is not set", cc.KeyEnv)
	}
	key, err := cache.Decode32(raw)
	if err != nil {
		return fmt.Errorf("environment variable %s (cache.keyEnv): %w", cc.KeyEnv, err)
	}

	baseURL := upstreamBaseURL(cfg, repo.Host)
	if baseURL == nil {
		return fmt.Errorf("--repo %q: host %q is not a configured upstream", repoArg, repo.Host)
	}

	// The server hashes the same raw key bytes and the same parsed base URL.
	sum := cache.RepoHash(key, baseURL, repo)
	repoHash := hex.EncodeToString(sum[:])

	purged := 0
	for _, group := range groups {
		n, err := cache.PurgeDiskPrefix(cc.Dir, "v1/"+string(group)+"/"+repoHash+"/")
		purged += n
		if err != nil {
			return fmt.Errorf("purge %s entries (%d purged so far): %w", group, purged, err)
		}
	}

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "purged %d entries\n", purged)
	return err
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

// parseCachePurgeGroups maps --group to the entry groups to purge; empty
// selects both.
func parseCachePurgeGroups(raw string) ([]cache.Group, error) {
	switch raw {
	case "":
		return []cache.Group{cache.GroupRefs, cache.GroupPack}, nil
	case string(cache.GroupRefs):
		return []cache.Group{cache.GroupRefs}, nil
	case string(cache.GroupPack):
		return []cache.Group{cache.GroupPack}, nil
	default:
		return nil, fmt.Errorf(`--group %q must be "refs" or "pack"`, raw)
	}
}
