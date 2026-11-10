package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/config"
)

// cachePurgeRemoteTimeout bounds `haybale cache purge --remote`: writing
// the purge marker and deleting the remote and local entries.
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
		"on every replica; when cache.remote is configured it warns that replicas will refill " +
		"the purged entries from the bucket. With --remote it first writes the repository's " +
		"purge marker to cache.remote, then deletes the repository's remote entries, then " +
		"the local ones; a missing cache.dir is skipped. Every replica sharing the remote tier " +
		"drops its older local entries at its next purge-marker check, within about a minute " +
		"plus its next upstream refs request for the repository. A failed run is safe to repeat.",
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
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	var remoteStore cache.BlobStore
	if remote {
		if remoteStore, err = cc.BuildRemote(ctx); err != nil {
			return fmt.Errorf("--remote: %w", err)
		}
		if remoteStore == nil {
			return errors.New("--remote: cache.remote is not configured")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cachePurgeRemoteTimeout)
		defer cancel()
	} else if cc.HasRemote() {
		_, _ = fmt.Fprintln(stderr, "warning: cache.remote is configured but --remote was not given: "+
			"replicas will refill the purged entries from the bucket; use --remote to purge the shared tier")
	}

	localMissing := false
	var writeErr error
	report := func(w io.Writer, format string, args ...any) {
		if _, err := fmt.Fprintf(w, format, args...); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	// The server hashes the same key and the same parsed base URL.
	res, err := cache.PurgeRepository(ctx, keyring, cache.PurgeRequest{
		Repo:    repo,
		BaseURL: baseURL,
		Groups:  groups,
		Now:     time.Now(),
		Remote:  remoteStore,
		DeleteLocal: func(prefix string) (int, error) {
			n, err := cache.PurgeDiskPrefix(cc.Dir, prefix)
			if remote && errors.Is(err, fs.ErrNotExist) {
				localMissing = true
				return 0, nil
			}
			return n, err
		},
		StepDone: func(step cache.PurgeStep, res cache.PurgeResult) {
			switch step {
			case cache.PurgeStepMarker:
				if res.MarkerReplaced {
					report(stderr, "notice: the repository's purge marker failed verification and was replaced\n")
				}
			case cache.PurgeStepRemote:
				report(stdout, "wrote the purge marker and purged %s from the remote tier\n", pluralEntries(res.Remote))
			case cache.PurgeStepLocal:
				if localMissing {
					report(stderr, "notice: cache.dir %q does not exist; there are no local entries to purge\n", cc.Dir)
					return
				}
				report(stdout, "purged %s\n", pluralEntries(res.Local))
			}
		},
	})
	if err != nil {
		return purgeCommandError(err, res)
	}
	return writeErr
}

// purgeCommandError phrases each failed step of a purge for the operator,
// with how far the step got.
func purgeCommandError(err error, res cache.PurgeResult) error {
	errs := []error{err}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs = joined.Unwrap()
	}
	out := make([]error, 0, len(errs))
	for _, e := range errs {
		var pe *cache.PurgeError
		if !errors.As(e, &pe) {
			out = append(out, e)
			continue
		}
		switch pe.Step {
		case cache.PurgeStepMarker:
			out = append(out, fmt.Errorf("--remote: write the purge marker (nothing was deleted): %w", pe.Err))
		case cache.PurgeStepRemote:
			out = append(out, fmt.Errorf("--remote: the purge marker was written, but purging the remote tier failed (%s deleted so far): %w", pluralEntries(res.Remote), pe.Err))
		default:
			out = append(out, fmt.Errorf("purge %s entries (%s purged so far): %w", pe.Group, pluralEntries(res.Local), pe.Err))
		}
	}
	return errors.Join(out...)
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
