package cache

import (
	"context"
	"errors"
	"io/fs"
	"time"
)

// scannedEntry is a committed entry file found by scan.
type scannedEntry struct {
	path    string
	size    int64
	modTime time.Time
}

// scanResult is what scan found in the cache directory. Names that match
// neither the entry pattern nor the temp-file pattern are not reported.
type scanResult struct {
	entries   []scannedEntry
	temps     []string
	irregular []string // entry-pattern names that are not regular files
	emptyDirs []string // repository directories with nothing in them
}

// scan lists the cache directory without holding the store lock. It never
// follows symlinks: only real directories matching the layout are entered.
func (s *DiskStore) scan() (scanResult, error) {
	var res scanResult
	fsys := s.root.FS()
	top, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return res, err
	}
	hasLayout := false
	for _, d := range top {
		if validTempName(d.Name()) && d.Type().IsRegular() {
			res.temps = append(res.temps, d.Name())
		}
		hasLayout = hasLayout || d.Name() == layoutVersionDir && d.IsDir()
	}
	if !hasLayout {
		return res, nil
	}
	groups, err := readDirIfExists(fsys, layoutVersionDir)
	if err != nil {
		return res, err
	}
	for _, group := range groups {
		groupDir := layoutVersionDir + "/" + group.Name()
		if !group.IsDir() || !validGroupDir(groupDir) {
			continue
		}
		repos, err := readDirIfExists(fsys, groupDir)
		if err != nil {
			return res, err
		}
		for _, repo := range repos {
			repoDir := groupDir + "/" + repo.Name()
			if !repo.IsDir() || !validRepoDir(repoDir) {
				continue
			}
			files, err := readDirIfExists(fsys, repoDir)
			if err != nil {
				return res, err
			}
			if len(files) == 0 {
				res.emptyDirs = append(res.emptyDirs, repoDir)
			}
			for _, f := range files {
				p := repoDir + "/" + f.Name()
				if !validEntryPath(p) {
					continue
				}
				if !f.Type().IsRegular() {
					res.irregular = append(res.irregular, p)
					continue
				}
				info, err := f.Info()
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return res, err
				}
				res.entries = append(res.entries, scannedEntry{path: p, size: info.Size(), modTime: info.ModTime()})
			}
		}
	}
	return res, nil
}

// readDirIfExists is fs.ReadDir returning no entries for a missing
// directory.
func readDirIfExists(fsys fs.FS, name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return entries, err
}

// RunJanitor sweeps the store immediately and then every interval until
// ctx ends. A sweep deletes committed entries older than retention,
// temporary files that belong to no live spool, and least-recently-used
// entries while usage exceeds the budget; it never deletes a live spool
// or an entry that is open. It also reconciles the index with files
// removed or added by another process, such as `haybale cache purge`.
func (s *DiskStore) RunJanitor(ctx context.Context, interval, retention time.Duration) {
	if interval <= 0 || retention <= 0 {
		s.logger.Error("cache: janitor not started: interval and retention must be positive",
			"interval", interval, "retention", retention)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.sweep(retention)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepStats counts what one sweep removed.
type sweepStats struct {
	expired, evicted, temps int
}

// sweep runs one janitor pass. The directory is listed without the lock;
// every decision is then re-checked under it, so files committed, opened
// or deleted during the listing are handled correctly.
func (s *DiskStore) sweep(retention time.Duration) sweepStats {
	var stats sweepStats
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return stats
	}
	startSeq := s.seq
	s.mu.Unlock()

	res, err := s.scan()
	if err != nil {
		s.storeError("sweep", err)
		return stats
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return stats
	}
	defer s.reportLocked()

	for _, name := range res.temps {
		if _, live := s.spools[name]; !live && s.removeLocked(name, "sweep") {
			stats.temps++
		}
	}
	s.reconcileLocked(res, startSeq)

	cutoff := s.now().Add(-retention)
	var expired int64
	for e := s.lru.Back(); e != nil; {
		es := e.Value.(*entryState)
		e = e.Prev()
		if es.readers == 0 && es.modTime.Before(cutoff) && s.removeLocked(es.path, "expire") {
			s.dropLocked(es)
			expired++
		}
	}
	if expired > 0 {
		s.metrics.RecordResponseCacheEvictions(context.Background(), expired)
	}
	stats.expired = int(expired)

	if over := s.committed + s.inflight + s.pinned - s.budget; over > 0 {
		before := len(s.entries)
		if err := s.evictLocked(over); err != nil {
			s.logger.Warn("cache: disk usage exceeds the budget and open entries cannot be evicted", "error", err)
		}
		stats.evicted = before - len(s.entries)
	}

	for _, dir := range res.emptyDirs {
		// Fails harmlessly if a commit has since added an entry.
		if validRepoDir(dir) {
			_ = s.root.Remove(dir)
		}
	}
	return stats
}

// reconcileLocked adds entry files the index does not know and drops
// index entries whose files are gone. Each discrepancy is confirmed with
// an Lstat under the lock, and entries indexed after the listing started
// (seq above startSeq) are left alone.
func (s *DiskStore) reconcileLocked(res scanResult, startSeq uint64) {
	seen := make(map[string]struct{}, len(res.entries))
	for _, e := range res.entries {
		seen[e.path] = struct{}{}
		if _, ok := s.entries[e.path]; ok {
			continue
		}
		info, err := s.root.Lstat(e.path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		es := s.indexLocked(e.path, info.Size(), info.ModTime())
		es.elem = s.lru.PushBack(es)
	}
	for path, es := range s.entries {
		if _, ok := seen[path]; ok || es.seq > startSeq || es.readers > 0 {
			continue
		}
		if _, err := s.root.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			s.dropLocked(es)
		}
	}
}
