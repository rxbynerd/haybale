package cache

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJanitorExpiresByRetention(t *testing.T) {
	clock := newFakeClock()
	s := openStore(t, cacheDir(t), 1<<20, clock)
	old, held, fresh := entryPath(GroupPack, 1, 1), entryPath(GroupPack, 1, 2), entryPath(GroupRefs, 1, 3)
	commitEntry(t, s, old, []byte("old"))
	commitEntry(t, s, held, []byte("held"))
	clock.Advance(2 * time.Hour)
	commitEntry(t, s, fresh, []byte("fresh"))
	clock.Advance(time.Hour)

	e, err := s.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	if stats := s.sweep(150 * time.Minute); stats.expired != 1 {
		t.Fatalf("expired %d entries, want 1", stats.expired)
	}
	if _, err := s.Open(old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired entry still present: err = %v", err)
	}
	readStoreEntry(t, s, fresh)
	readStoreEntry(t, s, held)

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := s.sweep(150 * time.Minute); stats.expired != 1 {
		t.Fatalf("expired %d entries after close, want 1", stats.expired)
	}
	if _, err := s.Open(held); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired entry survived after its reader closed: err = %v", err)
	}
	assertUsage(t, s, 5, 0, 0)
}

func TestJanitorRetentionSurvivesReopen(t *testing.T) {
	dir := cacheDir(t)
	clock := newFakeClock()
	s := openStore(t, dir, 1<<20, clock)
	p := entryPath(GroupPack, 1, 1)
	commitEntry(t, s, p, []byte("data"))
	readStoreEntry(t, s, p) // reads do not extend retention
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(25 * time.Hour)
	s2 := openStore(t, dir, 1<<20, clock)
	if stats := s2.sweep(24 * time.Hour); stats.expired != 1 {
		t.Fatalf("expired %d entries, want 1", stats.expired)
	}
}

func TestJanitorRemovesStaleTempsOnly(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	live, err := s.Create(entryPath(GroupPack, 1, 1), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	stale := []string{
		s.tempPrefix + "0123456789abcdef",
		tempNamePrefix + "fedcba9876543210-0123456789abcdef",
	}
	for _, name := range append(stale, "keep-me") {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if stats := s.sweep(time.Hour); stats.temps != len(stale) {
		t.Fatalf("removed %d temp files, want %d", stats.temps, len(stale))
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale temp %s survived: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "keep-me")); err != nil {
		t.Fatalf("a name outside the patterns was removed: %v", err)
	}
	if err := live.Commit(); err != nil {
		t.Fatalf("live spool damaged by the sweep: %v", err)
	}
	if got := readStoreEntry(t, s, entryPath(GroupPack, 1, 1)); string(got) != "live" {
		t.Fatalf("committed %q", got)
	}
}

func TestJanitorReconcilesExternalChanges(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	a, b := entryPath(GroupPack, 1, 1), entryPath(GroupPack, 1, 2)
	commitEntry(t, s, a, []byte("aaaa"))
	commitEntry(t, s, b, []byte("bb"))

	// Another process deletes a and adds c.
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(a))); err != nil {
		t.Fatal(err)
	}
	c := entryPath(GroupRefs, 2, 3)
	if err := os.MkdirAll(filepath.Join(dir, "v1", "refs", hex64(2)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(c)), []byte("ccc"), 0o600); err != nil {
		t.Fatal(err)
	}

	s.sweep(time.Hour)
	assertUsage(t, s, 5, 0, 0)
	if _, err := s.Open(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open of a deleted entry: err = %v", err)
	}
	if got := readStoreEntry(t, s, c); string(got) != "ccc" {
		t.Fatalf("added entry read %q", got)
	}
}

func TestJanitorEnforcesBudget(t *testing.T) {
	dir := cacheDir(t)
	clock := newFakeClock()
	s := openStore(t, dir, 1000, clock)
	paths := []string{entryPath(GroupPack, 1, 1), entryPath(GroupPack, 1, 2), entryPath(GroupPack, 1, 3)}
	for _, p := range paths {
		commitEntry(t, s, p, make([]byte, 300))
		clock.Advance(time.Minute)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	small := openStore(t, dir, 500, clock)
	assertUsage(t, small, 900, 0, 0)
	if stats := small.sweep(time.Hour); stats.evicted != 2 {
		t.Fatalf("evicted %d entries, want 2", stats.evicted)
	}
	assertUsage(t, small, 300, 0, 0)
	readStoreEntry(t, small, paths[2]) // the newest survives
}

func TestJanitorRemovesEmptyRepositoryDirs(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	p := entryPath(GroupRefs, 1, 1)
	commitEntry(t, s, p, []byte("x"))
	if err := s.Delete(p); err != nil {
		t.Fatal(err)
	}
	s.sweep(time.Hour)
	if _, err := os.Stat(filepath.Join(dir, "v1", "refs", hex64(1))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty repository directory survived: %v", err)
	}
	commitEntry(t, s, p, []byte("y"))
}

func TestRunJanitorLoop(t *testing.T) {
	clock := newFakeClock()
	s := openStore(t, cacheDir(t), 1<<20, clock)
	commitEntry(t, s, entryPath(GroupPack, 1, 1), []byte("x"))
	clock.Advance(2 * time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runJanitor(ctx, 5*time.Millisecond, time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if committed, _, _ := s.usage(); committed == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("janitor did not expire the entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runJanitor did not return after cancel")
	}

	returned := make(chan struct{})
	go func() {
		s.runJanitor(context.Background(), 0, time.Hour)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("runJanitor with a zero interval did not return")
	}
}
