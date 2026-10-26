// Package memory provides the default in-process bouncer.Store.
//
// It is a replay and attempt-budget guard, not an answer store, so it is
// correct for a single process only. A multi-replica deployment needs a shared
// store such as the redis adapter.
package memory

import (
	"context"
	"errors"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCapacity reports a full store. It fails closed rather than evicting live
// markers, because evicting a marker re-enables replay.
var ErrCapacity = errors.New("memory: capacity reached")

const shardCount = 64

// DefaultCapacity bounds memory use at roughly 8 MB.
const DefaultCapacity = 1 << 16

type entry struct {
	expiresAt int64 // unix nanoseconds
	count     int32
}

type shard struct {
	mu      sync.Mutex
	entries map[string]entry
}

// Store is a sharded, bounded Store implementation.
type Store struct {
	shards   [shardCount]shard
	seed     maphash.Seed
	capacity int
	total    atomic.Int64
	stop     chan struct{}
	once     sync.Once
	sweep    time.Duration
}

// Option configures a Store.
type Option func(*config)

type config struct {
	capacity int
	sweep    time.Duration
}

// WithCapacity sets the maximum number of live markers.
func WithCapacity(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.capacity = n
		}
	}
}

// WithSweepInterval sets how often expired entries are collected.
func WithSweepInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.sweep = d
		}
	}
}

// New returns a Store with a background sweeper. Call Close when done.
func New(opts ...Option) *Store {
	cfg := config{capacity: DefaultCapacity, sweep: 30 * time.Second}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	s := &Store{seed: maphash.MakeSeed(), capacity: cfg.capacity, stop: make(chan struct{}), sweep: cfg.sweep}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]entry)
	}
	go s.run()
	return s
}

func (s *Store) run() {
	ticker := time.NewTicker(s.sweep)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepExpired(time.Now())
		case <-s.stop:
			return
		}
	}
}

// Close stops the sweeper. It is safe to call more than once.
func (s *Store) Close() error {
	s.once.Do(func() { close(s.stop) })
	return nil
}

// Consume marks id as used. Only the first caller within the TTL sees ok.
func (s *Store) Consume(_ context.Context, id string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Second
	}
	sh := s.shardFor(id)
	now := time.Now()
	expires := now.Add(ttl).UnixNano()

	sh.mu.Lock()
	defer sh.mu.Unlock()
	if old, ok := sh.entries[id]; ok {
		if old.expiresAt > now.UnixNano() {
			return false, nil
		}
		sh.entries[id] = entry{expiresAt: expires, count: 1}
		return true, nil
	}
	if s.total.Load() >= int64(s.capacity) {
		s.sweepExpiredLocked(now)
		if s.total.Load() >= int64(s.capacity) {
			return false, ErrCapacity
		}
	}
	sh.entries[id] = entry{expiresAt: expires, count: 1}
	s.total.Add(1)
	return true, nil
}

// Attempt increments the counter for id and reports the new value.
func (s *Store) Attempt(_ context.Context, id string, ttl time.Duration, max int32) (int32, bool, error) {
	if ttl <= 0 {
		ttl = time.Second
	}
	sh := s.shardFor(id)
	now := time.Now()
	expires := now.Add(ttl).UnixNano()

	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.entries[id]
	if !ok || e.expiresAt <= now.UnixNano() {
		if !ok && s.total.Load() >= int64(s.capacity) {
			s.sweepExpiredLocked(now)
			if s.total.Load() >= int64(s.capacity) {
				return 0, false, ErrCapacity
			}
		}
		if !ok {
			s.total.Add(1)
		}
		e = entry{expiresAt: expires}
	}
	e.count++
	e.expiresAt = expires
	sh.entries[id] = e
	return e.count, e.count > max, nil
}

func (s *Store) shardFor(id string) *shard {
	return &s.shards[maphash.String(s.seed, id)%shardCount]
}

func (s *Store) sweepExpired(now time.Time) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		s.sweepShardLocked(sh, now)
		sh.mu.Unlock()
	}
}

func (s *Store) sweepExpiredLocked(now time.Time) {
	for i := range s.shards {
		sh := &s.shards[i]
		if sh.mu.TryLock() {
			s.sweepShardLocked(sh, now)
			sh.mu.Unlock()
		}
	}
}

func (s *Store) sweepShardLocked(sh *shard, now time.Time) {
	for id, e := range sh.entries {
		if e.expiresAt <= now.UnixNano() {
			delete(sh.entries, id)
			s.total.Add(-1)
		}
	}
}
