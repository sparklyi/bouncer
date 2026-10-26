// Package storetest is a contract suite for bouncer.Store implementations.
//
// Adapters (memory, redis, sql, ...) should run it so that "any store works"
// is a tested promise rather than a README claim.
package storetest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sparklyi/bouncer"
)

// Run exercises the Store contract. newStore must return an isolated store and
// register its cleanup with t.
func Run(t *testing.T, newStore func(t *testing.T) bouncer.Store) {
	t.Helper()
	ctx := context.Background()

	t.Run("consume once", func(t *testing.T) {
		s := newStore(t)
		ok, err := s.Consume(ctx, "id-1", time.Minute)
		if err != nil || !ok {
			t.Fatalf("first Consume = %v, %v; want true", ok, err)
		}
		ok, err = s.Consume(ctx, "id-1", time.Minute)
		if err != nil || ok {
			t.Fatalf("second Consume = %v, %v; want false", ok, err)
		}
	})

	t.Run("consume expires", func(t *testing.T) {
		s := newStore(t)
		if ok, err := s.Consume(ctx, "id-2", 20*time.Millisecond); err != nil || !ok {
			t.Fatalf("Consume: %v, %v", ok, err)
		}
		time.Sleep(40 * time.Millisecond)
		if ok, err := s.Consume(ctx, "id-2", time.Minute); err != nil || !ok {
			t.Fatalf("after expiry Consume = %v, %v; want true", ok, err)
		}
	})

	t.Run("concurrent consume has one winner", func(t *testing.T) {
		s := newStore(t)
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := s.Consume(ctx, "id-3", time.Minute); err == nil && ok {
					winners.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := winners.Load(); got != 1 {
			t.Fatalf("winners = %d, want exactly 1", got)
		}
	})

	t.Run("attempt is monotonic and bounded", func(t *testing.T) {
		s := newStore(t)
		for want := int32(1); want <= 3; want++ {
			n, exceeded, err := s.Attempt(ctx, "id-4", time.Minute, 3)
			if err != nil {
				t.Fatalf("Attempt: %v", err)
			}
			if n != want {
				t.Fatalf("Attempt n = %d, want %d", n, want)
			}
			if exceeded != (want > 3) {
				t.Fatalf("exceeded = %v at n=%d", exceeded, n)
			}
		}
		n, exceeded, err := s.Attempt(ctx, "id-4", time.Minute, 3)
		if err != nil || n != 4 || !exceeded {
			t.Fatalf("Attempt 4 = %d, %v, %v; want 4, true", n, exceeded, err)
		}
	})

	t.Run("attempt count survives a longer ttl", func(t *testing.T) {
		s := newStore(t)
		if _, _, err := s.Attempt(ctx, "id-5", 50*time.Millisecond, 2); err != nil {
			t.Fatal(err)
		}
		time.Sleep(70 * time.Millisecond)
		n, exceeded, err := s.Attempt(ctx, "id-5", time.Minute, 2)
		if err != nil || n != 1 || exceeded {
			t.Fatalf("after expiry Attempt = %d, %v, %v; want 1, false", n, exceeded, err)
		}
	})
}
