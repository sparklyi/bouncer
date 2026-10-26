package memory_test

import (
	"testing"
	"time"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/store/memory"
	"github.com/sparklyi/bouncer/store/storetest"
)

func newStore(t *testing.T) bouncer.Store {
	t.Helper()
	s := memory.New(memory.WithSweepInterval(20 * time.Millisecond))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreContract(t *testing.T) {
	storetest.Run(t, newStore)
}

func TestStoreCapacityFailsClosed(t *testing.T) {
	s := memory.New(memory.WithCapacity(2), memory.WithSweepInterval(time.Hour))
	t.Cleanup(func() { _ = s.Close() })
	ctx := t.Context()
	for _, id := range []string{"a", "b"} {
		if ok, err := s.Consume(ctx, id, time.Minute); err != nil || !ok {
			t.Fatalf("Consume %q = %v, %v", id, ok, err)
		}
	}
	if ok, err := s.Consume(ctx, "c", time.Minute); err == nil || ok {
		t.Fatalf("Consume over capacity = %v, %v; want error", ok, err)
	}
}

func TestStoreCloseIsIdempotent(t *testing.T) {
	s := memory.New(memory.WithSweepInterval(time.Hour))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
