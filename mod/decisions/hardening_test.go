package decisions

import (
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"sync"
	"testing"
	"time"
)

func TestExpiryFallbackResyncAndMutation(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	cache := NewCacheWithClock(func() time.Time { return now })
	broad := decision(1, "range", "192.0.2.0/24", "ban")
	narrow := decision(2, "ip", "192.0.2.1", "ban")
	narrow.Duration = str("1s")
	duplicate := decision(3, "ip", "192.0.2.1", "ban")
	duplicate.Duration = str("2s")
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{broad, narrow, duplicate}})
	*broad.Value = "198.51.100.1"
	got := cache.GetBan("::ffff:192.0.2.1")
	if got == nil || got.ID != 3 {
		t.Fatalf("mapped lookup: %#v", got)
	}
	*got.Value = "evil"
	*got.Duration = "0s"
	now = now.Add(1500 * time.Millisecond)
	got = cache.GetBan("192.0.2.1")
	if got == nil || got.ID != 3 {
		t.Fatal("valid same-prefix decision lost")
	}
	now = now.Add(time.Second)
	got = cache.GetBan("192.0.2.1")
	if got == nil || got.ID != 1 {
		t.Fatal("expired prefix hid wider ban")
	}
	cache.Expire()
	if cache.ActiveCount() != 1 {
		t.Fatal("expiry count")
	}
	cache.Replace(nil)
	if cache.GetBan("192.0.2.1") == nil {
		t.Fatal("failed snapshot cleared cache")
	}
	cache.Replace(&models.DecisionsStreamResponse{})
	if cache.GetBan("192.0.2.1") != nil {
		t.Fatal("empty snapshot failed to replace")
	}
}
func TestSameIDInvalidDurationAndRenewal(t *testing.T) {
	now := time.Now()
	cache := NewCacheWithClock(func() time.Time { return now })
	d := decision(1, "ip", "192.0.2.1", "ban")
	d.Duration = str("2s")
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
	now = now.Add(time.Second)
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
	now = now.Add(time.Second)
	if cache.GetBan("192.0.2.1") != nil {
		t.Fatal("duplicate extended deadline")
	}
	cache.Expire()
	for _, duration := range []string{"", "0s", "-1s", "broken", "99999999h"} {
		d.Duration = str(duration)
		cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
		if cache.GetBan("192.0.2.1") != nil || len(cache.decisions) != 0 {
			t.Fatalf("invalid duration retained: %q", duration)
		}
	}
	d.Duration = str("1h")
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
	nonban := decision(1, "ip", "192.0.2.1", "captcha")
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{nonban}})
	if cache.GetBan("192.0.2.1") != nil {
		t.Fatal("non-ban left stale ban")
	}
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
	moved := decision(1, "ip", "198.51.100.1", "ban")
	cache.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{nil, decision(999, "ip", "192.0.2.1", "ban")}, New: []*models.Decision{nil, moved}})
	if cache.GetBan("192.0.2.1") != nil || cache.GetBan("198.51.100.1") == nil {
		t.Fatal("same ID not moved")
	}
	cache.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{moved}, New: []*models.Decision{d}})
	if cache.GetBan("192.0.2.1") == nil {
		t.Fatal("delete/new ordering")
	}
}
func TestMappedCIDRAndNativeFamilies(t *testing.T) {
	c := NewCache()
	c.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{decision(1, "range", "::ffff:192.0.2.0/120", "ban"), decision(2, "ip", "2001:db8::1/128", "ban")}})
	for _, raw := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		if c.GetBan(raw) == nil {
			t.Fatalf("miss %s", raw)
		}
	}
	for _, raw := range []string{"2001:db8::2", "::192.0.2.1", "198.51.100.1"} {
		if c.GetBan(raw) != nil {
			t.Fatalf("cross-family inference %s", raw)
		}
	}
}
func TestCacheConcurrentAndStaleExpiry(t *testing.T) {
	now := time.Now()
	cache := NewCacheWithClock(func() time.Time { return now })
	short := decision(1, "ip", "192.0.2.1", "ban")
	short.Duration = str("1s")
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{short}})
	cache.Apply(&models.DecisionsStreamResponse{Deleted: []*models.Decision{short}})
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{decision(1, "ip", "198.51.100.1", "ban")}})
	now = now.Add(2 * time.Second)
	cache.Expire()
	if cache.GetBan("198.51.100.1") == nil {
		t.Fatal("stale expiry removed new decision")
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{decision(2, "ip", "192.0.2.1", "ban")}})
				cache.LookupBan("192.0.2.1")
				cache.GetBan("198.51.100.1")
				cache.Expire()
			}
		}()
	}
	wg.Wait()
}
func BenchmarkRequestLookup(b *testing.B) {
	c := largeBlocklistCache()
	for b.Loop() {
		if _, ok := c.LookupBan("10.0.0.1"); !ok {
			b.Fatal("missing ban")
		}
	}
}
func BenchmarkIPv6Hit(b *testing.B) {
	c := NewCache()
	c.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{decision(1, "range", "2001:db8::/32", "ban")}})
	for b.Loop() {
		c.LookupBan("2001:db8::1")
	}
}
func BenchmarkExpiredPrefix(b *testing.B) {
	now := time.Now()
	c := NewCacheWithClock(func() time.Time { return now })
	d := decision(1, "ip", "192.0.2.1", "ban")
	d.Duration = str("1s")
	c.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{d}})
	now = now.Add(time.Minute)
	for b.Loop() {
		c.LookupBan("192.0.2.1")
	}
}
func BenchmarkConcurrentLookupUpdate(b *testing.B) {
	c := largeBlocklistCache()
	ctx := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx:
				return
			default:
				c.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{decision(100001, "ip", "192.0.2.1", "ban")}})
			}
		}
	}()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.LookupBan("10.0.0.1")
		}
	})
	close(ctx)
	<-done
}
