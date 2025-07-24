package resolver

import (
	"dns/internal/parser"
	"net"
	"testing"
	"time"
)

func makeARecord(name string, ttl uint32) parser.DNSResourceRecord {
	return parser.DNSResourceRecord{
		Name:  name,
		Type:  parser.RTA,
		Class: parser.RCIN,
		TTL:   ttl,
		RData: parser.ARecord{IP: net.IPv4(127, 0, 0, 1)},
	}
}

func TestCache_AddAndGet_NoExpiry(t *testing.T) {
	c := NewCache()
	domain := "example.com."
	key := cacheKey{Name: domain, Type: parser.RTA, Class: parser.RCIN}
	record := makeARecord(domain, 60)

	c.Add(domain, record)

	got, ok := c.Get(key)
	if !ok || len(got) != 1 {
		t.Fatalf("expected 1 record, got %v", got)
	}

	if got[0].Name != "example.com." {
		t.Errorf("expected name 'example.com.', got %v", got[0].Name)
	}
}

func TestCache_ExpiredRecordIsNotReturned(t *testing.T) {
	c := NewCache()
	domain := "expired.com."
	key := cacheKey{Name: domain, Type: parser.RTA, Class: parser.RCIN}
	record := makeARecord(domain, 1)

	c.Add(domain, record)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	got, ok := c.Get(key)
	if ok || len(got) != 0 {
		t.Fatalf("expected expired record to be purged, got %v", got)
	}
}

func TestCache_AddMultipleAndRetrieve(t *testing.T) {
	c := NewCache()
	domain := "multi.com."
	key := cacheKey{Name: domain, Type: parser.RTA, Class: parser.RCIN}

	r1 := makeARecord(domain, 10)
	r2 := makeARecord(domain, 10)

	c.Add(domain, r1)
	c.Add(domain, r2)

	got, ok := c.Get(key)
	if !ok || len(got) != 2 {
		t.Fatalf("expected 2 records, got %v", got)
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewCache()
	domain := "concurrent.com."
	rr := makeARecord(domain, 10)

	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		go func() {
			c.Add(domain, rr)
		}()
		go func() {
			c.Get(cacheKey{rr.Name, rr.Type, rr.Class})
		}()
	}

	time.Sleep(1 * time.Second)

	records, ok := c.Get(cacheKey{rr.Name, rr.Type, rr.Class})
	if !ok || len(records) == 0 {
		t.Fatal("expected record to exist after concurrent access")
	}
}

func TestCache_ClearExpiredCleansUp(t *testing.T) {
	c := NewCache()
	domain := "cleanup.com."
	valid := makeARecord(domain, 5)
	expired := makeARecord(domain, 1)

	c.Add(domain, valid)
	c.Add(domain, expired)

	time.Sleep(2 * time.Second)

	records, ok := c.Get(cacheKey{domain, valid.Type, valid.Class})
	if !ok || len(records) != 1 {
		t.Fatalf("expected 1 live record, got %v", records)
	}

	time.Sleep(100 * time.Millisecond)

	internal := c.GetInternal()
	key := cacheKey{Name: domain, Type: valid.Type, Class: valid.Class}
	cached := internal[key]
	if len(cached) != 1 {
		t.Errorf("expected 1 cached record after cleanup, got %d", len(cached))
	}
}

func (c *cache) GetInternal() map[cacheKey][]cachedResourceRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := make(map[cacheKey][]cachedResourceRecord, len(c.records))
	for k, v := range c.records {
		cp[k] = append([]cachedResourceRecord(nil), v...)
	}
	return cp
}
