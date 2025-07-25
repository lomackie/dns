package resolver

import (
	"dns/internal/parser"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type cachedResourceRecord struct {
	record parser.DNSResourceRecord
	expiry time.Time
}

type cacheKey struct {
	Name  string
	Type  parser.RecordType
	Class parser.RecordClass
}

func (ck cacheKey) String() string {
	return fmt.Sprintf("%s; %v; %v", ck.Name, ck.Class, ck.Type)
}

type cache struct {
	records map[cacheKey][]cachedResourceRecord
	logger  *zap.Logger
	mu      sync.RWMutex
}

func (c *cache) ClearExpired(k cacheKey) {
	c.mu.Lock()
	c.logger.Debug("Cleaning up cache", zap.String("Key", k.String()))
	records := getLiveCachedResourceRecords(c.records[k])
	if len(records) > 0 {
		c.records[k] = records
	} else {
		delete(c.records, k)
	}
	c.mu.Unlock()
}

func getLiveCachedResourceRecords(crrs []cachedResourceRecord) []cachedResourceRecord {
	result := make([]cachedResourceRecord, 0, len(crrs))
	for _, crr := range crrs {
		if time.Now().Before(crr.expiry) {
			result = append(result, crr)
		}
	}
	return result
}

func getLiveResourceRecords(crrs []cachedResourceRecord) ([]parser.DNSResourceRecord, bool) {
	hasExpired := false
	result := make([]parser.DNSResourceRecord, 0, len(crrs))
	for _, crr := range crrs {
		if time.Now().Before(crr.expiry) {
			result = append(result, crr.record)
		} else {
			hasExpired = true
		}
	}
	return result, hasExpired
}

func (c *cache) Get(k cacheKey) ([]parser.DNSResourceRecord, bool) {
	c.mu.RLock()
	crrs, ok := c.records[k]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	result, hasExpired := getLiveResourceRecords(crrs)
	if hasExpired {
		go c.ClearExpired(k)
	}
	return result, len(result) > 0
}

func (c *cache) Add(domain string, v parser.DNSResourceRecord) {
	c.mu.Lock()
	k := cacheKey{domain, v.Type, v.Class}
	crrs, ok := c.records[k]
	if !ok {
		crrs = make([]cachedResourceRecord, 0, 1)
	}
	crrs = append(crrs, cachedResourceRecord{
		record: v,
		expiry: time.Now().Add(time.Second * time.Duration(v.TTL)),
	})
	c.records[k] = crrs
	c.mu.Unlock()
}

func NewCache(logger *zap.Logger) *cache {
	return &cache{
		records: make(map[cacheKey][]cachedResourceRecord),
		logger:  logger,
	}
}
