package middleware

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"strings"
	"sync"
	"time"
)

// ShardedCache interface remains the same
type ShardedCache interface {
	Put(key string, value interface{})
	Get(key string) (interface{}, bool)
	Delete(key string)
}

// shardedItem: lastAccess stores Unix timestamp in MILLISECONDS
type shardedItem struct {
	value      interface{}
	lastAccess int64 // Unix timestamp in MILLISECONDS
}

// shard remains the same
type shard struct {
	m  map[string]*shardedItem
	mu sync.RWMutex
}

// ShardedTTLMap: maxTTLDuration is time.Duration
type ShardedTTLMap struct {
	shards           []*shard
	numShards        uint32
	maxTTLDuration   time.Duration // Stores the TTL duration (e.g., 1s, 500ms, 1h)
	name             string
	lastWarning      int64
	cleanupFrequency time.Duration
	warningThreshold int
}

// NewShardedTTLMap remains the same
func NewShardedTTLMap(initialCapacity int, maxTTL time.Duration, name string) (*ShardedTTLMap, error) {
	if initialCapacity <= 0 {
		initialCapacity = 1000
	}
	if maxTTL <= 0 {
		return nil, errors.New("maxTTL must be positive")
	}
	if name == "" {
		return nil, errors.New("cache name cannot be empty")
	}

	numShards := uint32(256)
	if initialCapacity < int(numShards) {
		initialCapacity = int(numShards)
	}

	shards := make([]*shard, numShards)
	for i := 0; i < int(numShards); i++ {
		shards[i] = &shard{
			m: make(map[string]*shardedItem, initialCapacity/int(numShards)),
		}
	}

	m := &ShardedTTLMap{
		shards:           shards,
		numShards:        numShards,
		maxTTLDuration:   maxTTL,
		name:             name,
		lastWarning:      0,
		cleanupFrequency: time.Second,
		warningThreshold: initialCapacity / int(numShards) * 2,
	}

	go m.cleanupLoop()
	go m.warningLoop()

	return m, nil
}

// getShard remains the same
func (m *ShardedTTLMap) getShard(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	shardID := h.Sum32() % m.numShards
	return m.shards[shardID]
}

// Put: Store lastAccess in MILLISECONDS. Does NOT update lastAccess on existing keys.
func (m *ShardedTTLMap) Put(k string, v interface{}) {
	s := m.getShard(k)
	s.mu.Lock()
	defer s.mu.Unlock()

	it, ok := s.m[k]
	if !ok { // If item does NOT exist, create it and set its creation time
		it = &shardedItem{
			value:      v,
			lastAccess: time.Now().UnixMilli(), // Set creation time in MILLISECONDS
		}
		s.m[k] = it
	} else { // If item EXISTS, just update its value (DO NOT update lastAccess)
		it.value = v
	}
}

// Get: Compare using MILLISECONDS
func (m *ShardedTTLMap) Get(k string) (interface{}, bool) {
	s := m.getShard(k)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if it, ok := s.m[k]; ok {
		// Compare current time in MILLISECONDS with lastAccess in MILLISECONDS
		// and maxTTLDuration in MILLISECONDS.
		if time.Now().UnixMilli()-it.lastAccess < m.maxTTLDuration.Milliseconds() {
			return it.value, true
		}
	}
	return nil, false
}

// Delete remains the same
func (m *ShardedTTLMap) Delete(k string) {
	s := m.getShard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

// cleanupLoop: Compare using MILLISECONDS
func (m *ShardedTTLMap) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupFrequency)
	defer ticker.Stop()

	for now := range ticker.C {
		nowMilli := now.UnixMilli()                    // Get current time in MILLISECONDS
		maxTTLMilli := m.maxTTLDuration.Milliseconds() // Get TTL in MILLISECONDS

		for _, s := range m.shards {
			s.mu.Lock()
			for k, v := range s.m {
				if nowMilli-v.lastAccess >= maxTTLMilli {
					delete(s.m, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// warningLoop remains the same
func (m *ShardedTTLMap) warningLoop() {
	ticker := time.NewTicker(time.Hour * 24)
	defer ticker.Stop()

	for now := range ticker.C {
		totalCount := 0
		shardWarnings := make([]string, 0, m.numShards)

		for i, s := range m.shards {
			s.mu.RLock()
			count := len(s.m)
			s.mu.RUnlock()
			totalCount += count
			if count > m.warningThreshold {
				shardWarnings = append(shardWarnings, fmt.Sprintf("shard %d (%d items)", i, count))
			}
		}

		warningWindowMs := (time.Hour * 24).Milliseconds()
		if totalCount > m.warningThreshold*int(m.numShards) && (now.UnixMilli()-m.lastWarning) > warningWindowMs {
			log.Printf("ShardedTTLMap %s total size of %d is above warning threshold. Problematic shards: %v", m.name, totalCount, strings.Join(shardWarnings, ", "))
			m.lastWarning = now.UnixMilli()
		} else if totalCount <= m.warningThreshold*int(m.numShards) && m.lastWarning != 0 {
			if (now.UnixMilli() - m.lastWarning) > warningWindowMs {
				log.Printf("ShardedTTLMap %s total size of %d is now below warning threshold. Resetting warning state.", m.name, totalCount)
				m.lastWarning = 0
			}
		}
	}
}
