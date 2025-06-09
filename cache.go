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

type ShardedCache interface {
	Put(key string, value interface{})
	Get(key string) (interface{}, bool)
	Delete(key string)
}

// shardedItem holds a cached value and the time it was last accessed.
// lastAccess is stored as a Unix timestamp in milliseconds.
type shardedItem struct {
	value      interface{}
	lastAccess int64
}

type shard struct {
	m  map[string]*shardedItem
	mu sync.RWMutex
}

// ShardedTTLMap is a time-aware sharded cache.
type ShardedTTLMap struct {
	shards           []*shard
	numShards        uint32
	maxTTLDuration   time.Duration // Stores the TTL duration (e.g., 1s, 500ms, 1h)
	name             string
	lastWarning      int64
	cleanupFrequency time.Duration
	warningThreshold int
}

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

func (m *ShardedTTLMap) getShard(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	shardID := h.Sum32() % m.numShards
	return m.shards[shardID]
}

// Put stores a key/value pair without updating lastAccess for existing keys.
func (m *ShardedTTLMap) Put(k string, v interface{}) {
	s := m.getShard(k)
	s.mu.Lock()
	defer s.mu.Unlock()

	it, ok := s.m[k]
	if !ok {
		it = &shardedItem{value: v, lastAccess: time.Now().UnixMilli()}
		s.m[k] = it
	} else {
		it.value = v
	}
}

// Get retrieves a value if it has not expired.
func (m *ShardedTTLMap) Get(k string) (interface{}, bool) {
	s := m.getShard(k)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if it, ok := s.m[k]; ok {
		if time.Now().UnixMilli()-it.lastAccess < m.maxTTLDuration.Milliseconds() {
			return it.value, true
		}
	}
	return nil, false
}

func (m *ShardedTTLMap) Delete(k string) {
	s := m.getShard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

// cleanupLoop periodically removes expired items.
func (m *ShardedTTLMap) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupFrequency)
	defer ticker.Stop()

	for now := range ticker.C {
		nowMilli := now.UnixMilli()
		maxTTLMilli := m.maxTTLDuration.Milliseconds()

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
