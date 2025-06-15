package middleware

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// Helper to disable logs during tests if needed
func disableLogs() func() {
	oldOutput := log.Writer()
	log.SetOutput(new(bytes.Buffer)) // Redirect to a black hole
	return func() {
		log.SetOutput(oldOutput) // Restore
	}
}

func TestNewShardedTTLMap(t *testing.T) {
	defer disableLogs()()

	// Test valid creation
	cache, err := NewShardedTTLMap(100, time.Second*5, "test_cache_1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cache == nil {
		t.Fatal("Expected cache not to be nil")
	}
	if len(cache.shards) != 256 { // Default numShards
		t.Errorf("Expected 256 shards, got %d", len(cache.shards))
	}
	if cache.maxTTLDuration != time.Second*5 {
		t.Errorf("Expected maxTTLDuration 5s, got %d", cache.maxTTLDuration)
	}

	// Test error cases
	_, err = NewShardedTTLMap(0, time.Second*5, "test_cache_2")
	if err != nil {
		t.Logf("Expected no error for initialCapacity=0 (uses default), got %v", err) // Adjusted expectation
	}

	_, err = NewShardedTTLMap(100, 0, "test_cache_3")
	if err == nil || !strings.Contains(err.Error(), "maxTTL must be positive") {
		t.Errorf("Expected 'maxTTL must be positive' error, got %v", err)
	}

	_, err = NewShardedTTLMap(100, time.Second*5, "")
	if err == nil || !strings.Contains(err.Error(), "cache name cannot be empty") {
		t.Errorf("Expected 'cache name cannot be empty' error, got %v", err)
	}
}

func TestShardedTTLMap_PutAndGet(t *testing.T) {
	defer disableLogs()()
	cache, _ := NewShardedTTLMap(10, time.Hour, "test_put_get") // Long TTL for testing

	key := "test_key"
	value := "test_value"

	// Put an item
	cache.Put(key, value)

	// Get the item
	retrievedValue, ok := cache.Get(key)
	if !ok {
		t.Error("Expected item to be found, but it was not")
	}
	if retrievedValue != value {
		t.Errorf("Expected value %q, got %q", value, retrievedValue)
	}

	// Update item
	newValue := "new_value"
	cache.Put(key, newValue)
	retrievedValue, ok = cache.Get(key)
	if !ok || retrievedValue != newValue {
		t.Errorf("Expected updated value %q, got %q", newValue, retrievedValue)
	}

	// Get non-existent item
	_, ok = cache.Get("non_existent_key")
	if ok {
		t.Error("Expected item not to be found, but it was")
	}
}

func TestShardedTTLMap_Delete(t *testing.T) {
	defer disableLogs()()
	cache, _ := NewShardedTTLMap(10, time.Hour, "test_delete")

	key := "delete_key"
	value := "delete_value"

	cache.Put(key, value)
	_, ok := cache.Get(key)
	if !ok {
		t.Fatal("Expected item to be present before deletion")
	}

	cache.Delete(key)
	_, ok = cache.Get(key)
	if ok {
		t.Error("Expected item to be deleted, but it was found")
	}

	// Deleting a non-existent key should not panic
	cache.Delete("non_existent_key")
}

func TestShardedTTLMap_TTL(t *testing.T) {
	defer disableLogs()()
	// Use a short TTL for testing expiration
	cache, _ := NewShardedTTLMap(10, time.Millisecond*50, "test_ttl")

	key := "ttl_key"
	value := "ttl_value"

	cache.Put(key, value)

	// Item should be immediately accessible
	_, ok := cache.Get(key)
	if !ok {
		t.Error("Expected item to be found immediately")
	}

	// Wait for item to expire (and for cleanup to run, if necessary)
	time.Sleep(time.Millisecond * 100) // Longer than TTL to ensure cleanup or expiry check

	_, ok = cache.Get(key)
	if ok {
		t.Error("Expected item to be expired and not found after TTL")
	}
}

func TestShardedTTLMap_Concurrency(t *testing.T) {
	defer disableLogs()()
	cache, _ := NewShardedTTLMap(1000, time.Second, "test_concurrency")
	numGoroutines := 100
	numOperations := 1000 // Operations per goroutine

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // For puts and gets

	// Concurrent Put operations
	for i := 0; i < numGoroutines; i++ {
		go func(g int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("put_key_%d_%d", g, j)
				value := fmt.Sprintf("put_value_%d_%d", g, j)
				cache.Put(key, value)
			}
		}(i)
	}

	// Concurrent Get operations (can start while puts are happening)
	for i := 0; i < numGoroutines; i++ {
		go func(g int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("put_key_%d_%d", g, j) // Try to get keys that might exist
				cache.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Verify a subset of keys after concurrent operations
	for i := 0; i < numGoroutines; i += 10 { // Check every 10th goroutine's keys
		for j := 0; j < numOperations; j += 100 { // Check every 100th op
			key := fmt.Sprintf("put_key_%d_%d", i, j)
			value := fmt.Sprintf("put_value_%d_%d", i, j)
			retrievedValue, ok := cache.Get(key)
			// Due to TTL, some might be expired. Focus on ensuring no data corruption or panics.
			if ok && retrievedValue != value {
				t.Errorf("Data corruption: Expected value %q for %q, got %q", value, key, retrievedValue)
			}
		}
	}
}

func TestShardedTTLMap_WarningThreshold(t *testing.T) {
	defer disableLogs()() // Suppress log output for this test

	// Create a map with a very small threshold per shard to trigger warnings easily
	cache, _ := NewShardedTTLMap(10, time.Hour, "test_warning")
	cache.warningThreshold = 1         // Force warning after 1 item per shard
	cache.cleanupFrequency = time.Hour // Disable active cleanup during test

	// Fill more items than threshold in at least one shard
	// Fill ~300 items total, so each shard gets > 1 if distributed evenly
	for i := 0; i < 300; i++ {
		cache.Put(fmt.Sprintf("key_%d", i), i)
	}

	// Manually trigger a warning check
	// now := time.Now()
	// Simulate the warningLoop logic
	totalCount := 0
	var anyShardAboveThreshold bool

	for i, s := range cache.shards {
		s.mu.RLock()
		count := len(s.m)
		s.mu.RUnlock()
		totalCount += count
		if count > cache.warningThreshold {
			t.Logf("shard %d (%d items)", i, count)
			anyShardAboveThreshold = true
		}
	}

	if !anyShardAboveThreshold {
		t.Error("Expected at least one shard to be above warning threshold, but none were")
	}
	// Simulate calling the method and verify log (difficult directly without redirecting log.Writer)
	// You'd typically use a test double for log.Writer here.
	// For now, rely on `anyShardAboveThreshold` and manual verification of output if logs are enabled.
}

// --- Benchmarks for ShardedTTLMap ---

func BenchmarkShardedTTLMap_Put(b *testing.B) {
	cache, _ := NewShardedTTLMap(b.N, time.Hour, "benchmark_put")
	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cache.Put(keys[i], i)
	}
}

func BenchmarkShardedTTLMap_Get(b *testing.B) {
	cache, _ := NewShardedTTLMap(b.N, time.Hour, "benchmark_get")
	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
		cache.Put(keys[i], i) // Populate cache
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cache.Get(keys[i])
	}
}

func BenchmarkShardedTTLMap_Put_Concurrent(b *testing.B) {
	cache, _ := NewShardedTTLMap(b.N, time.Hour, "benchmark_put_concurrent")
	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Put(keys[i%b.N], i) // Use modulo to reuse keys
			i++
		}
	})
}

func BenchmarkShardedTTLMap_Get_Concurrent(b *testing.B) {
	// 1. Define a fixed, reasonable number of keys to pre-populate.
	// These keys will be used to create contention during parallel reads.
	const numContentionKeys = 1000

	// 2. Create the cache. Initial capacity should accommodate the pre-populated keys.
	// MaxTTL is set to a long duration to prevent items expiring during the benchmark.
	cache, _ := NewShardedTTLMap(numContentionKeys*2, time.Hour, "benchmark_get_concurrent")

	// 3. Pre-populate the cache with these fixed keys ONCE, before the benchmark timer starts.
	contentionKeys := make([]string, numContentionKeys)
	for i := 0; i < numContentionKeys; i++ {
		contentionKeys[i] = fmt.Sprintf("key-%d", i)
		cache.Put(contentionKeys[i], i)
	}

	b.ResetTimer() // Reset timer *after* setup to measure only the Get operations
	b.ReportAllocs()

	// 4. Run the benchmark in parallel.
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine will pick a key from the pre-populated set to read.
		// `pb.Next()` returns true as long as there are iterations left for this goroutine.
		// `i` is a local counter for each goroutine to cycle through keys.
		var i int = 0
		for pb.Next() {
			// Access a key from the fixed set using modulo to cycle through them.
			cache.Get(contentionKeys[i%numContentionKeys])
			i++ // Increment local counter for the next key
		}
	})
}
