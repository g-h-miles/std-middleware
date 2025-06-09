package middleware

import (
	"errors"
	"fmt" // Required for Sprintf in IsAllowed
	"math"
	"net/http"
	"time"
)

// --- Token Bucket Rate Limiter (No Changes) ---
type TokenBucketCache struct {
	count      int
	lastRefill int64
}

type TokenBucketRateLimiter struct {
	cache          ShardedCache
	cachePrefix    string
	bucketCapacity int
	refillRate     float64
}

func NewTokenBucketRateLimiter(identifier string, bucketCapacity int, refillRate float64) (*TokenBucketRateLimiter, error) {
	if bucketCapacity <= 0 {
		return nil, errors.New("token bucket capacity must be positive")
	}
	if refillRate <= 0 {
		return nil, errors.New("token bucket refill rate must be positive")
	}

	storage, err := NewShardedTTLMap(10000, time.Minute*15, "token_bucket_rate_limiter:"+identifier)
	if err != nil {
		return nil, err
	}
	cachePrefix := "tb_rate_limit:" + identifier + ":"

	return &TokenBucketRateLimiter{
		cache:          storage,
		cachePrefix:    cachePrefix,
		bucketCapacity: bucketCapacity,
		refillRate:     refillRate,
	}, nil
}

func (tb *TokenBucketRateLimiter) IsAllowed(key string) bool {
	cacheKey := tb.cachePrefix + key
	currentTime := time.Now().UnixMilli()

	bucketIface, ok := tb.cache.Get(cacheKey)
	var bucket *TokenBucketCache
	if !ok {
		bucket = &TokenBucketCache{
			count:      tb.bucketCapacity,
			lastRefill: currentTime,
		}
	} else {
		bucket = bucketIface.(*TokenBucketCache)
	}

	elapsedTimeMs := currentTime - bucket.lastRefill
	elapsedTimeSeconds := float64(elapsedTimeMs) / 1000.0
	tokensToAdd := int(tb.refillRate * elapsedTimeSeconds)

	tokenCount := int(math.Min(float64(bucket.count+tokensToAdd), float64(tb.bucketCapacity)))

	isAllowed := tokenCount > 0
	if isAllowed {
		tokenCount--
	}

	tb.cache.Put(cacheKey, &TokenBucketCache{
		count:      tokenCount,
		lastRefill: currentTime,
	})

	return isAllowed
}

func TokenBucketMiddleware(limiter *TokenBucketRateLimiter, errorMsg string, statusCode int) Middleware {
	if limiter == nil {
		panic("TokenBucketMiddleware: TokenBucketRateLimiter cannot be nil")
	}
	if errorMsg == "" {
		errorMsg = "Too Many Requests"
	}
	if statusCode == 0 {
		statusCode = http.StatusTooManyRequests // 429
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.RemoteAddr
			if !limiter.IsAllowed(key) {
				http.Error(w, errorMsg, statusCode)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- Fixed Window Rate Limiter (CRITICAL FIXES HERE) ---

// FixedWindowCache: No change required
type FixedWindowCache struct {
	count int
}

type FixedWindowRateLimiter struct {
	cache       ShardedCache
	cachePrefix string
	limit       int
	windowSize  time.Duration
}

// NewFixedWindowRateLimiter: TTL for cache now reflects the actual window duration for the cache entry
func NewFixedWindowRateLimiter(identifier string, limit int, windowSize time.Duration) (*FixedWindowRateLimiter, error) {
	if limit <= 0 {
		return nil, errors.New("fixed window limit must be positive")
	}
	if windowSize <= 0 {
		return nil, errors.New("fixed window size must be positive")
	}

	// The ShardedTTLMap's maxTTLSeconds is the actual expiry.
	// We need it to be *exactly* the windowSize for Fixed Window.
	// The problem was if windowSize was < 1s, its .Seconds() would be 0, causing TTL issues.
	// ShardedTTLMap now uses Milliseconds internally for accuracy, so pass windowSize directly.
	storage, err := NewShardedTTLMap(10000, windowSize, "fixed_window_rate_limiter:"+identifier) // Pass windowSize directly
	if err != nil {
		return nil, err
	}
	cachePrefix := "fw_rate_limit:" + identifier + ":"

	return &FixedWindowRateLimiter{
		cache:       storage,
		cachePrefix: cachePrefix,
		limit:       limit,
		windowSize:  windowSize,
	}, nil
}

// IsAllowed: The CRITICAL FIX for Fixed Window logic.
// It relies on ShardedTTLMap correctly expiring and returning !ok when the window's time is up.
// The key is to generate a window-specific key, and the TTLMap's Put/Get logic handles the rest.
func (fw *FixedWindowRateLimiter) IsAllowed(key string) bool {
	// Calculate the current window ID based on the precise window start time.
	// Use UnixMilli() for current time and windowSize.Milliseconds() for window duration
	// to ensure precise window boundaries, even for sub-second windows.
	windowID := time.Now().UnixMilli() / fw.windowSize.Milliseconds()
	currentWindowCacheKey := fmt.Sprintf("%s%s:%d", fw.cachePrefix, key, windowID)

	bucketIface, ok := fw.cache.Get(currentWindowCacheKey)
	var bucket *FixedWindowCache

	if !ok {
		// This means we are in a new window for this key (or the key never existed).
		// Initialize a new counter for this window.
		bucket = &FixedWindowCache{
			count: 0,
		}
		// ShardedTTLMap.Put will set its internal `lastAccess` to `time.Now().UnixMilli()`
		// when this new bucket is first added. Its TTL will be `fw.windowSize`.
		// This is exactly what we want for a fixed window - its life is tied to its creation.
	} else {
		// We are within an existing window for this key.
		bucket = bucketIface.(*FixedWindowCache)
	}

	isAllowed := bucket.count < fw.limit
	if isAllowed {
		bucket.count++
		// When we Put the bucket back, ShardedTTLMap.Put will update `lastAccess`
		// to `time.Now().UnixMilli()`. This DOES NOT affect the Fixed Window's expiry
		// because the key `currentWindowCacheKey` uniquely identifies this window.
		// When the `windowID` changes (i.e., a new time window begins), a *new*
		// `currentWindowCacheKey` is generated, and `!ok` will be true, creating
		// a fresh counter.
		fw.cache.Put(currentWindowCacheKey, bucket)
	}

	return isAllowed
}

func FixedWindowMiddleware(limiter *FixedWindowRateLimiter, errorMsg string, statusCode int) Middleware {
	if limiter == nil {
		panic("FixedWindowMiddleware: FixedWindowRateLimiter cannot be nil")
	}
	if errorMsg == "" {
		errorMsg = "Too Many Requests"
	}
	if statusCode == 0 {
		statusCode = http.StatusTooManyRequests // 429
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.RemoteAddr
			if !limiter.IsAllowed(key) {
				http.Error(w, errorMsg, statusCode)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
