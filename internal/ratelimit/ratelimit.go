package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]bucket
	now     func() time.Time
}

type bucket struct {
	start time.Time
	count int
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		buckets: map[string]bucket{},
		now:     time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 || l.window <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b.start.IsZero() || now.Sub(b.start) >= l.window {
		l.buckets[key] = bucket{start: now, count: 1}
		l.pruneLocked(now)
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	l.buckets[key] = b
	return true
}

func (l *Limiter) pruneLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.start) >= l.window {
			delete(l.buckets, key)
		}
	}
}
