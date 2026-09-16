package scan

import (
	"context"
	"sync"
	"time"
)

// tokenBucket is a rate limiter.
//
// Written rather than taken as a dependency (golang.org/x/time/rate): it is
// sixty lines, and every dependency in a binary that runs inside a customer
// network is a supply-chain question a reviewer is entitled to ask. "We needed
// a token bucket" is not a good answer to it. See docs/dependencies.md.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	last     time.Time
	now      func() time.Time // injectable for deterministic tests
}

func newTokenBucket(perSecond int) *tokenBucket {
	if perSecond < 1 {
		perSecond = 1
	}
	// A burst of one second's worth: enough to absorb scheduling jitter without
	// ever exceeding the declared rate over any one-second window.
	cap := float64(perSecond)
	return &tokenBucket{
		tokens:   cap,
		capacity: cap,
		rate:     float64(perSecond),
		last:     time.Now(),
		now:      time.Now,
	}
}

// Wait blocks until a token is available or ctx is done.
func (b *tokenBucket) Wait(ctx context.Context) error {
	for {
		wait, ok := b.take()
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// take removes a token if one is available, else returns how long to wait.
func (b *tokenBucket) take() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}
	need := (1 - b.tokens) / b.rate
	d := time.Duration(need * float64(time.Second))
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d, false
}
