package touchque

import (
	"sort"
	"sync"
	"time"
)

// A small in-memory fixed-window rate limiter for NewRelayHandler's pre-auth
// routes. It protects the partner's own server (and their TouchQue quota) from
// scripted abuse of routes anyone on the internet can call. It is per process:
// behind several instances, each keeps its own counters, which still caps abuse
// per instance. Use your own shared limiter in front of the handler if you need
// one global budget, and set RateLimitOptions.Disabled here.

// RateLimitOptions configures the relay handler's built-in limiter. Zero
// values mean the defaults.
type RateLimitOptions struct {
	// Disabled turns the built-in limiter off (e.g. you already rate limit
	// in front of the handler).
	Disabled bool
	// Window is the window length. Default 60 s.
	Window time.Duration
	// PerIP is the number of requests per client IP per route per window. Default 20.
	PerIP int
	// PerUser is the number of requests per username per route per window
	// (routes that name a user). Default 5.
	PerUser int
}

const limiterMaxKeys = 50_000

type limiterEntry struct {
	count   int
	resetAt time.Time
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	window  time.Duration
	perIP   int
	perUser int
	maxKeys int
	now     func() time.Time
}

func newFixedWindowLimiter(opts RateLimitOptions) *fixedWindowLimiter {
	l := &fixedWindowLimiter{
		entries: make(map[string]*limiterEntry),
		window:  opts.Window,
		perIP:   opts.PerIP,
		perUser: opts.PerUser,
		maxKeys: limiterMaxKeys,
		now:     time.Now,
	}
	if l.window <= 0 {
		l.window = 60 * time.Second
	}
	if l.perIP <= 0 {
		l.perIP = 20
	}
	if l.perUser <= 0 {
		l.perUser = 5
	}
	return l
}

// hit counts one request for key. It returns the seconds to wait when the
// count is over limit, otherwise 0.
func (l *fixedWindowLimiter) hit(key string, limit int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok || !e.resetAt.After(now) {
		if !ok && len(l.entries) >= l.maxKeys {
			l.prune(now)
		}
		e = &limiterEntry{resetAt: now.Add(l.window)}
		l.entries[key] = e
	}
	e.count++
	if e.count <= limit {
		return 0
	}
	ms := e.resetAt.Sub(now).Milliseconds()
	wait := int((ms + 999) / 1000)
	if wait < 1 {
		wait = 1
	}
	return wait
}

// prune drops expired windows. If the map is still full (a flood of distinct
// keys), it drops the oldest half rather than grow without bound. Called with
// l.mu held.
func (l *fixedWindowLimiter) prune(now time.Time) {
	for k, v := range l.entries {
		if !v.resetAt.After(now) {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.maxKeys {
		return
	}
	keys := make([]string, 0, len(l.entries))
	for k := range l.entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return l.entries[keys[i]].resetAt.Before(l.entries[keys[j]].resetAt) })
	for _, k := range keys[:len(keys)/2] {
		delete(l.entries, k)
	}
}
