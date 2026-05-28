package analysis

import (
	"sync"
	"time"
)

// RateLimiter enforces per-IP sliding-window rate limits.
type RateLimiter struct {
	mu          sync.Mutex
	perMinute   int
	perHour     int
	connections map[string]*ipConnections
	done        chan struct{}
}

type ipConnections struct {
	minuteWindow []time.Time
	hourWindow   []time.Time
}

// NewRateLimiter creates a RateLimiter and starts the background cleanup goroutine.
func NewRateLimiter(perMinute, perHour int) *RateLimiter {
	r := &RateLimiter{
		perMinute:   perMinute,
		perHour:     perHour,
		connections: make(map[string]*ipConnections),
		done:        make(chan struct{}),
	}
	go r.cleanup()
	return r
}

// Stop terminates the background cleanup goroutine. Safe to call multiple times.
func (r *RateLimiter) Stop() {
	select {
	case <-r.done:
		// already closed
	default:
		close(r.done)
	}
}

// Check records a connection attempt for ip and returns true if it is within
// the configured limits, false if either limit is exceeded.
func (r *RateLimiter) Check(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	minuteAgo := now.Add(-time.Minute)
	hourAgo := now.Add(-time.Hour)

	conn, ok := r.connections[ip]
	if !ok {
		conn = &ipConnections{}
		r.connections[ip] = conn
	}

	// Evict stale entries from both windows.
	conn.minuteWindow = filterAfter(conn.minuteWindow, minuteAgo)
	conn.hourWindow = filterAfter(conn.hourWindow, hourAgo)

	// Check limits before recording this attempt.
	if r.perMinute > 0 && len(conn.minuteWindow) >= r.perMinute {
		return false
	}
	if r.perHour > 0 && len(conn.hourWindow) >= r.perHour {
		return false
	}

	conn.minuteWindow = append(conn.minuteWindow, now)
	conn.hourWindow = append(conn.hourWindow, now)
	return true
}

// cleanup removes entries for IPs that have had no activity in the last hour.
// Runs as a background goroutine every 5 minutes. Exits when Stop() is called.
func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.mu.Lock()
			cutoff := time.Now().Add(-time.Hour)
			for ip, conn := range r.connections {
				conn.minuteWindow = filterAfter(conn.minuteWindow, time.Now().Add(-time.Minute))
				conn.hourWindow = filterAfter(conn.hourWindow, cutoff)
				if len(conn.minuteWindow) == 0 && len(conn.hourWindow) == 0 {
					delete(r.connections, ip)
				}
			}
			r.mu.Unlock()
		}
	}
}

// filterAfter returns only the timestamps that are after cutoff.
func filterAfter(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[i] = t
			i++
		}
	}
	return times[:i]
}