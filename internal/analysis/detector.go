package analysis

import (
	"sync"
	"time"
)

// Detector identifies port-scan behaviour based on how many distinct ports an
// IP touches within a configurable sliding window.
type Detector struct {
	mu            sync.Mutex
	portScans     map[string]*portScanTracker
	scanWindow    time.Duration
	scanThreshold int
	done          chan struct{}
}

type portScanTracker struct {
	ports     map[int]time.Time
	firstSeen time.Time
}

// NewDetector creates a Detector with the given window and port threshold.
// Passing zero values applies safe defaults (60 s window, 5 distinct ports).
func NewDetector(scanWindow time.Duration, threshold int) *Detector {
	if scanWindow <= 0 {
		scanWindow = 60 * time.Second
	}
	if threshold <= 0 {
		threshold = 5
	}

	d := &Detector{
		portScans:     make(map[string]*portScanTracker),
		scanWindow:    scanWindow,
		scanThreshold: threshold,
		done:          make(chan struct{}),
	}
	go d.cleanup()
	return d
}

// Stop terminates the background cleanup goroutine. Safe to call multiple times.
func (d *Detector) Stop() {
	select {
	case <-d.done:
		// already closed
	default:
		close(d.done)
	}
}

// RecordPort notes that ip connected to port and returns true when the number
// of distinct ports within the scan window reaches the threshold.
func (d *Detector) RecordPort(ip string, port int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-d.scanWindow)

	tracker, ok := d.portScans[ip]
	if !ok {
		tracker = &portScanTracker{
			ports:     make(map[int]time.Time),
			firstSeen: now,
		}
		d.portScans[ip] = tracker
	}

	// Evict ports whose timestamps have fallen outside the window.
	for p, ts := range tracker.ports {
		if ts.Before(cutoff) {
			delete(tracker.ports, p)
		}
	}

	tracker.ports[port] = now

	return len(tracker.ports) >= d.scanThreshold
}

// cleanup runs as a background goroutine and removes trackers for IPs that
// have had no activity within twice the scan window. Exits when Stop() is called.
func (d *Detector) cleanup() {
	ticker := time.NewTicker(d.scanWindow * 2)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.mu.Lock()
			cutoff := time.Now().Add(-d.scanWindow)
			for ip, tracker := range d.portScans {
				for p, ts := range tracker.ports {
					if ts.Before(cutoff) {
						delete(tracker.ports, p)
					}
				}
				if len(tracker.ports) == 0 {
					delete(d.portScans, ip)
				}
			}
			d.mu.Unlock()
		}
	}
}