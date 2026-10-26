package analysis

import (
	"testing"
	"time"
)

func TestDetectorReportsOncePerBurst(t *testing.T) {
	d := NewDetector(time.Minute, 3)
	defer d.Stop()
	firsts := 0
	for _, p := range []int{21, 22, 80, 3306, 8080} {
		scanning, first := d.RecordPort("1.2.3.4", p)
		if first {
			firsts++
		}
		if p == 80 && !scanning {
			t.Error("third distinct port should flag a scan")
		}
	}
	if firsts != 1 {
		t.Errorf("scan reported %d times, want once", firsts)
	}
}

func TestRateLimiter(t *testing.T) {
	r := NewRateLimiter(2, 0)
	defer r.Stop()
	if !r.Check("a") || !r.Check("a") || r.Check("a") {
		t.Error("per-minute limit not enforced")
	}
	if !r.Check("b") {
		t.Error("limits must be per IP")
	}
}
