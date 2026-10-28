package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// MaxAttempts is how many starts an update gets to come up and stay up
// (GoodAfter) before the launcher puts the previous version back.
const MaxAttempts = 3

// GoodAfter is how long a newly applied version must run before it counts
// as good; until then every start counts as an attempt.
var GoodAfter = 45 * time.Second

// Environment variables the launcher hands to the staged binary.
const (
	EnvBase = "SKYGUARD_UPDATE_BASE" // the binary the service starts
	EnvSlot = "SKYGUARD_UPDATE_SLOT" // the version it handed over to
)

// Slot is one staged version.
type Slot struct {
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	AppliedAt time.Time `json:"applied_at"`
	Good      bool      `json:"good"`     // it came up and stayed up
	Attempts  int       `json:"attempts"` // starts while not yet good
}

// Event is one thing that happened to the installed version.
type Event struct {
	At     time.Time `json:"at"`
	From   string    `json:"from,omitempty"`
	To     string    `json:"to,omitempty"`
	Result string    `json:"result"` // applied, running, rolled-back, replaced
	Reason string    `json:"reason,omitempty"`
}

// State is kept in <data_dir>/updates/state.json.
type State struct {
	Current  *Slot   `json:"current,omitempty"`  // what the launcher starts
	Previous *Slot   `json:"previous,omitempty"` // what it goes back to
	Failure  *Event  `json:"failure,omitempty"`  // the last update that was undone
	History  []Event `json:"history"`
}

// Dir is where updates live.
func Dir(dataDir string) string { return filepath.Join(dataDir, "updates") }

func statePath(dataDir string) string { return filepath.Join(Dir(dataDir), "state.json") }

// LoadState reads the state; a missing file is an empty state.
func LoadState(dataDir string) (*State, error) {
	st := &State{History: []Event{}}
	b, err := os.ReadFile(statePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return &State{History: []Event{}}, fmt.Errorf("%s is unreadable: %w", statePath(dataDir), err)
	}
	if st.History == nil {
		st.History = []Event{}
	}
	return st, nil
}

// Save writes the state atomically.
func (st *State) Save(dataDir string) error {
	if err := os.MkdirAll(Dir(dataDir), 0o750); err != nil {
		return err
	}
	if len(st.History) > 30 {
		st.History = st.History[len(st.History)-30:]
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dataDir))
}

func (st *State) record(e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	st.History = append(st.History, e)
}

// Launch runs first in every start of the binary the service starts (the
// base). It returns the staged binary to hand over to, or "" to go on as
// the base. It counts the staged version's attempts and puts the previous
// one back after MaxAttempts starts that did not stay up.
func Launch(dataDir, self string, base Build, logger *slog.Logger) string {
	st, err := LoadState(dataDir)
	if err != nil {
		logger.Error("update state unreadable; starting the installed version", "error", err)
		return ""
	}
	c := st.Current
	if c == nil {
		return ""
	}
	// The installed binary may have been replaced since (a rebuilt image, a
	// new package): the newest choice wins.
	newer := false
	if IsRelease(base.Version) {
		newer = Compare(base.Version, c.Version) >= 0
	} else if fi, err := os.Stat(self); err == nil && fi.ModTime().After(c.AppliedAt) {
		newer = true
	}
	if newer {
		st.record(Event{From: c.Version, To: base.Version, Result: "replaced", Reason: "the installed binary is newer than the applied update"})
		st.Current, st.Previous = nil, nil
		_ = st.Save(dataDir)
		logger.Info("the installed binary is newer than the applied update; using it", "installed", base.Version, "update", c.Version)
		return ""
	}
	if !c.Good {
		c.Attempts++
		if c.Attempts > MaxAttempts {
			rollback(st, c, fmt.Sprintf("it did not stay up for %s in %d starts", GoodAfter, MaxAttempts))
			_ = st.Save(dataDir)
			logger.Error("update undone: the new version kept failing", "version", c.Version, "back_to", nameOf(st.Current, base.Version))
			if st.Current == nil {
				return ""
			}
			c = st.Current
		}
		_ = st.Save(dataDir)
	}
	if fi, err := os.Stat(c.Path); err != nil || fi.Mode()&0o111 == 0 {
		rollback(st, c, "its binary is missing or not executable")
		_ = st.Save(dataDir)
		logger.Error("update undone: its binary is gone", "path", c.Path)
		return Launch(dataDir, self, base, logger) // the previous one, if any
	}
	return c.Path
}

// rollback makes the previous good version current again, or none.
func rollback(st *State, failed *Slot, reason string) {
	e := Event{At: time.Now().UTC(), From: failed.Version, Result: "rolled-back", Reason: reason}
	if p := st.Previous; p != nil && p.Good && p.Version != failed.Version {
		st.Current, st.Previous = p, nil
		e.To = p.Version
	} else {
		st.Current, st.Previous = nil, nil
		e.To = "installed"
	}
	st.Failure = &e
	st.record(e)
}

func nameOf(s *Slot, base string) string {
	if s == nil {
		return base + " (installed)"
	}
	return s.Version
}

// Exec replaces this process with path, keeping the arguments and telling
// it which base handed over.
func Exec(path, base, version string) error {
	env := append(os.Environ(), EnvBase+"="+base, EnvSlot+"="+version)
	return syscall.Exec(path, append([]string{path}, os.Args[1:]...), env)
}

// Restart replaces this process with the base binary, which then starts
// whatever the state says. Call it after the server has stopped.
func Restart(base string) error {
	env := []string{}
	for _, kv := range os.Environ() {
		if !hasPrefix(kv, EnvBase+"=") && !hasPrefix(kv, EnvSlot+"=") {
			env = append(env, kv)
		}
	}
	return syscall.Exec(base, append([]string{base}, os.Args[1:]...), env)
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// MarkGood records that version came up and stayed up.
func MarkGood(dataDir, version string) error {
	st, err := LoadState(dataDir)
	if err != nil || st.Current == nil || st.Current.Version != version || st.Current.Good {
		return err
	}
	st.Current.Good, st.Current.Attempts = true, 0
	st.record(Event{To: version, Result: "running"})
	return st.Save(dataDir)
}
