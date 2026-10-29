package inventory

import (
	"strings"
	"time"
	"unicode"
)

// Target is one scanned place: the host, a container or an instance.
type Target struct {
	Key     string `json:"key"`  // host, docker:<id>, incus:<name>
	Kind    string `json:"kind"` // host, docker, incus
	Name    string `json:"name"`
	Image   string `json:"image,omitempty"`
	Running bool   `json:"running"`
	Via     string `json:"via"` // how the files were read

	OS       *OSInfo   `json:"os,omitempty"`
	Apps     []App     `json:"apps"`     // the software people ask about: servers, runtimes, frameworks, panels
	Packages []Package `json:"packages"` // everything with a version a vulnerability database knows
	Notes    []string  `json:"notes,omitempty"`

	ScannedAt time.Time `json:"scanned_at"`
	TookMS    int64     `json:"took_ms"`
	Error     string    `json:"error,omitempty"`

	Findings      []Finding  `json:"findings"`
	VulnCheckedAt *time.Time `json:"vuln_checked_at,omitempty"`
}

// OSInfo is the distribution, from os-release.
type OSInfo struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"` // OSV's name for its packages, "" when OSV has none
}

// App is one notable piece of software.
type App struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`  // server, runtime, framework, panel, app, image
	Where   string `json:"where"` // the file or field it was read from
}

// Package is one versioned component in a vulnerability database's terms.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // Debian:12, Alpine:v3.20, npm, Go, PyPI…
	Manager   string `json:"manager"`   // dpkg, apk, npm, go, pip
	Binary    string `json:"binary,omitempty"`
}

// Finding is one known vulnerability in one package.
type Finding struct {
	ID       string   `json:"id"` // OSV ID: GHSA-…, DEBIAN-CVE-…, GO-…
	CVEs     []string `json:"cves,omitempty"`
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Fixed    string   `json:"fixed,omitempty"` // the first version without it, "" when none yet
	Severity string   `json:"severity"`        // critical, high, medium, low, unknown
	Score    float64  `json:"score,omitempty"`
	Summary  string   `json:"summary"`
	URL      string   `json:"url"`
	Note     string   `json:"note,omitempty"` // a distribution's own urgency
}

// Limits on what one target may hand back.
const (
	maxPackages = 20000
	maxApps     = 300
	maxText     = 160
)

// clean makes text read from a target safe to keep and show: printable,
// one line, short.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxText {
		s = s[:maxText]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

func (t *Target) addApp(a App) {
	a.Name, a.Version, a.Where = clean(a.Name), clean(a.Version), clean(a.Where)
	if a.Name == "" || len(t.Apps) >= maxApps {
		return
	}
	for i, x := range t.Apps {
		if strings.EqualFold(x.Name, a.Name) {
			// keep the one with a version; the first source otherwise
			if x.Version == "" && a.Version != "" {
				t.Apps[i] = a
			}
			return
		}
	}
	t.Apps = append(t.Apps, a)
}

func (t *Target) addPackage(p Package) {
	p.Name, p.Version, p.Binary = clean(p.Name), clean(p.Version), clean(p.Binary)
	if p.Name == "" || p.Version == "" || len(t.Packages) >= maxPackages {
		return
	}
	t.Packages = append(t.Packages, p)
}

func (t *Target) note(s string) { t.Notes = append(t.Notes, s) }
