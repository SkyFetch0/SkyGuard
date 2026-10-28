// Package update keeps SkyGuard current without git, a compiler or a
// rebuilt image: it looks for new releases on GitHub, downloads the binary
// for this machine, checks its checksum and signature, makes sure it runs
// and accepts the current config, backs up the database and the config, and
// stages it in the data directory. The binary that the service starts (the
// one in the image or in /usr/local/bin) then hands over to the staged one at
// every start, and takes over again by itself if the staged one keeps
// failing: an update can be undone, and a bad one undoes itself.
package update

import (
	"strconv"
	"strings"
)

// Build describes the running binary; main fills it in from -ldflags.
type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

// IsRelease reports whether v is a release version rather than "dev" or a
// local build.
func IsRelease(v string) bool {
	_, ok := parse(v)
	return ok
}

type semver struct {
	n   [3]int
	pre string
}

func parse(v string) (semver, bool) {
	var s semver
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, s.pre = v[:i], v[i+1:]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return s, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return s, false
		}
		s.n[i] = n
	}
	return s, true
}

// Compare orders two versions like semver: -1, 0 or 1. A version that does
// not parse ("dev") sorts before every release.
func Compare(a, b string) int {
	x, okx := parse(a)
	y, oky := parse(b)
	switch {
	case !okx && !oky:
		return 0
	case !okx:
		return -1
	case !oky:
		return 1
	}
	for i := range x.n {
		if x.n[i] != y.n[i] {
			if x.n[i] < y.n[i] {
				return -1
			}
			return 1
		}
	}
	// 1.2.0-rc.1 < 1.2.0
	switch {
	case x.pre == y.pre:
		return 0
	case x.pre == "":
		return 1
	case y.pre == "":
		return -1
	}
	return comparePre(x.pre, y.pre)
}

func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		x, errx := strconv.Atoi(as[i])
		y, erry := strconv.Atoi(bs[i])
		switch {
		case errx == nil && erry == nil:
			if x < y {
				return -1
			}
			return 1
		case errx == nil:
			return -1
		case erry == nil:
			return 1
		case as[i] < bs[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}
