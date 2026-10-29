package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// OSV looks packages up in OSV.dev, the open vulnerability database that
// gathers the advisories of Debian, Ubuntu, Alpine, GitHub (npm, PyPI…) and
// the Go project. Only package names, versions and ecosystems are sent.
type OSV struct {
	API   string // https://api.osv.dev
	HTTP  *http.Client
	Cache VulnCache
}

// VulnCache keeps advisories so only changed ones are fetched again.
type VulnCache interface {
	GetVuln(id string) (data, modified string, ok bool)
	PutVuln(id, modified, data string) error
}

type pkgKey struct{ eco, name, version string }

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Check returns the findings for each package (by name, version and
// ecosystem) that OSV.dev knows a vulnerability in.
func (o *OSV) Check(ctx context.Context, pkgs []Package) (map[pkgKey][]Finding, error) {
	var keys []pkgKey
	seen := map[pkgKey]bool{}
	for _, p := range pkgs {
		k := pkgKey{p.Ecosystem, p.Name, p.Version}
		if p.Ecosystem != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	ids := map[pkgKey][]string{}
	modified := map[string]string{}
	for start := 0; start < len(keys); start += 1000 {
		end := min(start+1000, len(keys))
		var req struct {
			Queries []osvQuery `json:"queries"`
		}
		for _, k := range keys[start:end] {
			var q osvQuery
			q.Package.Name, q.Package.Ecosystem, q.Version = k.name, k.eco, k.version
			req.Queries = append(req.Queries, q)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID       string `json:"id"`
					Modified string `json:"modified"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := o.post(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			if start+i >= end {
				break
			}
			for _, v := range r.Vulns {
				ids[keys[start+i]] = append(ids[keys[start+i]], v.ID)
				modified[v.ID] = v.Modified
			}
		}
	}

	// the advisories themselves, from the cache unless they changed
	details := map[string]*osvVuln{}
	var mu sync.Mutex
	var firstErr error
	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				v, err := o.vuln(ctx, id, modified[id])
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if v != nil {
					details[id] = v
				}
				mu.Unlock()
			}
		}()
	}
	for id := range modified {
		if ctx.Err() != nil {
			break
		}
		work <- id
	}
	close(work)
	wg.Wait()
	if firstErr != nil && len(details) == 0 {
		return nil, firstErr
	}

	out := map[pkgKey][]Finding{}
	for k, list := range ids {
		for _, id := range list {
			v := details[id]
			if v == nil {
				out[k] = append(out[k], Finding{ID: id, Package: k.name, Version: k.version, Severity: "unknown", URL: "https://osv.dev/vulnerability/" + id})
				continue
			}
			out[k] = append(out[k], v.finding(k))
		}
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].Score > out[k][j].Score })
	}
	return out, nil
}

func (o *OSV) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (o *OSV) post(ctx context.Context, path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.API, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "skyguard-inventory")
	return o.do(req, out)
}

func (o *OSV) do(req *http.Request, out any) error {
	resp, err := o.client().Do(req)
	if err != nil {
		return fmt.Errorf("asking OSV.dev: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OSV.dev answered %s", resp.Status)
	}
	return json.Unmarshal(b, out)
}

func (o *OSV) vuln(ctx context.Context, id, modified string) (*osvVuln, error) {
	if o.Cache != nil {
		if data, mod, ok := o.Cache.GetVuln(id); ok && mod == modified {
			var v osvVuln
			if json.Unmarshal([]byte(data), &v) == nil {
				return &v, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(o.API, "/")+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "skyguard-inventory")
	var raw json.RawMessage
	if err := o.do(req, &raw); err != nil {
		return nil, err
	}
	var v osvVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	v.trim()
	if o.Cache != nil {
		if b, err := json.Marshal(v); err == nil {
			_ = o.Cache.PutVuln(id, modified, string(b))
		}
	}
	return &v, nil
}

// osvVuln is the part of an OSV advisory that is kept.
type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
		DatabaseSpecific  map[string]any `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// trim drops what is not needed before caching: long texts, affected
// entries of other distributions' releases.
func (v *osvVuln) trim() {
	if len(v.Details) > 600 {
		v.Details = v.Details[:600]
	}
	for i := range v.Affected {
		v.Affected[i].DatabaseSpecific = nil
		if es := v.Affected[i].EcosystemSpecific; es != nil {
			keep := map[string]any{}
			for _, k := range []string{"urgency", "severity"} {
				if x, ok := es[k]; ok {
					keep[k] = x
				}
			}
			v.Affected[i].EcosystemSpecific = keep
		}
	}
}

var reCVE = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func (v *osvVuln) finding(k pkgKey) Finding {
	f := Finding{ID: v.ID, Package: k.name, Version: k.version, URL: "https://osv.dev/vulnerability/" + v.ID, Severity: "unknown"}
	f.Summary = clean(v.Summary)
	if f.Summary == "" {
		f.Summary = clean(firstLine([]byte(v.Details)))
	}
	cves := map[string]bool{}
	for _, s := range append([]string{v.ID}, v.Aliases...) {
		for _, c := range reCVE.FindAllString(s, -1) {
			if !cves[c] {
				cves[c] = true
				f.CVEs = append(f.CVEs, c)
			}
		}
	}
	// the affected entry for this package and release
	for _, a := range v.Affected {
		if a.Package.Name != k.name || (a.Package.Ecosystem != k.eco && !strings.HasPrefix(k.eco, strings.SplitN(a.Package.Ecosystem, ":", 2)[0])) {
			continue
		}
		// a package can be listed once per release line; take the one
		// whose range holds the version
		fix, in := fixedFor(a.Ranges, k.version)
		if in || f.Fixed == "" {
			f.Fixed = fix
		}
		if u, ok := a.EcosystemSpecific["urgency"].(string); ok && u != "" {
			f.Note = "Debian: " + u
		}
		if in {
			break
		}
	}
	// severity: a CVSS v3 vector, else the advisory's or the distribution's rating
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, ok := cvss3(s.Score); ok && score > f.Score {
				f.Score = score
			}
		}
	}
	switch {
	case f.Score > 0:
		f.Severity = bucket(f.Score)
	default:
		for _, s := range v.Severity {
			if s.Type == "Ubuntu" {
				f.Severity, f.Note = rating(s.Score), "Ubuntu: "+s.Score
			}
		}
		if r, ok := v.DatabaseSpecific["severity"].(string); ok && f.Severity == "unknown" {
			f.Severity = rating(r)
		}
	}
	if f.Score > 0 {
		f.Score = math.Round(f.Score*10) / 10
	}
	return f
}

// fixedFor picks the fix of the range the version falls in
// (introduced <= version < fixed), comparing the numbers in the versions,
// and whether one held it; when none does, the last fix listed.
func fixedFor(ranges []struct {
	Events []map[string]string `json:"events"`
}, version string) (string, bool) {
	var last string
	for _, r := range ranges {
		introduced := "0"
		for _, e := range r.Events {
			if x, ok := e["introduced"]; ok {
				introduced = x
			}
			if x, ok := e["fixed"]; ok {
				if looseCompare(introduced, version) <= 0 && looseCompare(version, x) < 0 {
					return x, true
				}
				last = x
			}
		}
	}
	return last, false
}

// looseCompare orders versions by the numbers in them: right for semver
// and Go, close enough for Debian and Alpine to pick a range.
func looseCompare(a, b string) int {
	na, nb := numbers(a), numbers(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numbers(v string) []int {
	var out []int
	n, in := 0, false
	for _, r := range v {
		if r >= '0' && r <= '9' {
			n, in = n*10+int(r-'0'), true
			if n > 1<<40 {
				n = 1 << 40
			}
			continue
		}
		if in {
			out = append(out, n)
		}
		n, in = 0, false
	}
	if in {
		out = append(out, n)
	}
	return out
}

func bucket(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

func rating(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return "unknown"
}

// cvss3 computes a CVSS v3.x base score from its vector.
func cvss3(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	w := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0},
	}
	get := func(k string) (float64, bool) { x, ok := w[k][m[k]]; return x, ok }
	av, ok1 := get("AV")
	ac, ok2 := get("AC")
	ui, ok3 := get("UI")
	c, ok4 := get("C")
	i, ok5 := get("I")
	a, ok6 := get("A")
	changed := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, false
	}
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || (m["S"] != "U" && !changed) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+exploit), 10)), true
	}
	return roundUp(math.Min(impact+exploit, 10)), true
}

// roundUp is CVSS's "round up to one decimal", without float surprises.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}
