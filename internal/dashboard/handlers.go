package dashboard

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/netutil"
	"github.com/skyguard/skyguard/internal/storage"
)

// maxQueryLimit is the upper bound for any paginated API query.
const maxQueryLimit = 10_000

func (d *Dashboard) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats, err := d.db.GetStats()
	if err != nil {
		d.internalError(w, "stats", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleTimeline returns per-hour connection counts for the last N hours (default 24).
func (d *Dashboard) handleTimeline(w http.ResponseWriter, r *http.Request) {
	hours := intParam(r.URL.Query(), "hours", 24, 1, 720)
	buckets, err := d.db.GetTimeline(hours)
	if err != nil {
		d.internalError(w, "timeline", err)
		return
	}
	writeJSON(w, http.StatusOK, buckets)
}

// connectionFilter parses ip, country, service, action, since, until (RFC3339),
// limit and offset from the query string.
func connectionFilter(q url.Values, defLimit int) storage.ConnectionFilter {
	f := storage.ConnectionFilter{
		IP:          netutil.NormalizeIP(q.Get("ip")),
		Country:     strings.TrimSpace(q.Get("country")),
		ServiceType: strings.TrimSpace(q.Get("service")),
		Action:      strings.TrimSpace(q.Get("action")),
		Limit:       intParam(q, "limit", defLimit, 1, maxQueryLimit),
		Offset:      intParam(q, "offset", 0, 0, 1<<30),
	}
	if t, err := time.Parse(time.RFC3339, q.Get("since")); err == nil {
		f.Since = t
	}
	if t, err := time.Parse(time.RFC3339, q.Get("until")); err == nil {
		f.Until = t
	}
	return f
}

// handleConnections returns connection records, newest first, filtered by
// the optional query parameters (see connectionFilter).
func (d *Dashboard) handleConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := d.db.SearchConnections(connectionFilter(r.URL.Query(), 100))
	if err != nil {
		d.internalError(w, "connections", err)
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

// handleExport streams a CSV export using the same filters as /api/connections.
func (d *Dashboard) handleExport(w http.ResponseWriter, r *http.Request) {
	conns, err := d.db.SearchConnections(connectionFilter(r.URL.Query(), maxQueryLimit))
	if err != nil {
		d.internalError(w, "export", err)
		return
	}

	filename := fmt.Sprintf("skyguard-connections-%s.csv", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "timestamp", "source_ip", "source_port", "dest_port", "country", "city", "service_type", "action", "data"})
	for _, c := range conns {
		_ = cw.Write([]string{
			strconv.FormatInt(c.ID, 10),
			c.Timestamp.UTC().Format(time.RFC3339),
			c.SourceIP,
			strconv.Itoa(c.SourcePort),
			strconv.Itoa(c.DestPort),
			csvSafe(c.Country),
			csvSafe(c.City),
			csvSafe(c.ServiceType),
			csvSafe(c.Action),
			csvSafe(c.Data),
		})
	}
	cw.Flush()
}

// csvSafe neutralises spreadsheet formula injection: attacker-controlled
// strings (HTTP paths, SSH client banners) starting with = + - @ would be
// evaluated by Excel/LibreOffice when the export is opened.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (d *Dashboard) handleBanned(w http.ResponseWriter, _ *http.Request) {
	banned, err := d.db.GetActiveBans()
	if err != nil {
		d.internalError(w, "banned IPs", err)
		return
	}
	writeJSON(w, http.StatusOK, banned)
}

func (d *Dashboard) handleAttackers(w http.ResponseWriter, r *http.Request) {
	attackers, err := d.db.GetTopAttackers(intParam(r.URL.Query(), "limit", 50, 1, 1000))
	if err != nil {
		d.internalError(w, "attackers", err)
		return
	}
	writeJSON(w, http.StatusOK, attackers)
}

func (d *Dashboard) handleCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := d.db.GetTopCredentials(intParam(r.URL.Query(), "limit", 100, 1, 1000))
	if err != nil {
		d.internalError(w, "credentials", err)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

// handleIPDetail returns everything known about one IP.
func (d *Dashboard) handleIPDetail(w http.ResponseWriter, r *http.Request) {
	ip := netutil.NormalizeIP(r.URL.Query().Get("ip"))
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid or missing ip")
		return
	}
	score, err := d.db.GetIPScore(ip)
	if err != nil {
		d.internalError(w, "ip score", err)
		return
	}
	banned, err := d.db.IsBanned(ip)
	if err != nil {
		d.internalError(w, "ip ban", err)
		return
	}
	conns, err := d.db.SearchConnections(storage.ConnectionFilter{IP: ip, Limit: 100})
	if err != nil {
		d.internalError(w, "ip connections", err)
		return
	}
	creds, err := d.db.GetCredentialsByIP(ip, 100)
	if err != nil {
		d.internalError(w, "ip credentials", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":          ip,
		"whitelisted": d.bans.IsWhitelisted(ip),
		"banned":      banned,
		"score":       score,
		"connections": conns,
		"credentials": creds,
	})
}

func (d *Dashboard) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	ab := d.settings.AutoBan()
	writeJSON(w, http.StatusOK, map[string]any{
		"auto_ban_enabled": ab.Enabled,
		"score_threshold":  ab.ScoreThreshold,
		"ban_duration":     formatDuration(ab.BanDuration),
		"firewall_method":  d.fw.Method(),
	})
}

// handlePostSettings updates only the fields that are present in the request.
func (d *Dashboard) handlePostSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	ab := d.settings.AutoBan()
	if r.PostForm.Has("auto_ban_enabled") {
		ab.Enabled = parseBool(r.PostForm.Get("auto_ban_enabled"))
	}
	if v := strings.TrimSpace(r.PostForm.Get("score_threshold")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "score_threshold must be a positive integer")
			return
		}
		ab.ScoreThreshold = n
	}
	if v := strings.TrimSpace(r.PostForm.Get("ban_duration")); v != "" {
		dur, err := config.ParseDuration(v)
		if err != nil || dur < 0 {
			writeError(w, http.StatusBadRequest, "invalid ban_duration (e.g. 30m, 24h, 7d; 0 = permanent)")
			return
		}
		ab.BanDuration = dur
	}
	if err := d.settings.SetAutoBan(ab); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.logger.Info("auto-ban settings updated via dashboard",
		"enabled", ab.Enabled, "threshold", ab.ScoreThreshold, "duration", ab.BanDuration)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleFirewall returns the configured backend and a snapshot of its rules.
func (d *Dashboard) handleFirewall(w http.ResponseWriter, _ *http.Request) {
	rules, err := d.fw.List()
	if err != nil {
		d.logger.Error("firewall list error", "error", err)
		rules = []string{"error reading rules: " + err.Error()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"method": d.fw.Method(), "rules": rules})
}

// handleBan manually bans an IP. Form fields: ip (required), duration
// (default 24h, "0" = permanent), permanent (bool), reason.
func (d *Dashboard) handleBan(w http.ResponseWriter, r *http.Request) {
	ip := netutil.NormalizeIP(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid or missing ip")
		return
	}
	permanent := parseBool(r.FormValue("permanent"))
	duration := 24 * time.Hour
	if dv := strings.TrimSpace(r.FormValue("duration")); dv != "" && !permanent {
		parsed, err := config.ParseDuration(dv)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid duration (e.g. 1h, 24h, 7d; 0 = permanent)")
			return
		}
		duration = parsed
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "manual"
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}

	if d.bans.IsWhitelisted(ip) {
		writeError(w, http.StatusBadRequest, ip+" is whitelisted (or loopback) and cannot be banned")
		return
	}
	if err := d.bans.BanIP(ip, reason, duration, permanent || duration == 0); err != nil {
		d.logger.Error("manual ban failed", "ip", ip, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.logger.Info("manual ban applied via dashboard", "ip", ip, "permanent", permanent || duration == 0, "duration", duration)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

// handleUnban removes a ban from the database and the firewall and resets the score.
func (d *Dashboard) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := netutil.NormalizeIP(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid or missing ip")
		return
	}
	if err := d.bans.UnbanIP(ip); err != nil {
		d.logger.Error("manual unban failed", "ip", ip, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.logger.Info("manual unban applied via dashboard", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip})
}

func (d *Dashboard) internalError(w http.ResponseWriter, what string, err error) {
	d.logger.Error(what+" query error", "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func intParam(q url.Values, key string, def, min, max int) int {
	n, err := strconv.Atoi(q.Get(key))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// formatDuration prints whole days as "7d" so the value round-trips through
// config.ParseDuration and reads naturally; 0 is shown as "0" (permanent).
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	day := 24 * time.Hour
	switch {
	case d%day == 0:
		return fmt.Sprintf("%dd", d/day)
	case d%time.Hour == 0: // "1h", not "1h0m0s", so it matches the panel's presets
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// chartRange maps the ?range= parameter to a window and its bucket size.
type chartRange struct {
	Name  string        `json:"name"`
	Span  time.Duration `json:"-"`
	Step  time.Duration `json:"-"`
	Since time.Time     `json:"since"`
	Until time.Time     `json:"until"`
	// Bucket is "hour" or "day".
	Bucket string `json:"bucket"`
}

func parseRange(q url.Values) chartRange {
	r := chartRange{Name: "24h", Span: 24 * time.Hour, Step: time.Hour, Bucket: "hour"}
	switch q.Get("range") {
	case "7d":
		r = chartRange{Name: "7d", Span: 7 * 24 * time.Hour, Step: time.Hour, Bucket: "hour"}
	case "30d":
		r = chartRange{Name: "30d", Span: 30 * 24 * time.Hour, Step: 24 * time.Hour, Bucket: "day"}
	}
	// The window ends at the end of the current bucket, so the last bar is
	// the bucket in progress and the first is a whole one.
	r.Until = time.Now().UTC().Truncate(r.Step).Add(r.Step)
	r.Since = r.Until.Add(-r.Span)
	return r
}

// handleSummary returns everything the overview needs for one range: the
// counters for this and the previous period, where connections ended up,
// and the busiest sources, services, countries and ports.
func (d *Dashboard) handleSummary(w http.ResponseWriter, r *http.Request) {
	rg := parseRange(r.URL.Query())
	cur, err := d.db.Summary(rg.Since, rg.Until)
	if err != nil {
		d.internalError(w, "summary", err)
		return
	}
	prev, err := d.db.Summary(rg.Since.Add(-rg.Span), rg.Since)
	if err != nil {
		d.internalError(w, "summary", err)
		return
	}
	stats, err := d.db.GetStats()
	if err != nil {
		d.internalError(w, "summary", err)
		return
	}
	outcomes, err := d.db.Outcomes(rg.Since, rg.Until)
	if err != nil {
		d.internalError(w, "outcomes", err)
		return
	}
	sources, err := d.db.TopSources(rg.Since, rg.Until, 8)
	if err != nil {
		d.internalError(w, "top sources", err)
		return
	}
	out := map[string]any{
		"range":       rg,
		"current":     cur,
		"previous":    prev,
		"active_bans": stats.ActiveBans,
		"outcomes":    outcomes,
		"top_sources": sources,
	}
	for _, by := range []string{"service", "country", "port"} {
		rows, err := d.db.Breakdown(by, rg.Since, rg.Until, 8)
		if err != nil {
			d.internalError(w, "breakdown", err)
			return
		}
		out[by+"s"] = rows
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSeries returns per-hour (24h, 7d) or per-day (30d) counts.
func (d *Dashboard) handleSeries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rg := parseRange(q)
	var f storage.SeriesFilter
	if v := q.Get("ip"); v != "" {
		f.IP = netutil.NormalizeIP(v)
		if net.ParseIP(f.IP) == nil {
			writeError(w, http.StatusBadRequest, "invalid ip")
			return
		}
	}
	if v := q.Get("port"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			writeError(w, http.StatusBadRequest, "invalid port")
			return
		}
		f.Port = p
	}
	buckets, err := d.db.Series(rg.Since, rg.Until, rg.Step, f)
	if err != nil {
		d.internalError(w, "series", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rg, "buckets": buckets})
}

// handleCredentialBreakdown returns the most tried usernames and passwords
// and the credentials per service for one range.
func (d *Dashboard) handleCredentialBreakdown(w http.ResponseWriter, r *http.Request) {
	rg := parseRange(r.URL.Query())
	out := map[string]any{"range": rg}
	for _, by := range []string{"username", "password", "service"} {
		rows, err := d.db.CredentialBreakdown(by, rg.Since, rg.Until, 10)
		if err != nil {
			d.internalError(w, "credential breakdown", err)
			return
		}
		out[by+"s"] = rows
	}
	writeJSON(w, http.StatusOK, out)
}

// serviceView is a service with its traffic over the last 24 hours.
type serviceView struct {
	ServiceStatus
	Hits24h        int64   `json:"hits_24h"`
	Credentials24h int64   `json:"credentials_24h"`
	Hourly         []int64 `json:"hourly"` // connections per hour, oldest first
}

func (d *Dashboard) handleServices(w http.ResponseWriter, _ *http.Request) {
	until := time.Now().UTC()
	since := until.Add(-24 * time.Hour)
	hits, err := d.db.Breakdown("port", since, until, 1000)
	if err != nil {
		d.internalError(w, "services", err)
		return
	}
	creds, err := d.db.CredentialBreakdown("service", since, until, 1000)
	if err != nil {
		d.internalError(w, "services", err)
		return
	}
	byPort := map[string]int64{}
	for _, h := range hits {
		byPort[h.Key] = h.Count
	}
	byService := map[string]int64{}
	for _, c := range creds {
		byService[c.Key] = c.Count
	}
	out := []serviceView{}
	for _, s := range d.bans.Services() {
		v := serviceView{ServiceStatus: s, Hits24h: byPort[strconv.Itoa(s.Port)]}
		series, err := d.db.Series(since, until, time.Hour, storage.SeriesFilter{Port: s.Port})
		if err != nil {
			d.internalError(w, "services", err)
			return
		}
		for _, b := range series {
			v.Hourly = append(v.Hourly, b.Total)
		}
		if s.Kind == "honeypot" {
			v.Credentials24h = byService[s.Type]
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetService switches a honeypot: form fields name and enabled.
func (d *Dashboard) handleSetService(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || !r.PostForm.Has("enabled") {
		writeError(w, http.StatusBadRequest, "name and enabled are required")
		return
	}
	enabled := parseBool(r.PostForm.Get("enabled"))
	if err := d.bans.SetServiceEnabled(name, enabled); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	d.logger.Info("service switched via dashboard", "name", name, "enabled", enabled)
	for _, s := range d.bans.Services() {
		if s.Name == name {
			writeJSON(w, http.StatusOK, s)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Version is the running build, set by main.
var Version = "dev"

// handleInfo names the product and its scope for the shell: the host this
// SkyGuard protects, its version and the firewall backend.
func (d *Dashboard) handleInfo(w http.ResponseWriter, _ *http.Request) {
	host, _ := os.Hostname()
	ab := d.settings.AutoBan()
	writeJSON(w, http.StatusOK, map[string]any{
		"host":             host,
		"version":          Version,
		"firewall_method":  d.fw.Method(),
		"auto_ban_enabled": ab.Enabled,
		"score_threshold":  ab.ScoreThreshold,
		"containers":       d.ctr != nil,
	})
}
