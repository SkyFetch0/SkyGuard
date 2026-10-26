package dashboard

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	if d%day == 0 {
		return fmt.Sprintf("%dd", d/day)
	}
	return d.String()
}
