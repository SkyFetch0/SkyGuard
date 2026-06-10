package dashboard

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/storage"
)

// handleIndex serves the embedded HTML dashboard page.
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck
	w.Write([]byte(indexHTML))
}

// handleStats returns enriched aggregate connection statistics as JSON.
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := d.db.GetExtendedStats()
	if err != nil {
		d.logger.Error("stats query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, stats)
}

// handleTimeline returns per-hour connection counts for the last N hours (default 24).
func (d *Dashboard) handleTimeline(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	buckets, err := d.db.GetTimeline(hours)
	if err != nil {
		d.logger.Error("timeline query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if buckets == nil {
		buckets = []*storage.TimelineBucket{}
	}
	jsonResponse(w, http.StatusOK, buckets)
}

// handleSearch searches connections with optional filter params:
// ip, country, service, action, since (RFC3339), until (RFC3339), limit, offset.
func (d *Dashboard) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.ConnectionFilter{
		IP:          strings.TrimSpace(q.Get("ip")),
		Country:     strings.TrimSpace(q.Get("country")),
		ServiceType: strings.TrimSpace(q.Get("service")),
		Action:      strings.TrimSpace(q.Get("action")),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Limit = n
		}
	}
	if f.Limit == 0 || f.Limit > maxQueryLimit {
		f.Limit = 200
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			f.Offset = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = t
		}
	}

	conns, err := d.db.SearchConnections(f)
	if err != nil {
		d.logger.Error("search query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conns == nil {
		conns = []*storage.Connection{}
	}
	jsonResponse(w, http.StatusOK, conns)
}

// handleExport streams a CSV export of connections matching the same filter params as handleSearch.
func (d *Dashboard) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.ConnectionFilter{
		IP:          strings.TrimSpace(q.Get("ip")),
		Country:     strings.TrimSpace(q.Get("country")),
		ServiceType: strings.TrimSpace(q.Get("service")),
		Action:      strings.TrimSpace(q.Get("action")),
		Limit:       maxQueryLimit,
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = t
		}
	}

	conns, err := d.db.SearchConnections(f)
	if err != nil {
		d.logger.Error("export query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("skyguard-connections-%s.csv", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv")
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
			c.Country,
			c.City,
			c.ServiceType,
			c.Action,
			c.Data,
		})
	}
	cw.Flush()
}

// maxQueryLimit is the upper bound for any paginated API query.
const maxQueryLimit = 10_000

// handleConnections returns the most recent connection records.
// Accepts an optional "limit" query parameter (default 100, max 10 000).
func (d *Dashboard) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}

	conns, err := d.db.GetRecentConnections(limit)
	if err != nil {
		d.logger.Error("connections query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, conns)
}

// handleBanned returns the list of all banned IP records.
func (d *Dashboard) handleBanned(w http.ResponseWriter, r *http.Request) {
	banned, err := d.db.GetBannedIPs()
	if err != nil {
		d.logger.Error("banned IPs query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, banned)
}

// handleAttackers returns the top 20 IPs by threat score.
func (d *Dashboard) handleAttackers(w http.ResponseWriter, r *http.Request) {
	attackers, err := d.db.GetTopAttackers(20)
	if err != nil {
		d.logger.Error("attackers query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, attackers)
}

// handleCredentials returns the top 50 attempted credential pairs.
func (d *Dashboard) handleCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := d.db.GetTopCredentials(50)
	if err != nil {
		d.logger.Error("credentials query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, creds)
}

// handleSettings exposes (GET) and updates (POST) the runtime auto-ban settings.
func (d *Dashboard) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ab := d.settings.AutoBan()
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"auto_ban_enabled": ab.Enabled,
			"score_threshold":  ab.ScoreThreshold,
			"ban_duration":     ab.BanDuration.String(),
		})
	case http.MethodPost:
		if !sameOriginRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ab := d.settings.AutoBan()
		ab.Enabled = r.FormValue("auto_ban_enabled") == "1" || strings.EqualFold(r.FormValue("auto_ban_enabled"), "true")
		if v := r.FormValue("score_threshold"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				http.Error(w, "invalid score_threshold", http.StatusBadRequest)
				return
			}
			ab.ScoreThreshold = n
		}
		if v := r.FormValue("ban_duration"); v != "" {
			dur, err := time.ParseDuration(v)
			if err != nil || dur < 0 {
				http.Error(w, "invalid ban_duration (use e.g. 30m, 1h, 24h)", http.StatusBadRequest)
				return
			}
			ab.BanDuration = dur
		}
		if err := d.settings.SetAutoBan(ab); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.logger.Info("auto-ban settings updated via dashboard",
			"enabled", ab.Enabled, "threshold", ab.ScoreThreshold, "duration", ab.BanDuration)
		jsonResponse(w, http.StatusOK, map[string]interface{}{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFirewall returns the configured backend and a snapshot of its rules.
func (d *Dashboard) handleFirewall(w http.ResponseWriter, r *http.Request) {
	rules, err := d.fw.List()
	if err != nil {
		d.logger.Error("firewall list error", "error", err)
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"method": d.fw.Method(),
			"rules":  []string{"error reading rules: " + err.Error()},
		})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"method": d.fw.Method(),
		"rules":  rules,
	})
}

// handleBan manually bans an IP (database + firewall). POST only.
// Accepts form/query params: ip (required), duration (e.g. "24h", optional),
// permanent ("1"/"true", optional), reason (optional).
func (d *Dashboard) handleBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid or missing ip", http.StatusBadRequest)
		return
	}

	permanent := r.FormValue("permanent") == "1" || strings.EqualFold(r.FormValue("permanent"), "true")
	duration := 24 * time.Hour
	if dv := r.FormValue("duration"); dv != "" {
		parsed, err := time.ParseDuration(dv)
		if err != nil {
			http.Error(w, "invalid duration (use e.g. 1h, 24h, 168h)", http.StatusBadRequest)
			return
		}
		if parsed < 0 {
			http.Error(w, "duration must be non-negative", http.StatusBadRequest)
			return
		}
		duration = parsed
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "manual"
	}

	if err := d.db.BanIP(ip, reason, duration, permanent); err != nil {
		d.logger.Error("manual ban: db error", "ip", ip, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if permanent {
		if err := d.fw.BanIPPermanent(ip); err != nil {
			d.logger.Error("manual ban: firewall error", "ip", ip, "error", err)
		}
	} else if err := d.fw.BanIP(ip, duration); err != nil {
		d.logger.Error("manual ban: firewall error", "ip", ip, "error", err)
	}
	d.logger.Info("manual ban applied via dashboard", "ip", ip, "permanent", permanent)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"ok": true, "ip": ip})
}

// handleUnban removes a ban from both the database and the firewall. POST only.
func (d *Dashboard) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid or missing ip", http.StatusBadRequest)
		return
	}

	if err := d.db.UnbanIP(ip); err != nil {
		d.logger.Error("manual unban: db error", "ip", ip, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := d.fw.UnbanIP(ip); err != nil {
		d.logger.Debug("manual unban: firewall error (rule may not exist)", "ip", ip, "error", err)
	}
	d.logger.Info("manual unban applied via dashboard", "ip", ip)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"ok": true, "ip": ip})
}

// sameOriginRequest is a lightweight CSRF guard for state-changing endpoints.
func sameOriginRequest(r *http.Request) bool {
	if r.Header.Get("X-SkyGuard-Request") != "" {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site":
		return true
	}
	return false
}

// jsonResponse writes data as JSON with the given HTTP status code.
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

// indexHTML is the inline dashboard HTML page (professional redesign).
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SkyGuard</title>
<style>
:root{
  --bg:#0b0f1a;--surface:#111827;--surface2:#1a2234;--border:#1f2d45;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#4a5568;
  --accent:#3b82f6;--accent2:#1d4ed8;
  --green:#22c55e;--yellow:#f59e0b;--red:#ef4444;--orange:#f97316;--purple:#a855f7;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent);text-decoration:none}

/* ── Layout ── */
.layout{display:flex;flex:1;min-height:0}
.sidebar{width:220px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:1rem 0}
.sidebar-logo{padding:.5rem 1.25rem 1.25rem;display:flex;align-items:center;gap:.6rem;border-bottom:1px solid var(--border);margin-bottom:.75rem}
.sidebar-logo span{font-size:1.1rem;font-weight:700;color:#60a5fa;letter-spacing:-.02em}
.sidebar-logo .dot{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.nav-item{display:flex;align-items:center;gap:.6rem;padding:.55rem 1.25rem;font-size:.85rem;color:var(--text2);cursor:pointer;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text);background:var(--surface2)}
.nav-item.active{color:#60a5fa;background:rgba(59,130,246,.08);border-left-color:#3b82f6}
.nav-icon{font-size:.95rem;width:18px;text-align:center;flex-shrink:0}
.sidebar-section{font-size:.65rem;font-weight:600;letter-spacing:.08em;color:var(--text3);padding:.75rem 1.25rem .25rem;text-transform:uppercase}
.main{flex:1;overflow-y:auto;min-width:0}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:.75rem 1.75rem;display:flex;align-items:center;gap:1rem;position:sticky;top:0;z-index:10}
.topbar-title{font-size:.95rem;font-weight:600}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:.75rem}
.live-badge{display:flex;align-items:center;gap:.4rem;font-size:.75rem;color:var(--green)}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
.last-update{font-size:.75rem;color:var(--text3)}
.content{padding:1.5rem 1.75rem}

/* ── Tabs ── */
.tabs{display:flex;gap:.25rem;margin-bottom:1.5rem;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:.5rem 1rem;font-size:.85rem;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:#60a5fa;border-bottom-color:#3b82f6}
.tab-panel{display:none}
.tab-panel.active{display:block}

/* ── Stats grid ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem;margin-bottom:1.5rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:.625rem;padding:1rem 1.125rem;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:2px 2px 0 0}
.stat-card.c-blue::before{background:var(--accent)}
.stat-card.c-orange::before{background:var(--orange)}
.stat-card.c-green::before{background:var(--green)}
.stat-card.c-red::before{background:var(--red)}
.stat-card.c-purple::before{background:var(--purple)}
.stat-card.c-yellow::before{background:var(--yellow)}
.stat-label{font-size:.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.375rem}
.stat-val{font-size:1.75rem;font-weight:700;line-height:1}
.stat-sub{font-size:.7rem;color:var(--text3);margin-top:.3rem}
.stat-card.c-blue .stat-val{color:#60a5fa}
.stat-card.c-orange .stat-val{color:var(--orange)}
.stat-card.c-green .stat-val{color:var(--green)}
.stat-card.c-red .stat-val{color:var(--red)}
.stat-card.c-purple .stat-val{color:var(--purple)}
.stat-card.c-yellow .stat-val{color:var(--yellow)}

/* ── Charts ── */
.chart-container{background:var(--surface);border:1px solid var(--border);border-radius:.625rem;padding:1.125rem;margin-bottom:1.5rem}
.chart-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.chart-title{font-size:.85rem;font-weight:600}
.chart-legend{display:flex;gap:1rem}
.legend-item{display:flex;align-items:center;gap:.35rem;font-size:.7rem;color:var(--text2)}
.legend-dot{width:8px;height:8px;border-radius:50%}
#timeline-svg{width:100%;height:120px;display:block;overflow:visible}

/* ── Search/Filter bar ── */
.filter-bar{background:var(--surface);border:1px solid var(--border);border-radius:.625rem;padding:1rem 1.125rem;margin-bottom:1rem;display:flex;flex-wrap:wrap;gap:.6rem;align-items:flex-end}
.filter-group{display:flex;flex-direction:column;gap:.3rem;min-width:130px}
.filter-label{font-size:.65rem;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}
.filter-input{background:var(--surface2);border:1px solid var(--border);border-radius:.4rem;color:var(--text);font-size:.8rem;padding:.4rem .6rem;outline:none;transition:border .15s}
.filter-input:focus{border-color:var(--accent)}
.filter-input select,.filter-input option{background:var(--surface2)}
select.filter-input{appearance:none;cursor:pointer}
.filter-actions{display:flex;gap:.5rem;align-items:flex-end;margin-left:auto}

/* ── Tables ── */
.section{margin-bottom:1.5rem}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:.625rem}
.section-title{font-size:.85rem;font-weight:600}
.section-meta{font-size:.75rem;color:var(--text3)}
.tbl-wrap{background:var(--surface);border:1px solid var(--border);border-radius:.625rem;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{background:var(--bg);color:var(--text2);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;padding:.625rem 1rem;text-align:left;white-space:nowrap;position:sticky;top:0;z-index:1}
td{padding:.55rem 1rem;border-top:1px solid var(--border);font-size:.8rem;color:#cbd5e1;white-space:nowrap}
tr:hover td{background:rgba(255,255,255,.025)}
.tbl-scroll{max-height:380px;overflow-y:auto}

/* ── Tags ── */
.tag{display:inline-flex;align-items:center;padding:.15rem .5rem;border-radius:.25rem;font-size:.68rem;font-weight:600;letter-spacing:.02em}
.tag-red{background:rgba(239,68,68,.15);color:#fca5a5}
.tag-green{background:rgba(34,197,94,.15);color:#86efac}
.tag-yellow{background:rgba(245,158,11,.15);color:#fde68a}
.tag-blue{background:rgba(59,130,246,.15);color:#93c5fd}
.tag-purple{background:rgba(168,85,247,.15);color:#d8b4fe}
.tag-gray{background:rgba(100,116,139,.15);color:#94a3b8}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:.35rem;padding:.4rem .85rem;border-radius:.4rem;font-size:.78rem;font-weight:500;cursor:pointer;border:none;transition:all .15s;outline:none}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text2)}
.btn-ghost:hover{border-color:#4a6080;color:var(--text)}
.btn-danger{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);color:#fca5a5}
.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-sm{padding:.25rem .55rem;font-size:.72rem}
.btn-export{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);color:#86efac}
.btn-export:hover{background:rgba(34,197,94,.18)}

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:.625rem;padding:1.125rem;margin-bottom:1rem}
.panel-title{font-size:.8rem;font-weight:600;margin-bottom:.875rem;display:flex;align-items:center;gap:.5rem}
.form-row{display:flex;flex-wrap:wrap;gap:.6rem;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:.3rem}
.form-label{font-size:.68rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em}
.form-input{background:var(--surface2);border:1px solid var(--border);border-radius:.4rem;color:var(--text);font-size:.82rem;padding:.45rem .65rem;outline:none;transition:border .15s;min-width:140px}
.form-input:focus{border-color:var(--accent)}
.form-msg{font-size:.75rem;margin-top:.5rem;min-height:1.1em}
.form-msg.ok{color:var(--green)}
.form-msg.err{color:var(--red)}
.checkbox-row{display:flex;align-items:center;gap:.4rem;font-size:.82rem;cursor:pointer;user-select:none;color:var(--text2)}
.checkbox-row input{accent-color:var(--accent);cursor:pointer}
.divider{height:1px;background:var(--border);margin:.75rem 0}

/* ── Score bar ── */
.score-bar{display:flex;align-items:center;gap:.6rem}
.score-track{flex:1;height:4px;background:var(--surface2);border-radius:2px;overflow:hidden;max-width:80px}
.score-fill{height:100%;border-radius:2px;background:var(--red);transition:width .3s}
.score-num{font-size:.78rem;font-weight:600;color:var(--red);min-width:35px;text-align:right}

/* ── Pre/code ── */
pre{background:var(--surface2);border:1px solid var(--border);border-radius:.5rem;padding:.875rem;font-size:.75rem;color:#cbd5e1;overflow:auto;white-space:pre-wrap;margin:0}

/* ── Empty state ── */
.empty{text-align:center;padding:2.5rem 1rem;color:var(--text3);font-size:.82rem}

/* ── Toast ── */
#toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:100;display:flex;flex-direction:column;gap:.5rem}
.toast-item{background:var(--surface2);border:1px solid var(--border);border-radius:.5rem;padding:.65rem 1rem;font-size:.8rem;display:flex;align-items:center;gap:.5rem;animation:slideIn .2s ease}
.toast-item.ok{border-left:3px solid var(--green)}
.toast-item.err{border-left:3px solid var(--red)}
@keyframes slideIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:none}}

/* ── Grid layouts ── */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:900px){.two-col{grid-template-columns:1fr}.sidebar{width:180px}.stats-grid{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}}
@media(max-width:650px){.sidebar{display:none}.content{padding:1rem}}
</style>
</head>
<body>

<div class="layout">
  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sidebar-logo">
      <div class="dot"></div>
      <span>SkyGuard</span>
    </div>
    <div class="nav-item active" onclick="showPage('overview')"><span class="nav-icon">&#9632;</span> Overview</div>
    <div class="nav-item" onclick="showPage('logs')"><span class="nav-icon">&#9776;</span> Connection Logs</div>
    <div class="nav-item" onclick="showPage('threats')"><span class="nav-icon">&#9888;</span> Threats</div>
    <div class="nav-item" onclick="showPage('creds')"><span class="nav-icon">&#128273;</span> Credentials</div>
    <div class="nav-item" onclick="showPage('bans')"><span class="nav-icon">&#128683;</span> Bans</div>
    <div class="sidebar-section">System</div>
    <div class="nav-item" onclick="showPage('firewall')"><span class="nav-icon">&#128737;</span> Firewall</div>
    <div class="nav-item" onclick="showPage('settings')"><span class="nav-icon">&#9881;</span> Settings</div>
  </nav>

  <!-- Main -->
  <div class="main">
    <div class="topbar">
      <span class="topbar-title" id="page-title">Overview</span>
      <div class="topbar-right">
        <div class="live-badge"><div class="live-dot"></div>LIVE</div>
        <span class="last-update" id="last-update">-</span>
        <button class="btn btn-ghost btn-sm" onclick="refreshCurrent()">&#8635; Refresh</button>
      </div>
    </div>

    <div class="content">

      <!-- ═══════════════════════════════════════════
           PAGE: OVERVIEW
      ═══════════════════════════════════════════ -->
      <div id="page-overview" class="tab-panel active">
        <div class="stats-grid" id="stats-grid">
          <div class="stat-card c-blue"><div class="stat-label">Total Connections</div><div class="stat-val" id="s-total">-</div></div>
          <div class="stat-card c-orange"><div class="stat-label">Honeypot Hits</div><div class="stat-val" id="s-honeypot">-</div></div>
          <div class="stat-card c-green"><div class="stat-label">Forwarded</div><div class="stat-val" id="s-forwarded">-</div></div>
          <div class="stat-card c-red"><div class="stat-label">Dropped</div><div class="stat-val" id="s-dropped">-</div></div>
          <div class="stat-card c-yellow"><div class="stat-label">Today</div><div class="stat-val" id="s-today">-</div></div>
          <div class="stat-card c-purple"><div class="stat-label">Active Bans</div><div class="stat-val" id="s-bans">-</div></div>
          <div class="stat-card c-blue"><div class="stat-label">Unique IPs</div><div class="stat-val" id="s-ips" style="color:var(--text)">-</div></div>
          <div class="stat-card c-blue"><div class="stat-label">Countries</div><div class="stat-val" id="s-countries" style="color:var(--text)">-</div></div>
        </div>

        <!-- Timeline chart -->
        <div class="chart-container">
          <div class="chart-header">
            <span class="chart-title">Connection Activity — last 24h</span>
            <div class="chart-legend">
              <div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div>Total</div>
              <div class="legend-item"><div class="legend-dot" style="background:var(--orange)"></div>Honeypot</div>
              <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>Dropped</div>
            </div>
          </div>
          <svg id="timeline-svg"></svg>
          <div id="timeline-empty" class="empty" style="display:none">No data for the last 24 hours</div>
        </div>

        <!-- Recent connections mini-table -->
        <div class="section">
          <div class="section-hdr">
            <span class="section-title">Recent Connections</span>
            <span class="section-meta" id="conn-count"></span>
          </div>
          <div class="tbl-wrap tbl-scroll">
            <table>
              <thead><tr><th>Time</th><th>Source IP</th><th>Country</th><th>Port</th><th>Service</th><th>Action</th></tr></thead>
              <tbody id="conn-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: CONNECTION LOGS (search)
      ═══════════════════════════════════════════ -->
      <div id="page-logs" class="tab-panel">
        <div class="filter-bar">
          <div class="filter-group">
            <span class="filter-label">Source IP</span>
            <input class="filter-input" id="f-ip" placeholder="e.g. 1.2.3.4">
          </div>
          <div class="filter-group">
            <span class="filter-label">Country</span>
            <input class="filter-input" id="f-country" placeholder="e.g. CN">
          </div>
          <div class="filter-group">
            <span class="filter-label">Service</span>
            <select class="filter-input" id="f-service">
              <option value="">All</option>
              <option>ssh</option><option>ftp</option><option>mysql</option><option>http</option><option>passthrough</option>
            </select>
          </div>
          <div class="filter-group">
            <span class="filter-label">Action</span>
            <select class="filter-input" id="f-action">
              <option value="">All</option>
              <option>honeypot</option><option>forwarded</option><option>dropped</option><option>passthrough</option>
            </select>
          </div>
          <div class="filter-group">
            <span class="filter-label">Since (UTC)</span>
            <input class="filter-input" id="f-since" type="datetime-local">
          </div>
          <div class="filter-group">
            <span class="filter-label">Until (UTC)</span>
            <input class="filter-input" id="f-until" type="datetime-local">
          </div>
          <div class="filter-group">
            <span class="filter-label">Limit</span>
            <input class="filter-input" id="f-limit" type="number" value="200" min="1" max="10000" style="width:80px">
          </div>
          <div class="filter-actions">
            <button class="btn btn-primary" onclick="runSearch()">&#128269; Search</button>
            <button class="btn btn-ghost" onclick="clearSearch()">Clear</button>
            <button class="btn btn-export" onclick="exportCSV()" title="Download CSV">&#8659; CSV</button>
          </div>
        </div>
        <div class="section">
          <div class="section-hdr">
            <span class="section-title">Results</span>
            <span class="section-meta" id="search-count"></span>
          </div>
          <div class="tbl-wrap tbl-scroll" style="max-height:520px">
            <table>
              <thead><tr><th>#</th><th>Timestamp</th><th>Source IP</th><th>Src Port</th><th>Dst Port</th><th>Country</th><th>City</th><th>Service</th><th>Action</th><th>Data</th></tr></thead>
              <tbody id="search-body"><tr><td colspan="10" class="empty">Run a search above</td></tr></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: THREATS
      ═══════════════════════════════════════════ -->
      <div id="page-threats" class="tab-panel">
        <div class="section">
          <div class="section-hdr"><span class="section-title">Top Attackers by Threat Score</span></div>
          <div class="tbl-wrap">
            <table>
              <thead><tr><th>IP</th><th>Country</th><th>Score</th><th>Honeypot Hits</th><th>Actions</th></tr></thead>
              <tbody id="attackers-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: CREDENTIALS
      ═══════════════════════════════════════════ -->
      <div id="page-creds" class="tab-panel">
        <div class="section">
          <div class="section-hdr">
            <span class="section-title">Top Credential Attempts</span>
            <span class="section-meta">Harvested from SSH/FTP honeypots</span>
          </div>
          <div class="tbl-wrap tbl-scroll">
            <table>
              <thead><tr><th>Username</th><th>Password</th><th>Count</th><th>Service</th></tr></thead>
              <tbody id="creds-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: BANS
      ═══════════════════════════════════════════ -->
      <div id="page-bans" class="tab-panel">
        <div class="panel">
          <div class="panel-title">&#43; Manual Ban</div>
          <div class="form-row">
            <div class="form-group">
              <span class="form-label">IP Address</span>
              <input class="form-input" id="ban-ip" placeholder="1.2.3.4">
            </div>
            <div class="form-group">
              <span class="form-label">Duration</span>
              <input class="form-input" id="ban-dur" placeholder="24h (blank = 24h)" style="width:150px">
            </div>
            <div class="form-group">
              <span class="form-label">Reason</span>
              <input class="form-input" id="ban-reason" placeholder="manual" style="width:180px">
            </div>
            <div class="form-group" style="justify-content:flex-end;padding-bottom:.1rem">
              <label class="checkbox-row"><input type="checkbox" id="ban-perm"> Permanent</label>
            </div>
            <div class="form-group" style="justify-content:flex-end">
              <button class="btn btn-primary" onclick="doBan()">Ban IP</button>
            </div>
          </div>
          <div class="form-msg" id="ban-msg"></div>
        </div>

        <div class="section">
          <div class="section-hdr">
            <span class="section-title">Active Bans</span>
            <button class="btn btn-ghost btn-sm" onclick="loadBanned()">&#8635; Refresh</button>
          </div>
          <div class="tbl-wrap tbl-scroll">
            <table>
              <thead><tr><th>IP</th><th>Reason</th><th>Banned At</th><th>Expires</th><th>Type</th><th>Action</th></tr></thead>
              <tbody id="banned-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: FIREWALL
      ═══════════════════════════════════════════ -->
      <div id="page-firewall" class="tab-panel">
        <div class="section">
          <div class="section-hdr">
            <span class="section-title">Firewall Backend: <span id="fw-method" class="tag tag-blue">-</span></span>
            <button class="btn btn-ghost btn-sm" onclick="loadFirewall()">&#8635; Refresh</button>
          </div>
          <pre id="fw-rules">Loading...</pre>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════
           PAGE: SETTINGS
      ═══════════════════════════════════════════ -->
      <div id="page-settings" class="tab-panel">
        <div class="panel">
          <div class="panel-title">&#9881; Auto-Ban Settings</div>
          <div class="form-row">
            <div class="form-group" style="justify-content:flex-end;padding-bottom:.1rem">
              <label class="checkbox-row"><input type="checkbox" id="set-enabled"> Enabled</label>
            </div>
            <div class="form-group">
              <span class="form-label">Score Threshold</span>
              <input class="form-input" id="set-threshold" type="number" min="1" style="width:100px">
            </div>
            <div class="form-group">
              <span class="form-label">Ban Duration</span>
              <input class="form-input" id="set-duration" placeholder="e.g. 1h, 24h" style="width:130px">
            </div>
            <div class="form-group" style="justify-content:flex-end">
              <button class="btn btn-primary" onclick="saveSettings()">Save</button>
            </div>
          </div>
          <div class="form-msg" id="set-msg"></div>
        </div>
      </div>

    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /layout -->

<div id="toast"></div>

<script>
// ── Utilities ────────────────────────────────────────
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function fetchJ(url){const r=await fetch(url);if(!r.ok)throw new Error(r.statusText);return r.json();}
async function postForm(url,data){return fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-SkyGuard-Request':'1'},body:new URLSearchParams(data)});}
function fmtTime(ts){return ts?new Date(ts).toLocaleString():'-';}
function fmtRel(ts){if(!ts)return '-';const d=Math.round((Date.now()-new Date(ts))/1000);if(d<60)return d+'s ago';if(d<3600)return Math.round(d/60)+'m ago';if(d<86400)return Math.round(d/3600)+'h ago';return Math.round(d/86400)+'d ago';}

function showToast(msg,ok=true){
  const t=document.getElementById('toast');
  const el=document.createElement('div');
  el.className='toast-item '+(ok?'ok':'err');
  el.textContent=msg;
  t.appendChild(el);
  setTimeout(()=>el.remove(),3500);
}

function actionTag(a){
  const m={dropped:'tag-red',forwarded:'tag-green',honeypot:'tag-yellow',passthrough:'tag-blue'};
  return '<span class="tag '+(m[a]||'tag-gray')+'">'+esc(a)+'</span>';
}

// ── Navigation ───────────────────────────────────────
let currentPage='overview';
const pageTitles={overview:'Overview',logs:'Connection Logs',threats:'Threats',creds:'Credentials',bans:'Bans',firewall:'Firewall',settings:'Settings'};

function showPage(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>{if(n.textContent.trim().toLowerCase().startsWith(pageTitles[name].toLowerCase().slice(0,4)))n.classList.add('active');});
  document.getElementById('page-title').textContent=pageTitles[name]||name;
  currentPage=name;
  switch(name){
    case'overview':loadAll();break;
    case'logs':break;
    case'threats':loadAttackers();break;
    case'creds':loadCredentials();break;
    case'bans':loadBanned();break;
    case'firewall':loadFirewall();break;
    case'settings':loadSettings();break;
  }
}

function refreshCurrent(){showPage(currentPage);}

// ── Stats ────────────────────────────────────────────
async function loadStats(){
  try{
    const s=await fetchJ('/api/stats');
    document.getElementById('s-total').textContent=fmt(s.total);
    document.getElementById('s-honeypot').textContent=fmt(s.honeypot_hits);
    document.getElementById('s-forwarded').textContent=fmt(s.forwarded);
    document.getElementById('s-dropped').textContent=fmt(s.dropped);
    document.getElementById('s-today').textContent=fmt(s.connections_today);
    document.getElementById('s-bans').textContent=fmt(s.active_bans);
    document.getElementById('s-ips').textContent=fmt(s.unique_ips);
    document.getElementById('s-countries').textContent=fmt(s.unique_countries);
  }catch(e){console.error('stats',e);}
}
function fmt(n){return n==null?'-':Number(n).toLocaleString();}

// ── Timeline SVG chart ───────────────────────────────
async function loadTimeline(){
  try{
    const data=await fetchJ('/api/timeline?hours=24');
    const svg=document.getElementById('timeline-svg');
    const empty=document.getElementById('timeline-empty');
    if(!data||!data.length){svg.style.display='none';empty.style.display='block';return;}
    svg.style.display='block';empty.style.display='none';
    drawTimeline(svg,data);
  }catch(e){console.error('timeline',e);}
}

function drawTimeline(svg,data){
  const W=svg.clientWidth||800,H=120,pad={t:8,r:8,b:24,l:36};
  const iW=W-pad.l-pad.r,iH=H-pad.t-pad.b;
  const maxVal=Math.max(1,...data.map(d=>d.total));
  const n=data.length;
  const xScale=i=>pad.l+i*(iW/(n-1||1));
  const yScale=v=>pad.t+iH-(v/maxVal)*iH;

  const mkPath=(key,color,fill)=>{
    if(n===0)return'';
    let d=data.map((pt,i)=>(i===0?'M':'L')+xScale(i).toFixed(1)+','+yScale(pt[key]).toFixed(1)).join(' ');
    if(fill){
      const id='g'+key;
      d+=' L'+xScale(n-1).toFixed(1)+','+(pad.t+iH).toFixed(1)+' L'+pad.l+','+(pad.t+iH).toFixed(1)+' Z';
      return '<defs><linearGradient id="'+id+'" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="'+color+'" stop-opacity=".25"/><stop offset="100%" stop-color="'+color+'" stop-opacity=".02"/></linearGradient></defs><path d="'+d+'" fill="url(#'+id+')" stroke="none"/>';
    }
    return '<path d="'+d+'" fill="none" stroke="'+color+'" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>';
  };

  // Y grid lines
  let grid='';
  for(let i=0;i<=4;i++){
    const y=pad.t+iH*(i/4);
    const val=Math.round(maxVal*(1-i/4));
    grid+='<line x1="'+pad.l+'" y1="'+y.toFixed(1)+'" x2="'+(pad.l+iW)+'" y2="'+y.toFixed(1)+'" stroke="#1f2d45" stroke-width="1"/>';
    grid+='<text x="'+(pad.l-4)+'" y="'+(y+4).toFixed(1)+'" text-anchor="end" font-size="9" fill="#4a5568">'+val+'</text>';
  }

  // X labels: show ~6 evenly-spaced labels
  let xlabels='';
  data.forEach((pt,i)=>{
    if(i%(Math.ceil(n/6))===0){
      const h=pt.bucket?pt.bucket.slice(11,16):'';
      xlabels+='<text x="'+xScale(i).toFixed(1)+'" y="'+(H-4)+'" text-anchor="middle" font-size="9" fill="#4a5568">'+esc(h)+'</text>';
    }
  });

  svg.innerHTML=grid+mkPath('total','#3b82f6',true)+mkPath('total','#3b82f6')+mkPath('honeypot_hits','#f97316')+mkPath('dropped','#ef4444')+xlabels;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
}

// ── Recent connections ───────────────────────────────
async function loadConnections(){
  try{
    const rows=await fetchJ('/api/connections?limit=50');
    const tb=document.getElementById('conn-body');
    document.getElementById('conn-count').textContent=(rows||[]).length+' rows';
    if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="6" class="empty">No connections yet</td></tr>';return;}
    tb.innerHTML=rows.map(function(c){return '<tr><td>'+esc(fmtRel(c.Timestamp))+'</td><td><a href="javascript:void(0)" onclick="filterByIP(\''+esc(c.SourceIP)+'\')" style="color:#60a5fa">'+esc(c.SourceIP)+'</a></td><td>'+esc(c.Country||'-')+'</td><td>'+esc(c.DestPort)+'</td><td><span class="tag tag-gray">'+esc(c.ServiceType||'-')+'</span></td><td>'+actionTag(c.Action)+'</td></tr>';}).join('');
  }catch(e){console.error('connections',e);}
}

function filterByIP(ip){
  showPage('logs');
  document.getElementById('f-ip').value=ip;
  runSearch();
}

// ── Search ───────────────────────────────────────────
async function runSearch(){
  const params=new URLSearchParams();
  const ip=document.getElementById('f-ip').value.trim();
  const country=document.getElementById('f-country').value.trim();
  const service=document.getElementById('f-service').value;
  const action=document.getElementById('f-action').value;
  const since=document.getElementById('f-since').value;
  const until=document.getElementById('f-until').value;
  const limit=document.getElementById('f-limit').value||'200';
  if(ip)params.set('ip',ip);
  if(country)params.set('country',country);
  if(service)params.set('service',service);
  if(action)params.set('action',action);
  if(since)params.set('since',new Date(since).toISOString());
  if(until)params.set('until',new Date(until).toISOString());
  params.set('limit',limit);

  const tb=document.getElementById('search-body');
  tb.innerHTML='<tr><td colspan="10" class="empty">Searching...</td></tr>';
  document.getElementById('search-count').textContent='';

  try{
    const rows=await fetchJ('/api/search?'+params.toString());
    document.getElementById('search-count').textContent=(rows||[]).length+' result(s)';
    if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="10" class="empty">No results</td></tr>';return;}
    tb.innerHTML=rows.map(function(c,i){return '<tr><td style="color:var(--text3)">'+(i+1)+'</td><td>'+esc(fmtTime(c.Timestamp))+'</td><td><a href="javascript:void(0)" onclick="filterByIP(\''+esc(c.SourceIP)+'\')" style="color:#60a5fa">'+esc(c.SourceIP)+'</a></td><td>'+esc(c.SourcePort)+'</td><td>'+esc(c.DestPort)+'</td><td>'+esc(c.Country||'-')+'</td><td>'+esc(c.City||'-')+'</td><td><span class="tag tag-gray">'+esc(c.ServiceType||'-')+'</span></td><td>'+actionTag(c.Action)+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;color:var(--text3)" title="'+esc(c.Data)+'">'+esc(c.Data||'-')+'</td></tr>';}).join('');
  }catch(e){showToast('Search failed: '+e.message,false);}
}

function clearSearch(){
  ['f-ip','f-country','f-since','f-until'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('f-service').value='';
  document.getElementById('f-action').value='';
  document.getElementById('f-limit').value='200';
  document.getElementById('search-body').innerHTML='<tr><td colspan="10" class="empty">Run a search above</td></tr>';
  document.getElementById('search-count').textContent='';
}

function exportCSV(){
  const params=new URLSearchParams();
  const ip=document.getElementById('f-ip').value.trim();
  const country=document.getElementById('f-country').value.trim();
  const service=document.getElementById('f-service').value;
  const action=document.getElementById('f-action').value;
  const since=document.getElementById('f-since').value;
  const until=document.getElementById('f-until').value;
  if(ip)params.set('ip',ip);
  if(country)params.set('country',country);
  if(service)params.set('service',service);
  if(action)params.set('action',action);
  if(since)params.set('since',new Date(since).toISOString());
  if(until)params.set('until',new Date(until).toISOString());
  window.location.href='/api/export?'+params.toString();
}

// ── Attackers ────────────────────────────────────────
async function loadAttackers(){
  try{
    const rows=await fetchJ('/api/attackers');
    const tb=document.getElementById('attackers-body');
    if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="5" class="empty">No threats detected</td></tr>';return;}
    const max=Math.max(1,...rows.map(r=>r.Score||0));
    tb.innerHTML=rows.map(function(a){var pct=Math.round((a.Score/max)*100);return '<tr><td><a href="javascript:void(0)" onclick="filterByIP(\''+esc(a.IP)+'\')" style="color:#60a5fa">'+esc(a.IP)+'</a></td><td>'+esc(a.Country||'-')+'</td><td><div class="score-bar"><div class="score-track"><div class="score-fill" style="width:'+pct+'%"></div></div><span class="score-num">'+esc(a.Score)+'</span></div></td><td>'+esc(a.HoneypotHits)+'</td><td><button class="btn btn-danger btn-sm" onclick="quickBan(\''+esc(a.IP)+'\')">Ban</button></td></tr>';}).join('');
  }catch(e){console.error('attackers',e);}
}

function quickBan(ip){
  showPage('bans');
  document.getElementById('ban-ip').value=ip;
  document.getElementById('ban-ip').focus();
}

// ── Credentials ──────────────────────────────────────
async function loadCredentials(){
  try{
    const rows=await fetchJ('/api/credentials');
    const tb=document.getElementById('creds-body');
    if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="4" class="empty">No credentials captured yet</td></tr>';return;}
    tb.innerHTML=rows.map(function(c){return '<tr><td style="color:#fde68a">'+esc(c.username)+'</td><td style="color:#fca5a5;font-family:monospace">'+esc(c.password)+'</td><td><span style="color:var(--text);font-weight:600">'+esc(c.count)+'</span></td><td><span class="tag tag-gray">'+esc(c.service||'-')+'</span></td></tr>';}).join('');
  }catch(e){console.error('creds',e);}
}

// ── Bans ─────────────────────────────────────────────
async function loadBanned(){
  try{
    const rows=await fetchJ('/api/banned');
    const tb=document.getElementById('banned-body');
    if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="6" class="empty">No active bans</td></tr>';return;}
    tb.innerHTML=rows.map(function(b){var typTag=b.Permanent?'<span class="tag tag-red">permanent</span>':'<span class="tag tag-yellow">temporary</span>';return '<tr><td style="color:#60a5fa">'+esc(b.IP)+'</td><td>'+esc(b.Reason||'-')+'</td><td>'+esc(fmtTime(b.BannedAt))+'</td><td>'+esc(b.Permanent?'permanent':fmtTime(b.ExpiresAt))+'</td><td>'+typTag+'</td><td><button class="btn btn-ghost btn-sm" onclick="doUnban(\''+esc(b.IP)+'\')">Unban</button></td></tr>';}).join('');
  }catch(e){console.error('banned',e);}
}

async function doBan(){
  const ip=document.getElementById('ban-ip').value.trim();
  const dur=document.getElementById('ban-dur').value.trim();
  const perm=document.getElementById('ban-perm').checked;
  const reason=document.getElementById('ban-reason').value.trim();
  const msg=document.getElementById('ban-msg');
  if(!ip){msg.className='form-msg err';msg.textContent='Enter an IP address.';return;}
  const data={ip};
  if(dur)data.duration=dur;
  if(perm)data.permanent='1';
  if(reason)data.reason=reason;
  const r=await postForm('/api/ban',data);
  if(r.ok){
    msg.className='form-msg ok';
    msg.textContent='Banned '+ip+(perm?' (permanent)':'');
    document.getElementById('ban-ip').value='';
    document.getElementById('ban-dur').value='';
    document.getElementById('ban-reason').value='';
    document.getElementById('ban-perm').checked=false;
    showToast('Banned '+ip);
    loadBanned();
  }else{
    const txt=await r.text();
    msg.className='form-msg err';
    msg.textContent='Error: '+txt;
    showToast('Ban failed: '+txt,false);
  }
}

async function doUnban(ip){
  const r=await postForm('/api/unban',{ip});
  if(r.ok){showToast('Unbanned '+ip);loadBanned();}
  else showToast('Unban failed',false);
}

// ── Firewall ─────────────────────────────────────────
async function loadFirewall(){
  try{
    const fw=await fetchJ('/api/firewall');
    document.getElementById('fw-method').textContent=fw.method||'-';
    document.getElementById('fw-rules').textContent=(fw.rules||[]).join('\n')||'(no rules)';
  }catch(e){console.error('firewall',e);}
}

// ── Settings ─────────────────────────────────────────
async function loadSettings(){
  try{
    const s=await fetchJ('/api/settings');
    document.getElementById('set-enabled').checked=!!s.auto_ban_enabled;
    document.getElementById('set-threshold').value=s.score_threshold||0;
    document.getElementById('set-duration').value=s.ban_duration||'';
  }catch(e){console.error('settings',e);}
}

async function saveSettings(){
  const msg=document.getElementById('set-msg');
  const data={
    auto_ban_enabled:document.getElementById('set-enabled').checked?'1':'0',
    score_threshold:document.getElementById('set-threshold').value.trim(),
    ban_duration:document.getElementById('set-duration').value.trim()
  };
  const r=await postForm('/api/settings',data);
  if(r.ok){msg.className='form-msg ok';msg.textContent='Saved';showToast('Settings saved');}
  else{const t=await r.text();msg.className='form-msg err';msg.textContent='Error: '+t;showToast('Save failed',false);}
  loadSettings();
}

// ── Init & auto-refresh ──────────────────────────────
function loadAll(){
  loadStats();
  loadTimeline();
  loadConnections();
  document.getElementById('last-update').textContent='Updated '+new Date().toLocaleTimeString();
}

// Resize timeline on window resize
let resizeTimer;
window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(loadTimeline,200);});

loadAll();
setInterval(loadAll,15000);
</script>
</body>
</html>`