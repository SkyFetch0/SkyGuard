package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
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

// handleStats returns aggregate connection statistics as JSON.
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := d.db.GetConnectionStats()
	if err != nil {
		d.logger.Error("stats query error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusOK, stats)
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
		// Still return the method so the UI can show which backend is configured.
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
	if d := r.FormValue("duration"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			http.Error(w, "invalid duration", http.StatusBadRequest)
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
		// Firewall rule may not exist (e.g. method=none); log but don't fail.
		d.logger.Debug("manual unban: firewall error", "ip", ip, "error", err)
	}
	d.logger.Info("manual unban applied via dashboard", "ip", ip)
	jsonResponse(w, http.StatusOK, map[string]interface{}{"ok": true, "ip": ip})
}

// sameOriginRequest is a lightweight CSRF guard for state-changing endpoints.
// The dashboard JS sends the X-SkyGuard-Request header, which a cross-origin
// page cannot add to a "simple" request without triggering a CORS preflight
// (that the browser would then block). Modern browsers' Sec-Fetch-Site header
// is also accepted as a same-origin signal.
func sameOriginRequest(r *http.Request) bool {
	if r.Header.Get("X-SkyGuard-Request") != "" {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
		return true
	}
	return false
}

// jsonResponse writes data as JSON with the given HTTP status code.
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Headers already sent; nothing we can do except log.
		return
	}
}

// indexHTML is the inline dashboard HTML page.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SkyGuard Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:#1e293b;border-bottom:1px solid #334155;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
  header h1{font-size:1.4rem;font-weight:700;color:#38bdf8}
  header .badge{background:#ef4444;color:#fff;border-radius:9999px;padding:.2rem .6rem;font-size:.75rem;font-weight:600}
  main{padding:2rem;max-width:1400px;margin:0 auto}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}
  .card{background:#1e293b;border:1px solid #334155;border-radius:.75rem;padding:1.25rem}
  .card h3{font-size:.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
  .card .value{font-size:2rem;font-weight:700;color:#38bdf8}
  .card .label{font-size:.8rem;color:#64748b;margin-top:.25rem}
  table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:.75rem;overflow:hidden;border:1px solid #334155}
  th{background:#0f172a;color:#94a3b8;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;padding:.75rem 1rem;text-align:left}
  td{padding:.65rem 1rem;border-top:1px solid #1e293b;font-size:.85rem;color:#cbd5e1}
  tr:hover td{background:#263045}
  .section{margin-bottom:2rem}
  .section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem}
  .section-header h2{font-size:1rem;font-weight:600;color:#e2e8f0}
  .tag{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.7rem;font-weight:600}
  .tag-red{background:#7f1d1d;color:#fca5a5}
  .tag-green{background:#14532d;color:#86efac}
  .tag-yellow{background:#713f12;color:#fde68a}
  .tag-blue{background:#1e3a5f;color:#93c5fd}
  .refresh-btn{background:#334155;border:none;color:#94a3b8;padding:.4rem .9rem;border-radius:.4rem;cursor:pointer;font-size:.8rem}
  .refresh-btn:hover{background:#475569;color:#e2e8f0}
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; SkyGuard</h1>
  <span id="status-badge" class="badge">LIVE</span>
</header>
<main>
  <div class="grid" id="stats-grid">
    <div class="card"><h3>Total Connections</h3><div class="value" id="stat-total">-</div></div>
    <div class="card"><h3>Honeypot Hits</h3><div class="value" id="stat-honeypot" style="color:#f97316">-</div></div>
    <div class="card"><h3>Forwarded</h3><div class="value" id="stat-forwarded" style="color:#22c55e">-</div></div>
    <div class="card"><h3>Dropped</h3><div class="value" id="stat-dropped" style="color:#ef4444">-</div></div>
  </div>

  <div class="section">
    <div class="section-header">
      <h2>Recent Connections</h2>
      <button class="refresh-btn" onclick="loadAll()">&#x21bb; Refresh</button>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Source IP</th><th>Country</th><th>Port</th><th>Type</th><th>Action</th></tr></thead>
      <tbody id="connections-body"></tbody>
    </table>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
    <div class="section">
      <div class="section-header"><h2>Top Attackers</h2></div>
      <table>
        <thead><tr><th>IP</th><th>Country</th><th>Score</th><th>Hits</th></tr></thead>
        <tbody id="attackers-body"></tbody>
      </table>
    </div>
    <div class="section">
      <div class="section-header"><h2>Top Credentials</h2></div>
      <table>
        <thead><tr><th>Username</th><th>Password</th><th>Count</th></tr></thead>
        <tbody id="creds-body"></tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <h2>Active Bans</h2>
      <button class="refresh-btn" onclick="loadBanned()">&#x21bb; Refresh</button>
    </div>
    <table>
      <thead><tr><th>IP</th><th>Reason</th><th>Banned At</th><th>Expires</th><th>Type</th><th>Action</th></tr></thead>
      <tbody id="banned-body"></tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-header">
      <h2>Firewall Rules <span id="fw-method" class="tag tag-blue">-</span></h2>
      <button class="refresh-btn" onclick="loadFirewall()">&#x21bb; Refresh</button>
    </div>
    <div class="card" style="margin-bottom:1rem">
      <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
        <input id="ban-ip" placeholder="IP address (e.g. 1.2.3.4)" style="flex:1;min-width:180px;padding:.5rem;border-radius:.4rem;border:1px solid #334155;background:#0f172a;color:#e2e8f0">
        <input id="ban-dur" placeholder="duration (default 24h)" style="width:170px;padding:.5rem;border-radius:.4rem;border:1px solid #334155;background:#0f172a;color:#e2e8f0">
        <label style="font-size:.8rem;color:#94a3b8;display:flex;align-items:center;gap:.3rem"><input type="checkbox" id="ban-perm"> permanent</label>
        <button class="refresh-btn" onclick="banIP()">Ban IP</button>
      </div>
      <div id="ban-msg" style="font-size:.8rem;color:#94a3b8;margin-top:.5rem"></div>
    </div>
    <pre id="fw-rules" style="background:#1e293b;border:1px solid #334155;border-radius:.75rem;padding:1rem;overflow:auto;font-size:.8rem;color:#cbd5e1;white-space:pre-wrap;margin:0"></pre>
  </div>

  <div class="section">
    <div class="section-header"><h2>Auto-Ban Settings</h2></div>
    <div class="card">
      <div style="display:flex;gap:1.25rem;flex-wrap:wrap;align-items:center">
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem"><input type="checkbox" id="set-enabled"> Enabled</label>
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem">Threshold
          <input id="set-threshold" type="number" min="1" style="width:90px;padding:.4rem;border-radius:.4rem;border:1px solid #334155;background:#0f172a;color:#e2e8f0"></label>
        <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem">Ban duration
          <input id="set-duration" placeholder="1h" style="width:110px;padding:.4rem;border-radius:.4rem;border:1px solid #334155;background:#0f172a;color:#e2e8f0"></label>
        <button class="refresh-btn" onclick="saveSettings()">Save</button>
      </div>
      <div id="set-msg" style="font-size:.8rem;color:#94a3b8;margin-top:.5rem">Ban duration: e.g. 30m, 1h, 24h, 168h. 0s = permanent.</div>
    </div>
  </div>
</main>

<script>
async function fetchJSON(url){const r=await fetch(url);return r.json()}

// esc HTML-escapes attacker-controlled values (usernames, passwords, etc.)
// before they are inserted via innerHTML. Without this, honeypot-harvested
// input would execute as script in the operator's authenticated session.
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function actionTag(a){
  const m={'dropped':'tag-red','forwarded':'tag-green','honeypot':'tag-yellow','passthrough':'tag-blue'};
  const cls=m[a]||'tag-blue';
  return '<span class="tag '+cls+'">'+esc(a)+'</span>';
}

async function loadStats(){
  const s=await fetchJSON('/api/stats');
  document.getElementById('stat-total').textContent=s.total||0;
  document.getElementById('stat-honeypot').textContent=s.honeypot_hits||0;
  document.getElementById('stat-forwarded').textContent=s.forwarded||0;
  document.getElementById('stat-dropped').textContent=s.dropped||0;
}

async function loadConnections(){
  const rows=await fetchJSON('/api/connections?limit=50');
  const tb=document.getElementById('connections-body');
  tb.innerHTML=(rows||[]).map(c=>'<tr><td>'+esc(new Date(c.Timestamp).toLocaleString())+'</td><td>'+esc(c.SourceIP)+'</td><td>'+esc(c.Country||'-')+'</td><td>'+esc(c.DestPort)+'</td><td>'+esc(c.ServiceType)+'</td><td>'+actionTag(c.Action)+'</td></tr>').join('');
}

async function loadAttackers(){
  const rows=await fetchJSON('/api/attackers');
  const tb=document.getElementById('attackers-body');
  tb.innerHTML=(rows||[]).map(a=>'<tr><td>'+esc(a.IP)+'</td><td>'+esc(a.Country||'-')+'</td><td><b>'+esc(a.Score)+'</b></td><td>'+esc(a.HoneypotHits)+'</td></tr>').join('');
}

async function loadCredentials(){
  const rows=await fetchJSON('/api/credentials');
  const tb=document.getElementById('creds-body');
  tb.innerHTML=(rows||[]).map(c=>'<tr><td>'+esc(c.username)+'</td><td>'+esc(c.password)+'</td><td>'+esc(c.count)+'</td></tr>').join('');
}

async function postForm(url,data){
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-SkyGuard-Request':'1'},body:new URLSearchParams(data)});
}

async function loadBanned(){
  const rows=await fetchJSON('/api/banned');
  const tb=document.getElementById('banned-body');
  tb.innerHTML=(rows||[]).map(function(b){
    const exp=b.Permanent?'permanent':(b.ExpiresAt?new Date(b.ExpiresAt).toLocaleString():'-');
    const typ=b.Permanent?'<span class="tag tag-red">permanent</span>':'<span class="tag tag-yellow">temporary</span>';
    return '<tr><td>'+esc(b.IP)+'</td><td>'+esc(b.Reason||'-')+'</td><td>'+esc(new Date(b.BannedAt).toLocaleString())+'</td><td>'+esc(exp)+'</td><td>'+typ+'</td><td><button class="refresh-btn" onclick="unbanIP(\''+esc(b.IP)+'\')">Unban</button></td></tr>';
  }).join('');
}

async function loadFirewall(){
  const fw=await fetchJSON('/api/firewall');
  document.getElementById('fw-method').textContent=fw.method||'-';
  document.getElementById('fw-rules').textContent=(fw.rules||[]).join('\n');
}

async function banIP(){
  const ip=document.getElementById('ban-ip').value.trim();
  const dur=document.getElementById('ban-dur').value.trim();
  const perm=document.getElementById('ban-perm').checked;
  const msg=document.getElementById('ban-msg');
  if(!ip){msg.textContent='Enter an IP address.';return;}
  const data={ip:ip};
  if(dur)data.duration=dur;
  if(perm)data.permanent='1';
  const r=await postForm('/api/ban',data);
  msg.textContent=r.ok?('Banned '+ip+(perm?' (permanent)':'')):('Failed: '+(await r.text()));
  if(r.ok){document.getElementById('ban-ip').value='';document.getElementById('ban-dur').value='';document.getElementById('ban-perm').checked=false;}
  loadBanned();loadFirewall();
}

async function loadSettings(){
  const s=await fetchJSON('/api/settings');
  document.getElementById('set-enabled').checked=!!s.auto_ban_enabled;
  document.getElementById('set-threshold').value=s.score_threshold||0;
  document.getElementById('set-duration').value=s.ban_duration||'';
}

async function saveSettings(){
  const msg=document.getElementById('set-msg');
  const data={
    auto_ban_enabled:document.getElementById('set-enabled').checked?'1':'0',
    score_threshold:document.getElementById('set-threshold').value.trim(),
    ban_duration:document.getElementById('set-duration').value.trim()
  };
  const r=await postForm('/api/settings',data);
  msg.textContent=r.ok?('Saved ✓'):('Failed: '+(await r.text()));
  loadSettings();
}

async function unbanIP(ip){
  const r=await postForm('/api/unban',{ip:ip});
  if(r.ok){loadBanned();loadFirewall();}
}

function loadAll(){loadStats();loadConnections();loadAttackers();loadCredentials();loadBanned();loadFirewall();loadSettings();}
loadAll();
setInterval(loadAll,15000);
</script>
</body>
</html>`