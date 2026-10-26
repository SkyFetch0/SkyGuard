'use strict';
// SkyGuard dashboard. No inline handlers: every interactive element carries
// data-action / data-page / data-ip attributes and is handled by delegation,
// which lets the server send a strict "script-src 'self'" CSP.

(function () {
  const $ = (id) => document.getElementById(id);

  // ── Utilities ──────────────────────────────────────────────────────────
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }
  const fmtNum = (n) => (n == null ? '-' : Number(n).toLocaleString());
  const fmtTime = (ts) => (ts ? new Date(ts).toLocaleString() : '-');
  function fmtRel(ts) {
    if (!ts) return '-';
    const d = Math.round((Date.now() - new Date(ts)) / 1000);
    if (d < 60) return Math.max(d, 0) + 's ago';
    if (d < 3600) return Math.round(d / 60) + 'm ago';
    if (d < 86400) return Math.round(d / 3600) + 'h ago';
    return Math.round(d / 86400) + 'd ago';
  }

  async function api(url, opts) {
    const r = await fetch(url, Object.assign({ credentials: 'same-origin' }, opts));
    let body = null;
    const ct = r.headers.get('Content-Type') || '';
    if (ct.includes('application/json')) body = await r.json();
    else body = await r.text();
    if (!r.ok) {
      const msg = body && body.error ? body.error : (typeof body === 'string' && body ? body : r.statusText);
      throw new Error(msg.trim());
    }
    return body;
  }
  const getJSON = (url) => api(url);
  function postForm(url, data) {
    return api(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-SkyGuard-Request': '1' },
      body: new URLSearchParams(data),
    });
  }

  function toast(msg, ok = true) {
    const el = document.createElement('div');
    el.className = 'toast-item ' + (ok ? 'ok' : 'err');
    el.textContent = msg;
    $('toast').appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }
  function setError(msg) {
    const b = $('err-banner');
    b.textContent = msg || '';
    b.style.display = msg ? 'block' : 'none';
    $('live-badge').style.opacity = msg ? '.3' : '1';
  }

  const ACTION_TAGS = { dropped: 'tag-red', forwarded: 'tag-green', honeypot: 'tag-yellow' };
  const actionTag = (a) => '<span class="tag ' + (ACTION_TAGS[a] || 'tag-gray') + '">' + esc(a || '-') + '</span>';
  const svcTag = (s) => '<span class="tag tag-gray">' + esc(s || '-') + '</span>';
  const ipLink = (ip) => '<button class="link mono" data-action="ip" data-ip="' + esc(ip) + '">' + esc(ip) + '</button>';
  const empty = (cols, text) => '<tr><td colspan="' + cols + '" class="empty">' + esc(text) + '</td></tr>';
  const dataCell = (d) => '<td class="data-cell" title="' + esc(d) + '">' + esc(d || '-') + '</td>';

  // ── Navigation ─────────────────────────────────────────────────────────
  const TITLES = { overview: 'Overview', logs: 'Connection Logs', threats: 'Threats', creds: 'Credentials', bans: 'Bans', firewall: 'Firewall', settings: 'Settings' };
  const LOADERS = {
    overview: loadOverview, logs: () => {}, threats: loadAttackers, creds: loadCredentials,
    bans: loadBanned, firewall: loadFirewall, settings: loadSettings,
  };
  let currentPage = 'overview';

  function showPage(name) {
    if (!TITLES[name]) name = 'overview';
    currentPage = name;
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'page-' + name));
    document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.page === name));
    $('page-title').textContent = TITLES[name];
    if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
    refresh();
  }
  function refresh() {
    Promise.resolve(LOADERS[currentPage]()).then(() => {
      $('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();
    });
  }

  // ── Overview ───────────────────────────────────────────────────────────
  async function loadOverview() {
    await Promise.all([loadStats(), loadTimeline(), loadRecent()]);
  }

  async function loadStats() {
    try {
      const s = await getJSON('/api/stats');
      $('s-total').textContent = fmtNum(s.total);
      $('s-honeypot').textContent = fmtNum(s.honeypot_hits);
      $('s-forwarded').textContent = fmtNum(s.forwarded);
      $('s-dropped').textContent = fmtNum(s.dropped);
      $('s-today').textContent = fmtNum(s.connections_today);
      $('s-bans').textContent = fmtNum(s.active_bans);
      $('s-bans-today').textContent = fmtNum(s.bans_today) + ' today';
      $('s-creds').textContent = fmtNum(s.credentials);
      $('s-ips').textContent = fmtNum(s.unique_ips);
      $('s-countries').textContent = fmtNum(s.unique_countries) + ' countries';
      setError('');
    } catch (e) {
      setError('Cannot reach SkyGuard API: ' + e.message);
    }
  }

  let lastTimeline = [];
  async function loadTimeline() {
    try {
      lastTimeline = await getJSON('/api/timeline?hours=24');
      drawTimeline($('timeline-svg'), lastTimeline);
    } catch (e) { console.error('timeline', e); }
  }

  function drawTimeline(svg, data) {
    const W = svg.clientWidth || 800, H = 140, pad = { t: 8, r: 8, b: 24, l: 40 };
    const iW = W - pad.l - pad.r, iH = H - pad.t - pad.b, n = data.length;
    const maxVal = Math.max(1, ...data.map((d) => d.total));
    const x = (i) => pad.l + i * (iW / Math.max(n - 1, 1));
    const y = (v) => pad.t + iH - (v / maxVal) * iH;
    const path = (key) => data.map((pt, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(pt[key]).toFixed(1)).join(' ');

    let out = '';
    for (let i = 0; i <= 4; i++) {
      const gy = pad.t + iH * (i / 4);
      out += '<line x1="' + pad.l + '" y1="' + gy.toFixed(1) + '" x2="' + (pad.l + iW) + '" y2="' + gy.toFixed(1) + '" stroke="#1f2d45"/>';
      out += '<text x="' + (pad.l - 4) + '" y="' + (gy + 3).toFixed(1) + '" text-anchor="end" font-size="9" fill="#64748b">' + Math.round(maxVal * (1 - i / 4)) + '</text>';
    }
    if (n) {
      const area = path('total') + ' L' + x(n - 1).toFixed(1) + ',' + (pad.t + iH) + ' L' + pad.l + ',' + (pad.t + iH) + ' Z';
      out += '<defs><linearGradient id="gtot" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#3b82f6" stop-opacity=".25"/><stop offset="100%" stop-color="#3b82f6" stop-opacity=".02"/></linearGradient></defs>';
      out += '<path d="' + area + '" fill="url(#gtot)"/>';
      [['total', '#3b82f6'], ['honeypot_hits', '#f97316'], ['dropped', '#ef4444'], ['forwarded', '#22c55e']].forEach(([k, c]) => {
        out += '<path d="' + path(k) + '" fill="none" stroke="' + c + '" stroke-width="1.5" stroke-linejoin="round"/>';
      });
      const step = Math.ceil(n / 6);
      data.forEach((pt, i) => {
        if (i % step) return;
        const label = new Date(pt.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        out += '<text x="' + x(i).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="middle" font-size="9" fill="#64748b">' + esc(label) + '</text>';
      });
    }
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.innerHTML = out;
  }

  async function loadRecent() {
    try {
      const rows = await getJSON('/api/connections?limit=50');
      $('conn-count').textContent = rows.length + ' rows';
      $('conn-body').innerHTML = rows.length ? rows.map((c) =>
        '<tr><td title="' + esc(fmtTime(c.timestamp)) + '">' + esc(fmtRel(c.timestamp)) + '</td><td>' + ipLink(c.source_ip) +
        '</td><td>' + esc(c.country || '-') + '</td><td>' + esc(c.dest_port) + '</td><td>' + svcTag(c.service_type) +
        '</td><td>' + actionTag(c.action) + '</td>' + dataCell(c.data) + '</tr>').join('') : empty(7, 'No connections yet');
    } catch (e) { console.error('connections', e); }
  }

  // ── Connection log search ──────────────────────────────────────────────
  let searchOffset = 0;
  function searchParams() {
    const f = $('search-form');
    const p = new URLSearchParams();
    ['ip', 'country', 'service', 'action'].forEach((k) => { const v = f.elements[k].value.trim(); if (v) p.set(k, v); });
    ['since', 'until'].forEach((k) => { const v = f.elements[k].value; if (v) p.set(k, new Date(v).toISOString()); });
    return p;
  }
  async function runSearch() {
    const p = searchParams();
    const limit = Math.min(Math.max(parseInt($('search-form').elements.limit.value, 10) || 200, 1), 10000);
    p.set('limit', limit);
    p.set('offset', searchOffset);
    $('search-body').innerHTML = empty(9, 'Searching...');
    try {
      const rows = await getJSON('/api/connections?' + p.toString());
      $('search-count').textContent = rows.length + ' result(s)';
      $('page-info').textContent = rows.length ? (searchOffset + 1) + '–' + (searchOffset + rows.length) : '';
      $('search-body').innerHTML = rows.length ? rows.map((c) =>
        '<tr><td>' + esc(fmtTime(c.timestamp)) + '</td><td>' + ipLink(c.source_ip) + '</td><td>' + esc(c.source_port) +
        '</td><td>' + esc(c.dest_port) + '</td><td>' + esc(c.country || '-') + '</td><td>' + esc(c.city || '-') +
        '</td><td>' + svcTag(c.service_type) + '</td><td>' + actionTag(c.action) + '</td>' + dataCell(c.data) + '</tr>').join('')
        : empty(9, 'No results');
    } catch (e) {
      $('search-body').innerHTML = empty(9, 'Search failed');
      toast('Search failed: ' + e.message, false);
    }
  }
  function searchByIP(ip) {
    $('search-form').reset();
    $('search-form').elements.ip.value = ip;
    searchOffset = 0;
    closeModal();
    showPage('logs');
    runSearch();
  }

  // ── Threats / credentials ──────────────────────────────────────────────
  async function loadAttackers() {
    try {
      const rows = await getJSON('/api/attackers?limit=100');
      const max = Math.max(1, ...rows.map((r) => r.score));
      $('attackers-body').innerHTML = rows.length ? rows.map((a) =>
        '<tr><td>' + ipLink(a.ip) + '</td><td>' + esc(a.country || '-') + '</td><td><div class="score-bar"><div class="score-track"><div class="score-fill" style="width:' +
        Math.round(a.score / max * 100) + '%"></div></div><span class="score-num">' + esc(a.score) + '</span></div></td><td>' + esc(a.total_connections) +
        '</td><td>' + esc(a.honeypot_hits) + '</td><td>' + esc(a.credential_attempts) + '</td><td class="mono">' + esc((a.ports_scanned || []).join(', ') || '-') +
        '</td><td title="' + esc(fmtTime(a.last_seen)) + '">' + esc(fmtRel(a.last_seen)) + '</td><td><button class="btn btn-danger btn-sm" data-action="prefill-ban" data-ip="' + esc(a.ip) + '">Ban</button></td></tr>').join('')
        : empty(9, 'No threats detected');
    } catch (e) { console.error('attackers', e); }
  }

  async function loadCredentials() {
    try {
      const rows = await getJSON('/api/credentials?limit=200');
      $('creds-body').innerHTML = rows.length ? rows.map((c) =>
        '<tr><td>' + svcTag(c.service) + '</td><td class="mono" style="color:#fde68a">' + esc(c.username) + '</td><td class="mono" style="color:#fca5a5">' +
        esc(c.password || (c.service === 'mysql' ? '(hashed)' : '')) + '</td><td><strong>' + esc(c.count) + '</strong></td><td title="' + esc(fmtTime(c.last_seen)) + '">' + esc(fmtRel(c.last_seen)) + '</td></tr>').join('')
        : empty(5, 'No credentials captured yet');
    } catch (e) { console.error('creds', e); }
  }

  // ── Bans ───────────────────────────────────────────────────────────────
  async function loadBanned() {
    try {
      const rows = await getJSON('/api/banned');
      $('ban-count').textContent = rows.length + ' active';
      $('banned-body').innerHTML = rows.length ? rows.map((b) =>
        '<tr><td>' + ipLink(b.ip) + '</td><td>' + esc(b.reason || '-') + '</td><td>' + esc(fmtTime(b.banned_at)) + '</td><td>' +
        esc(b.permanent ? 'never' : fmtTime(b.expires_at)) + '</td><td>' + (b.permanent ? '<span class="tag tag-red">permanent</span>' : '<span class="tag tag-yellow">temporary</span>') +
        '</td><td><button class="btn btn-ghost btn-sm" data-action="unban" data-ip="' + esc(b.ip) + '">Unban</button></td></tr>').join('')
        : empty(6, 'No active bans');
    } catch (e) { console.error('banned', e); }
  }

  async function doBan(form) {
    const msg = $('ban-msg');
    const data = Object.fromEntries(new FormData(form).entries());
    try {
      await postForm('/api/ban', data);
      msg.className = 'form-msg ok';
      msg.textContent = 'Banned ' + data.ip + (data.permanent ? ' (permanent)' : '');
      form.reset();
      toast('Banned ' + data.ip);
      loadBanned();
    } catch (e) {
      msg.className = 'form-msg err';
      msg.textContent = 'Error: ' + e.message;
      toast('Ban failed: ' + e.message, false);
    }
  }

  async function doUnban(ip) {
    if (!confirm('Unban ' + ip + '? Its threat score will be reset.')) return;
    try {
      await postForm('/api/unban', { ip });
      toast('Unbanned ' + ip);
      if ($('ip-modal').classList.contains('open')) openIP(ip);
      refresh();
    } catch (e) { toast('Unban failed: ' + e.message, false); }
  }

  function prefillBan(ip) {
    closeModal();
    showPage('bans');
    $('ban-ip').value = ip;
    $('ban-ip').focus();
  }

  // ── Firewall / settings ────────────────────────────────────────────────
  async function loadFirewall() {
    try {
      const fw = await getJSON('/api/firewall');
      $('fw-method').textContent = fw.method || '-';
      $('fw-rules').textContent = (fw.rules || []).join('\n') || '(no rules)';
    } catch (e) { $('fw-rules').textContent = 'Error: ' + e.message; }
  }

  async function loadSettings() {
    try {
      const s = await getJSON('/api/settings');
      $('set-enabled').checked = !!s.auto_ban_enabled;
      $('set-threshold').value = s.score_threshold || '';
      $('set-duration').value = s.ban_duration || '';
    } catch (e) { console.error('settings', e); }
  }

  async function saveSettings() {
    const msg = $('set-msg');
    try {
      await postForm('/api/settings', {
        auto_ban_enabled: $('set-enabled').checked ? '1' : '0',
        score_threshold: $('set-threshold').value.trim(),
        ban_duration: $('set-duration').value.trim(),
      });
      msg.className = 'form-msg ok';
      msg.textContent = 'Saved';
      toast('Settings saved');
    } catch (e) {
      msg.className = 'form-msg err';
      msg.textContent = 'Error: ' + e.message;
      toast('Save failed', false);
    }
    loadSettings();
  }

  // ── IP detail modal ────────────────────────────────────────────────────
  async function openIP(ip) {
    $('ip-title').textContent = ip;
    $('ip-kv').innerHTML = '';
    $('ip-creds').innerHTML = empty(4, 'Loading...');
    $('ip-conns').innerHTML = empty(5, 'Loading...');
    $('ip-modal').classList.add('open');
    try {
      const d = await getJSON('/api/ip?ip=' + encodeURIComponent(ip));
      const s = d.score || {};
      let tags = '';
      if (d.whitelisted) tags += '<span class="tag tag-green">whitelisted</span> ';
      if (d.banned) tags += '<span class="tag tag-red">banned</span>';
      $('ip-tags').innerHTML = tags;
      $('ip-actions').innerHTML = '<button class="btn btn-ghost btn-sm" data-action="search-ip" data-ip="' + esc(ip) + '">All logs</button>' +
        (d.banned ? '<button class="btn btn-ghost btn-sm" data-action="unban" data-ip="' + esc(ip) + '">Unban</button>'
          : (d.whitelisted ? '' : '<button class="btn btn-danger btn-sm" data-action="prefill-ban" data-ip="' + esc(ip) + '">Ban</button>'));
      const kv = [['Score', s.score], ['Country', s.country || '-'], ['Events', s.total_connections], ['Honeypot hits', s.honeypot_hits],
        ['Credential attempts', s.credential_attempts], ['Ports', (s.ports_scanned || []).join(', ') || '-'],
        ['First seen', fmtTime(s.first_seen)], ['Last seen', fmtTime(s.last_seen)]];
      $('ip-kv').innerHTML = kv.map(([k, v]) => '<div><span>' + esc(k) + '</span>' + esc(v == null ? '-' : v) + '</div>').join('');
      $('ip-creds').innerHTML = d.credentials.length ? d.credentials.map((c) =>
        '<tr><td>' + esc(fmtTime(c.timestamp)) + '</td><td>' + svcTag(c.service) + '</td><td class="mono">' + esc(c.username) + '</td><td class="mono">' + esc(c.password) + '</td></tr>').join('')
        : empty(4, 'No credentials');
      $('ip-conns').innerHTML = d.connections.length ? d.connections.map((c) =>
        '<tr><td>' + esc(fmtTime(c.timestamp)) + '</td><td>' + esc(c.dest_port) + '</td><td>' + svcTag(c.service_type) + '</td><td>' + actionTag(c.action) + '</td>' + dataCell(c.data) + '</tr>').join('')
        : empty(5, 'No connections');
    } catch (e) {
      $('ip-kv').innerHTML = '<div>Error: ' + esc(e.message) + '</div>';
    }
  }
  function closeModal() { $('ip-modal').classList.remove('open'); }

  // ── Event wiring ───────────────────────────────────────────────────────
  document.addEventListener('click', (ev) => {
    const nav = ev.target.closest('[data-page]');
    if (nav) { showPage(nav.dataset.page); return; }
    const el = ev.target.closest('[data-action]');
    if (!el) return;
    const ip = el.dataset.ip;
    switch (el.dataset.action) {
      case 'refresh': refresh(); break;
      case 'ip': openIP(ip); break;
      case 'search-ip': searchByIP(ip); break;
      case 'prefill-ban': prefillBan(ip); break;
      case 'unban': doUnban(ip); break;
      case 'clear-search':
        $('search-form').reset(); searchOffset = 0;
        $('search-body').innerHTML = empty(9, 'Run a search above');
        $('search-count').textContent = ''; $('page-info').textContent = '';
        break;
      case 'export': location.href = '/api/export?' + searchParams().toString(); break;
      case 'page-next': searchOffset += parseInt($('search-form').elements.limit.value, 10) || 200; runSearch(); break;
      case 'page-prev': searchOffset = Math.max(0, searchOffset - (parseInt($('search-form').elements.limit.value, 10) || 200)); runSearch(); break;
      case 'close-modal': if (ev.target === el) closeModal(); break;
    }
  });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeModal(); });
  $('search-form').addEventListener('submit', (ev) => { ev.preventDefault(); searchOffset = 0; runSearch(); });
  $('ban-form').addEventListener('submit', (ev) => { ev.preventDefault(); doBan(ev.target); });
  $('settings-form').addEventListener('submit', (ev) => { ev.preventDefault(); saveSettings(); });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => drawTimeline($('timeline-svg'), lastTimeline), 150);
  });

  showPage(location.hash.slice(1) || 'overview');
  // Auto-refresh only the live views, and not while the tab is hidden.
  setInterval(() => {
    if (!document.hidden && (currentPage === 'overview' || currentPage === 'bans' || currentPage === 'threats')) refresh();
  }, 15000);
})();
