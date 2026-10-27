'use strict';
// SkyGuard dashboard. Every interactive element carries data-* attributes and is handled by delegation, so the
// server can send a strict "script-src 'self'" CSP. Charts come from charts.js (tasteskill, MIT).

(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  // ── formatting ──────────────────────────────────────────────────────────
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const nf = new Intl.NumberFormat('en');
  const num = (n) => (n == null ? '—' : nf.format(n));
  const MINUS = '−';
  const signed = (n) => (n > 0 ? '+' : n < 0 ? MINUS : '') + nf.format(Math.abs(n));
  const pct = (part, whole) => (whole ? `${(100 * part / whole).toFixed(part / whole < 0.1 ? 1 : 0)}%` : '0%');
  // Times use a 24-hour clock so chart axes step on whole hours (charts.js reads "HH:MM" labels as a clock).
  const fClock = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const fDay = new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric' });
  const fDate = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' });
  const clock = (d) => fClock.format(d);
  const dayName = (d) => fDay.format(d);
  const dateShort = (d) => fDate.format(d);
  const hourLabel = (h) => fClock.format(new Date(2000, 0, 1, h % 24));
  const stamp = (ts) => { if (!ts) return '—'; const d = new Date(ts); return `${dateShort(d)} ${clock(d)}`; };
  function ago(ts) {
    if (!ts) return '—';
    const s = Math.round((Date.now() - new Date(ts)) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }
  function until(ts) {
    if (!ts) return 'never';
    const s = Math.round((new Date(ts) - Date.now()) / 1000);
    if (s <= 0) return 'now';
    if (s < 3600) return `in ${Math.max(1, Math.round(s / 60))} min`;
    if (s < 86400) return `in ${Math.round(s / 3600)} h`;
    return `in ${Math.round(s / 86400)} d`;
  }
  const RANGE_WORDS = { '24h': '24 hours', '7d': '7 days', '30d': '30 days' };
  const SERVICE_NAMES = { ssh: 'SSH honeypot', ftp: 'FTP honeypot', mysql: 'MySQL honeypot', http: 'HTTP honeypot', stealth: 'Stealth port', passthrough: 'Passthrough' };
  const svcName = (k) => SERVICE_NAMES[k] || k;
  const OUTCOMES = {
    honeypot: { label: 'Trapped by a honeypot', colour: 'var(--flow-honeypot)' },
    forwarded: { label: 'Let through', colour: 'var(--flow-forwarded)' },
    banned: { label: 'Dropped: already banned', colour: 'var(--flow-1)' },
    blacklist: { label: 'Dropped: blacklist', colour: 'var(--flow-2)' },
    rate_limited: { label: 'Dropped: rate limit', colour: 'var(--flow-3)' },
    port_scan: { label: 'Dropped: port scan', colour: 'var(--flow-4)' },
    stealth_probe: { label: 'Dropped: stealth probe', colour: 'var(--flow-5)' },
    dropped_other: { label: 'Dropped: other', colour: 'var(--flow-6)' },
  };
  const OUTCOME_TAGS = { honeypot: 'Honeypot', dropped: 'Dropped', forwarded: 'Forwarded' };
  const outcomePill = (a) => (OUTCOME_TAGS[a] ? `<span class="pill o-${a}"><span class="dot"></span>${OUTCOME_TAGS[a]}</span>` : `<span class="pill">${esc(a || '—')}</span>`);
  // A ban is the system doing its job, not an alarm: a neutral tag.
  const BANNED = '<span class="pill"><span class="dot"></span>Banned</span>';
  const ipLink = (ip) => `<button class="ip-link" type="button" data-action="ip" data-ip="${esc(ip)}" translate="no" aria-label="Details for ${esc(ip)}">${esc(ip)}</button>`;
  const emptyRow = (cols, text) => `<tr><td colspan="${cols}"><div class="empty">${esc(text)}</div></td></tr>`;
  const emptyBlock = (text) => `<li><div class="empty">${esc(text)}</div></li>`;
  const skeletonRows = (cols, n = 5) => Array.from({ length: n }, () => `<tr>${'<td><span class="skeleton">000.000.000</span></td>'.repeat(cols)}</tr>`).join('');

  // ── api ─────────────────────────────────────────────────────────────────
  async function api(url, opts) {
    // Resolved against the origin: opened as http://user:pass@host/, the page's own URL carries the
    // credentials and the browser refuses to fetch any relative URL from it.
    const r = await fetch(new URL(url, location.origin), Object.assign({ credentials: 'same-origin' }, opts));
    const ct = r.headers.get('Content-Type') || '';
    const body = ct.includes('application/json') ? await r.json() : await r.text();
    if (!r.ok) throw new Error(((body && body.error) || (typeof body === 'string' && body) || r.statusText).trim());
    return body;
  }
  const post = (url, data) => api(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-SkyGuard-Request': '1' },
    body: new URLSearchParams(data),
  });

  function toast(msg, ok = true) {
    const el = document.createElement('div');
    el.className = 'toast' + (ok ? '' : ' err');
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }
  // A block that failed keeps its frame and says so, with a retry.
  function blockError(el, what, e) {
    const html = `<div class="block-error">Couldn't load ${esc(what)}: ${esc(e.message)}. <button class="card-link" type="button" data-action="refresh">Retry</button></div>`;
    if (el.tagName === 'TBODY') el.innerHTML = `<tr><td colspan="9">${html}</td></tr>`;
    else if (el.tagName === 'OL' || el.tagName === 'UL') el.innerHTML = `<li>${html}</li>`;
    else el.innerHTML = html;
  }

  // ── state ───────────────────────────────────────────────────────────────
  const state = {
    range: '24h',
    metric: 'total',
    info: null,
    conn: { action: '', offset: 0, limit: 200 },
    banned: new Set(),
  };
  const METRICS = [
    { key: 'total', label: 'Connections', field: 'connections', title: 'Connections' },
    { key: 'honeypot_hits', label: 'Honeypot hits', field: 'honeypot_hits', title: 'Honeypot hits' },
    { key: 'credentials', label: 'Logins tried', field: 'credentials', title: 'Logins tried' },
    { key: 'dropped', label: 'Dropped', field: 'dropped', title: 'Dropped connections' },
  ];

  // ── overview ────────────────────────────────────────────────────────────
  let lastSummary = null, lastSeries = null;

  async function loadOverview() {
    const [summary, series, latest] = await Promise.allSettled([
      api(`/api/summary?range=${state.range}`),
      api(`/api/series?range=${state.range}`),
      api('/api/connections?limit=6'),
    ]);
    if (summary.status === 'fulfilled') { lastSummary = summary.value; renderSummary(lastSummary); }
    else ['#kpis', '#flow', '#sources', '#by-service', '#by-geo'].forEach((s) => blockError($(s), 'the summary', summary.reason));
    if (series.status === 'fulfilled') { lastSeries = series.value; renderSeries(); }
    else blockError($('#series-chart'), 'the chart', series.reason);
    if (latest.status === 'fulfilled') renderLatest(latest.value);
    else blockError($('#latest'), 'the latest events', latest.reason);
    $$('[data-stamp]').forEach((el) => { el.textContent = `Updated ${clock(new Date())}`; });
  }

  function renderSummary(s) {
    const words = RANGE_WORDS[s.range.name];
    const cur = s.current, prev = s.previous;
    $('#kpis').innerHTML = METRICS.map((m) => {
      const v = cur[m.field], p = prev[m.field], d = v - p;
      const delta = v === 0 && p === 0 ? 'none in either period'
        : p === 0 ? `<span class="num">${signed(v)}</span> (new) vs previous ${words}`
        : d === 0 ? `same as previous ${words}`
        : `<span class="num">${signed(d)}</span> vs previous ${words}`;
      const sel = state.metric === m.key;
      return `<button class="kpi" role="tab" type="button" aria-selected="${sel}" data-metric="${m.key}">
        <div class="kpi-label">${esc(m.label)}</div><div class="kpi-value">${num(v)}</div><div class="delta">${delta}</div></button>`;
    }).join('');

    // The finding: the busiest source and whether it is stopped yet.
    const top = s.top_sources[0];
    const f = $('#finding');
    if (!cur.connections) {
      f.textContent = `No connections in the last ${words}.`;
    } else if (top) {
      const where = top.country ? ` (${esc(top.country)})` : '';
      const state_ = top.banned ? 'It is banned now.' : `It is not banned yet. <button class="card-link" type="button" data-action="ban" data-ip="${esc(top.ip)}">Ban it</button>`;
      f.innerHTML = `<strong class="mono">${esc(top.ip)}</strong>${where} made ${num(top.count)} of ${num(cur.connections)} connections in the last ${words} (${pct(top.count, cur.connections)}). ${state_}`;
    }

    // Decision flow: where every connection ended up.
    const outs = s.outcomes.filter((o) => o.count > 0), total = outs.reduce((a, o) => a + o.count, 0);
    $('#flow-meta').textContent = `${num(total)} connections`;
    $('#flow').innerHTML = !total ? '<div class="empty">No connections in this range.</div>'
      : `<div class="flow-bar" role="img" aria-label="${esc(outs.map((o) => `${OUTCOMES[o.key].label} ${pct(o.count, total)}`).join(', '))}">${outs.map((o) => `<span style="flex:${o.count};background:${OUTCOMES[o.key].colour}" title="${esc(OUTCOMES[o.key].label)}: ${num(o.count)}"></span>`).join('')}</div>
         <div class="flow-rows">${outs.map((o) => `<div class="flow-row"><i style="background:${OUTCOMES[o.key].colour}"></i><span>${esc(OUTCOMES[o.key].label)}</span><span class="n num">${num(o.count)}</span><span class="share num">${pct(o.count, total)}</span></div>`).join('')}</div>`;

    // Busiest sources, with the ban one click away.
    const maxSrc = Math.max(1, ...s.top_sources.map((x) => x.count));
    $('#sources').innerHTML = s.top_sources.length ? s.top_sources.slice(0, 5).map((x) => `<li>
        <span class="who">${ipLink(x.ip)}<span class="muted">${esc(x.country || '')}</span></span>
        <span class="n num">${num(x.count)}</span>
        <span class="act">${x.banned ? BANNED : `<button class="btn small" type="button" data-action="ban" data-ip="${esc(x.ip)}">Ban</button>`}</span>
        <span class="bar" style="width:${(100 * x.count / maxSrc).toFixed(1)}%"></span></li>`).join('') : emptyBlock('No sources in this range.');

    rankInto($('#by-service'), s.services.slice(0, 5).map((x) => ({ label: svcName(x.key), value: x.count })), 'No traffic in this range.');
    const useGeo = s.countrys && s.countrys.length;
    $('#geo-title').textContent = useGeo ? 'Countries' : 'Ports';
    rankInto($('#by-geo'), (useGeo ? s.countrys : s.ports).slice(0, 5).map((x) => ({ label: x.key, value: x.count, mono: !useGeo })), 'No traffic in this range.');
  }

  // A ranked list where a 2px bar under each label carries the share; the top item in the hue.
  function rankInto(el, rows, emptyText) {
    if (!rows.length) { el.innerHTML = emptyBlock(emptyText); return; }
    const max = Math.max(1, ...rows.map((r) => r.value));
    el.innerHTML = rows.map((r) => `<li><span class="who"><span class="${r.mono ? 'mono' : ''}" title="${esc(r.label)}">${esc(r.label)}</span></span>
      <span class="n num">${num(r.value)}</span><span></span><span class="bar" style="width:${(100 * r.value / max).toFixed(1)}%"></span></li>`).join('');
  }

  function bucketLabels(buckets, bucket) {
    return buckets.map((b) => {
      const d = new Date(b.bucket);
      if (bucket === 'day') return dateShort(d);
      if (state.range === '24h') return clock(d);
      return d.getHours() === 0 ? dayName(d) : `${dayName(d)} ${clock(d)}`;
    });
  }

  function renderSeries() {
    const m = METRICS.find((x) => x.key === state.metric);
    const { buckets, range } = lastSeries;
    const values = buckets.map((b) => b[m.key] || 0);
    const labels = bucketLabels(buckets, range.bucket);
    const per = range.bucket === 'day' ? 'day' : 'hour';
    $('#series-title').textContent = `${m.title} per ${per}`;
    const total = values.reduce((a, v) => a + v, 0);
    $('#series-meta').textContent = `${num(total)} in the last ${RANGE_WORDS[range.name]}`;
    const el = $('#series-chart');
    // A spike more than three times the typical bucket is named on the chart.
    const sorted = [...values].sort((a, b) => a - b), median = sorted[Math.floor(sorted.length / 2)] || 0;
    const peak = Math.max(...values), at = values.indexOf(peak);
    const annotations = peak >= 10 && peak > 3 * Math.max(1, median) ? [{ at, label: `Peak ${num(peak)} · ${labels[at]}`, short: `Peak ${num(peak)}` }] : undefined;
    const xAt = range.bucket === 'hour' && range.name === '7d' ? buckets.map((b, i) => (new Date(b.bucket).getHours() === 0 ? i : -1)).filter((i) => i >= 0) : null;
    Charts.bars(el, { labels, values, height: 220, annotations, xAt, format: Charts.fmt.int });
  }

  function renderLatest(rows) {
    $('#latest').innerHTML = rows.length ? rows.map((c) => `<tr>
      <td title="${esc(stamp(c.timestamp))}">${esc(ago(c.timestamp))}</td><td>${ipLink(c.source_ip)}</td><td>${esc(c.country || '—')}</td>
      <td>${esc(svcName(c.service_type))}</td><td class="n">${c.dest_port}</td>
      <td class="data" title="${esc(c.data)}">${esc(c.data || '—')}</td><td class="n">${outcomePill(c.action)}</td></tr>`).join('') : emptyRow(7, 'No connections yet.');
  }

  // ── connections ─────────────────────────────────────────────────────────
  function connParams() {
    const f = $('#conn-filters'), p = new URLSearchParams();
    for (const k of ['ip', 'service', 'country']) { const v = f.elements[k].value.trim(); if (v) p.set(k, v); }
    if (state.conn.action) p.set('action', state.conn.action);
    return p;
  }
  async function loadConnections() {
    const p = connParams();
    p.set('limit', state.conn.limit); p.set('offset', state.conn.offset);
    const body = $('#conn-body');
    if (!body.children.length) body.innerHTML = skeletonRows(8);
    const [rows, heat] = await Promise.allSettled([api('/api/connections?' + p), api('/api/series?range=7d')]);
    if (rows.status === 'fulfilled') {
      const r = rows.value;
      body.innerHTML = r.length ? r.map((c) => `<tr>
        <td title="${esc(stamp(c.timestamp))}" class="num">${esc(stamp(c.timestamp))}</td><td>${ipLink(c.source_ip)}</td><td class="n">${c.source_port || '—'}</td>
        <td>${esc(c.country || '—')}</td><td>${esc(svcName(c.service_type))}</td><td class="n">${c.dest_port}</td>
        <td class="data" title="${esc(c.data)}">${esc(c.data || '—')}</td><td class="n">${outcomePill(c.action)}</td></tr>`).join('') : emptyRow(8, 'No connections match these filters.');
      $('#page-info').textContent = r.length ? `${num(state.conn.offset + 1)}–${num(state.conn.offset + r.length)}` : '';
      $('#conn-count').textContent = r.length === state.conn.limit ? 'More are available' : `${num(state.conn.offset + r.length)} shown`;
      $('[data-action="page-prev"]').disabled = state.conn.offset === 0;
      $('[data-action="page-next"]').disabled = r.length < state.conn.limit;
    } else blockError(body, 'connections', rows.reason);
    if (heat.status === 'fulfilled') drawHeatmap($('#heatmap'), heat.value.buckets);
    else blockError($('#heatmap'), 'the heatmap', heat.reason);
  }

  // Seven local days by 24 local hours; one hue ramping from the empty cell to the busiest hour.
  function drawHeatmap(el, buckets) {
    const days = [], byKey = new Map();
    for (const b of buckets) {
      const d = new Date(b.bucket), key = d.toDateString();
      if (!byKey.has(key)) { byKey.set(key, new Array(24).fill(0)); days.push(d); }
      byKey.get(key)[d.getHours()] += b.total;
    }
    const rows = days.slice(-7), now = new Date();
    const isFuture = (d, hr) => d.toDateString() === now.toDateString() && hr > now.getHours();
    // One burst must not flatten the week: the scale tops out at the 95th percentile of the busy hours.
    const seen = rows.flatMap((d) => byKey.get(d.toDateString())).filter((v) => v > 0).sort((a, b) => a - b);
    const peakHour = seen.length ? seen[seen.length - 1] : 0;
    const max = Math.max(1, seen.length ? seen[Math.min(seen.length - 1, Math.floor(seen.length * 0.95))] : 1);
    const w = Math.max(320, el.clientWidth || 900), labelW = 64, cellGap = 2;
    const cw = (w - labelW) / 24, ch = 18, h = rows.length * (ch + cellGap) + 20;
    const steps = [0.18, 0.36, 0.56, 0.78, 1];
    const fill = (v) => (v === 0 ? 'var(--raised)' : `color-mix(in srgb, var(--accent) ${Math.round(100 * steps[Math.min(4, Math.floor(4.999 * Math.min(v, max) / max))])}%, var(--surface))`);
    let out = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-label="Connections by local day and hour over the last 7 days; busiest hour ${num(peakHour)}">`;
    rows.forEach((d, r) => {
      const y = r * (ch + cellGap);
      out += `<text x="0" y="${y + 13}">${esc(dayName(d))}</text>`;
      byKey.get(d.toDateString()).forEach((v, hr) => {
        if (isFuture(d, hr)) return;
        out += `<rect x="${(labelW + hr * cw).toFixed(1)}" y="${y}" width="${(cw - cellGap).toFixed(1)}" height="${ch}" rx="2" fill="${fill(v)}"><title>${esc(dayName(d))}, ${hourLabel(hr)}–${hourLabel(hr + 1)}: ${num(v)} connections</title></rect>`;
      });
    });
    for (let hr = 0; hr < 24; hr += 3) out += `<text x="${(labelW + hr * cw).toFixed(1)}" y="${h - 4}">${hourLabel(hr)}</text>`;
    out += '</svg>';
    const legend = `<div class="heat-legend">None<i style="background:var(--raised)"></i>${steps.map((s) => `<i style="background:color-mix(in srgb, var(--accent) ${Math.round(100 * s)}%, var(--surface))"></i>`).join('')}<span class="num">${num(max)}</span> or more · busiest hour <span class="num">${num(peakHour)}</span></div>`;
    el.innerHTML = out + legend;
  }

  // ── attackers and bans ──────────────────────────────────────────────────
  async function loadAttackers() {
    const [att, bans, info] = await Promise.allSettled([api('/api/attackers?limit=12'), api('/api/banned'), api('/api/info')]);
    const threshold = info.status === 'fulfilled' ? info.value.score_threshold : null;
    const autoOn = info.status === 'fulfilled' && info.value.auto_ban_enabled;
    $('#threshold-meta').textContent = threshold ? (autoOn ? `Auto-ban at ${num(threshold)} points` : `Auto-ban is off (threshold ${num(threshold)})`) : '';
    if (bans.status === 'fulfilled') {
      const b = bans.value;
      state.banned = new Set(b.map((x) => x.ip));
      $('#ban-count').textContent = `${num(b.length)} active`;
      $('#bans').innerHTML = b.length ? b.map((x) => `<tr><td>${ipLink(x.ip)}</td><td class="muted">${esc(x.reason || 'manual')}</td>
        <td class="n" title="${esc(x.permanent ? 'Permanent' : stamp(x.expires_at))}">${esc(x.permanent ? 'never' : until(x.expires_at))}</td>
        <td class="n"><button class="btn small" type="button" data-action="unban" data-ip="${esc(x.ip)}">Unban</button></td></tr>`).join('') : emptyRow(4, 'No active bans.');
      $('#att-sub').textContent = `${num(b.length)} IPs are banned. Scores add up from honeypot hits, failed logins, scans and rate limits.`;
      const REASONS = { failed_credential: 'Failed logins', honeypot_threshold: 'Honeypot hits', port_scan: 'Port scan', rate_limit_exceeded: 'Rate limit', blacklisted_country: 'Blacklisted country', manual: 'Banned by hand' };
      const byReason = {};
      b.forEach((x) => { const k = REASONS[x.reason] || x.reason || 'Banned by hand'; byReason[k] = (byReason[k] || 0) + 1; });
      rankInto($('#ban-reasons'), Object.entries(byReason).sort((p, q) => q[1] - p[1]).map(([label, value]) => ({ label, value })), 'Nobody is banned.');
      const perm = b.filter((x) => x.permanent).length;
      $('#reason-meta').textContent = perm ? `${num(perm)} permanent` : '';
    } else blockError($('#bans'), 'bans', bans.reason);
    if (att.status === 'fulfilled') {
      const rows = att.value, top = Math.max(threshold || 0, ...rows.map((r) => r.score)) || 1;
      $('#attackers').innerHTML = rows.length ? rows.map((a) => {
        const banned = state.banned.has(a.ip);
        const tick = threshold ? `<span class="tick" style="left:${(100 * threshold / top).toFixed(1)}%"></span>` : '';
        return `<li>
          <span class="who">${ipLink(a.ip)}<span class="muted">${esc(a.country || '')}</span><span class="muted detail">${num(a.total_connections)} events · ${num(a.credential_attempts)} logins · ports ${esc((a.ports_scanned || []).join(', ') || '—')}</span></span>
          <span class="n num">${num(a.score)}</span>
          <span class="act">${banned ? BANNED : `<button class="btn small" type="button" data-action="ban" data-ip="${esc(a.ip)}">Ban</button>`}</span>
          <span class="bar scorebar"><span style="width:${(100 * a.score / top).toFixed(1)}%"></span>${tick}</span></li>`;
      }).join('') : emptyBlock('No IP has a threat score yet.');
    } else blockError($('#attackers'), 'attackers', att.reason);
  }

  // ── credentials ─────────────────────────────────────────────────────────
  async function loadCredentials() {
    const [bd, pairs, series] = await Promise.allSettled([api(`/api/credentials/breakdown?range=${state.range}`), api('/api/credentials?limit=200'), api(`/api/series?range=${state.range}`)]);
    if (series.status === 'fulfilled') {
      const { buckets, range } = series.value, labels = bucketLabels(buckets, range.bucket);
      $('#cred-chart-title').textContent = `Logins tried per ${range.bucket}`;
      const xAt = range.bucket === 'hour' && range.name === '7d' ? buckets.map((x, i) => (new Date(x.bucket).getHours() === 0 ? i : -1)).filter((i) => i >= 0) : null;
      Charts.bars($('#cred-chart'), { labels, values: buckets.map((x) => x.credentials), height: 150, xAt });
    } else blockError($('#cred-chart'), 'the chart', series.reason);
    if (bd.status === 'fulfilled') {
      const b = bd.value, total = b.services.reduce((a, x) => a + x.count, 0);
      $('#cred-sub').textContent = `${num(total)} logins tried in the last ${RANGE_WORDS[state.range]}. MySQL sends only a hash, so only its usernames are known.`;
      rankInto($('#top-users'), b.usernames.slice(0, 8).map((x) => ({ label: x.key, value: x.count, mono: true })), 'No logins in this range.');
      rankInto($('#top-passwords'), b.passwords.slice(0, 8).map((x) => ({ label: x.key, value: x.count, mono: true })), 'No passwords in this range.');
      rankInto($('#cred-services'), b.services.map((x) => ({ label: svcName(x.key), value: x.count })), 'No logins in this range.');
    } else ['#top-users', '#top-passwords', '#cred-services'].forEach((s) => blockError($(s), 'credentials', bd.reason));
    if (pairs.status === 'fulfilled') {
      const p = pairs.value;
      $('#pairs').innerHTML = p.length ? p.map((c) => `<tr><td>${esc(svcName(c.service))}</td><td class="mono">${esc(c.username || '—')}</td>
        <td class="mono">${esc(c.password || (c.service === 'mysql' ? 'hash only' : '—'))}</td><td class="n">${num(c.count)}</td><td class="n" title="${esc(stamp(c.last_seen))}">${esc(ago(c.last_seen))}</td></tr>`).join('')
        : emptyRow(5, 'No credentials captured yet.');
    } else blockError($('#pairs'), 'credential pairs', pairs.reason);
  }

  // ── services ────────────────────────────────────────────────────────────
  async function loadServices() {
    let list;
    try { list = await api('/api/services'); } catch (e) { blockError($('#honeypots'), 'services', e); return; }
    const hp = list.filter((s) => s.kind === 'honeypot'), managed = list.filter((s) => s.kind !== 'honeypot');
    const on = hp.filter((s) => s.running).length;
    $('#svc-sub').textContent = `${on} of ${hp.length} honeypots are listening. A switch applies at once and survives restarts.`;
    $('#honeypots').innerHTML = hp.length ? hp.map(svcRow).join('') : '<div class="empty">No honeypots are configured. Add them under honeypot_services in the config file.</div>';
    $('#managed').innerHTML = managed.length ? managed.map(svcRow).join('') : '<div class="empty">No stealth or passthrough services are configured.</div>';
  }
  function svcStatus(s) {
    if (s.error) return '<span class="pill neg"><span class="dot"></span>Failed to start</span>';
    if (s.running) return '<span class="pill pos"><span class="dot"></span>Listening</span>';
    return '<span class="pill">Off</span>';
  }
  function svcRow(s) {
    const what = s.kind === 'honeypot' ? `${svcName(s.type)} on port <span class="num">${s.port}</span>`
      : s.kind === 'stealth' ? `Stealth port <span class="num">${s.port}</span>, forwards real clients`
      : `Port <span class="num">${s.port}</span> → <span class="mono">${esc(s.target)}</span>`;
    const control = s.toggleable
      ? `<input class="switch" type="checkbox" role="switch" data-action="toggle-service" data-name="${esc(s.name)}" ${s.enabled ? 'checked' : ''} aria-label="${esc(s.name)} honeypot">`
      : '<span class="lock" title="Managed in the config file"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="1.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg></span>';
    const figs = s.kind === 'honeypot'
      ? `<span class="fig"><span class="num">${num(s.hits_24h)}</span><span class="lbl">events</span></span><span class="fig"><span class="num">${s.type === 'http' || s.type === 'mysql' || s.type === 'ssh' || s.type === 'ftp' ? num(s.credentials_24h) : '—'}</span><span class="lbl">logins</span></span>`
      : `<span class="fig"><span class="num">${num(s.hits_24h)}</span><span class="lbl">events</span></span><span class="fig"><span class="num">${num(s.active_connections)}</span><span class="lbl">open now</span></span>`;
    const hourly = s.hourly || [], hmax = Math.max(1, ...hourly);
    // 24 hourly columns, oldest first; the hour in progress in the hue
    const bw = 100 / Math.max(1, hourly.length);
    const strip = hourly.length ? `<svg class="svc-bar" viewBox="0 0 100 28" preserveAspectRatio="none" role="img" aria-label="${esc(s.name)}: ${num(s.hits_24h)} connections in the last 24 hours, busiest hour ${num(Math.max(0, ...hourly))}">${hourly.map((v, i) => { const h = v ? Math.max(3, 28 * v / hmax) : 1; return `<rect x="${(i * bw + bw * 0.12).toFixed(2)}" y="${(28 - h).toFixed(2)}" width="${(bw * 0.76).toFixed(2)}" height="${h.toFixed(2)}" fill="${i === hourly.length - 1 ? 'var(--accent)' : 'var(--chart-muted)'}"><title>${num(v)} connections</title></rect>`; }).join('')}</svg>` : '<div></div>';
    return `<div class="svc">${control}
      <div><h3>${esc(s.name)} ${svcStatus(s)}</h3><div class="what">${what}</div></div>
      ${strip}
      <div class="figs">${figs}</div>
      ${s.error ? `<div class="err">${esc(s.error)}</div>` : ''}</div>`;
  }
  async function toggleService(input) {
    const name = input.dataset.name, on = input.checked;
    input.disabled = true;
    try {
      const s = await post('/api/services', { name, enabled: on ? '1' : '0' });
      toast(on ? `${name} is listening on port ${s.port}` : `${name} is switched off`);
    } catch (e) {
      input.checked = !on;
      toast(`${name}: ${e.message}`, false);
    }
    input.disabled = false;
    loadServices();
  }

  // ── settings ────────────────────────────────────────────────────────────
  async function loadSettings() {
    loadEngineSwitches();
    const [s, fw] = await Promise.allSettled([api('/api/settings'), api('/api/firewall')]);
    if (s.status === 'fulfilled') {
      const v = s.value;
      $('#set-enabled').checked = !!v.auto_ban_enabled;
      $('#set-state').textContent = v.auto_ban_enabled ? 'On: IPs over the threshold are banned' : 'Off: scores are kept, nobody is banned';
      $('#set-threshold').value = v.score_threshold;
      setDuration(v.ban_duration);
    }
    if (fw.status === 'fulfilled') {
      $('#fw-method').textContent = fw.value.method;
      $('#fw-rules').textContent = (fw.value.rules || []).join('\n') || '(no rules)';
    } else $('#fw-rules').textContent = `Couldn't load the rules: ${fw.reason.message}`;
  }
  function setDuration(value) {
    const group = $('[data-duration-group]');
    let found = false;
    $$('button', group).forEach((b) => { const on = b.dataset.duration === value; b.setAttribute('aria-pressed', on); found = found || on; });
    $$('button[data-custom]', group).forEach((b) => b.remove());
    if (!found && value) { // a value set in the config file that has no preset keeps its own button
      const b = document.createElement('button');
      Object.assign(b, { type: 'button', textContent: value });
      b.dataset.duration = value; b.dataset.custom = '1'; b.setAttribute('aria-pressed', 'true');
      group.appendChild(b);
    }
    $('#set-duration').value = value || '';
  }
  async function saveSettings(form) {
    const msg = $('#set-msg'), btn = $('#set-submit');
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      await post('/api/settings', {
        auto_ban_enabled: $('#set-enabled').checked ? '1' : '0',
        score_threshold: form.elements.score_threshold.value.trim(),
        ban_duration: $('#set-duration').value,
      });
      msg.textContent = `Saved at ${clock(new Date())}`;
      toast('Auto-ban settings saved');
      loadSettings();
    } catch (e) { msg.textContent = e.message; toast(`Not saved: ${e.message}`, false); }
    btn.disabled = false; btn.textContent = 'Save changes';
  }

  // ── dialogs ─────────────────────────────────────────────────────────────
  function openBan(ip = '') {
    const d = $('#ban-dialog'), f = $('#ban-form');
    f.reset(); $('#ban-error').textContent = '';
    f.elements.ip.value = ip;
    pressOnly($('[data-ban-duration]'), '1d');
    d.showModal();
    (ip ? f.elements.reason : f.elements.ip).focus();
  }
  async function submitBan(f) {
    const dur = $('[data-ban-duration] [aria-pressed="true"]').dataset.duration;
    const data = { ip: f.elements.ip.value.trim(), duration: dur, reason: f.elements.reason.value.trim() };
    if (dur === '0') data.permanent = '1';
    const btn = $('#ban-submit'); btn.disabled = true; btn.textContent = 'Banning…';
    try {
      await post('/api/ban', data);
      $('#ban-dialog').close();
      toast(`${data.ip} is banned ${dur === '0' ? 'permanently' : `for ${$('[data-ban-duration] [aria-pressed="true"]').textContent}`}`);
      refresh();
    } catch (e) { $('#ban-error').textContent = e.message; f.elements.ip.focus(); }
    btn.disabled = false; btn.textContent = 'Ban';
  }
  function confirmAction(title, text, okLabel) {
    const d = $('#confirm-dialog');
    $('#confirm-title').textContent = title; $('#confirm-text').textContent = text; $('#confirm-ok').textContent = okLabel;
    d.returnValue = '';
    d.showModal();
    return new Promise((res) => d.addEventListener('close', () => res(d.returnValue === 'ok'), { once: true }));
  }
  async function unban(ip) {
    if (!await confirmAction(`Unban ${ip}?`, 'The firewall rule is removed and its threat score starts again from zero.', 'Unban')) return;
    try { await post('/api/unban', { ip }); toast(`${ip} is unbanned`); refresh(); if ($('#ip-sheet').open) openIP(ip); }
    catch (e) { toast(`Unban failed: ${e.message}`, false); }
  }

  async function openIP(ip) {
    const sheet = $('#ip-sheet');
    $('#ip-title').textContent = ip;
    $('#ip-tags').innerHTML = ''; $('#ip-actions').innerHTML = '';
    $('#ip-facts').innerHTML = ['Score', 'Events', 'Honeypot hits', 'Logins'].map((k) => `<div><dt>${k}</dt><dd><span class="skeleton">000</span></dd></div>`).join('');
    $('#ip-creds').innerHTML = skeletonRows(4, 2); $('#ip-conns').innerHTML = skeletonRows(5, 3); $('#ip-chart').innerHTML = '';
    if (!sheet.open) sheet.showModal();
    try {
      const [d, series] = await Promise.all([api('/api/ip?ip=' + encodeURIComponent(ip)), api(`/api/series?range=30d&ip=${encodeURIComponent(ip)}`)]);
      const s = d.score || {};
      $('#ip-tags').innerHTML = (d.banned ? BANNED + ' ' : '') + (d.whitelisted ? '<span class="pill pos">Whitelisted</span>' : '') + (s.country ? ` <span class="pill">${esc(s.country)}</span>` : '');
      $('#ip-facts').innerHTML = [['Score', s.score], ['Events', s.total_connections], ['Honeypot hits', s.honeypot_hits], ['Logins', s.credential_attempts]]
        .map(([k, v]) => `<div><dt>${k}</dt><dd>${v == null ? '—' : num(v)}</dd></div>`).join('');
      $('#ip-actions').innerHTML = (d.banned ? `<button class="btn" type="button" data-action="unban" data-ip="${esc(ip)}">Unban</button>`
        : d.whitelisted ? '<span class="muted">Whitelisted addresses are never banned.</span>' : `<button class="btn primary" type="button" data-action="ban" data-ip="${esc(ip)}">Ban this IP</button>`)
        + `<button class="card-link" type="button" data-action="search-ip" data-ip="${esc(ip)}">All its connections</button>`
        + (s.first_seen ? `<span class="stamp">First seen ${esc(stamp(s.first_seen))}</span>` : '');
      const b = series.buckets;
      Charts.bars($('#ip-chart'), { labels: b.map((x) => dateShort(new Date(x.bucket))), values: b.map((x) => x.total), height: 120 });
      $('#ip-creds').innerHTML = d.credentials.length ? d.credentials.slice(0, 20).map((c) => `<tr><td class="num">${esc(stamp(c.timestamp))}</td><td>${esc(svcName(c.service))}</td><td class="mono">${esc(c.username || '—')}</td><td class="mono">${esc(c.password || '—')}</td></tr>`).join('') : emptyRow(4, 'No credentials from this IP.');
      $('#ip-conns').innerHTML = d.connections.length ? d.connections.slice(0, 25).map((c) => `<tr><td class="num">${esc(stamp(c.timestamp))}</td><td>${esc(svcName(c.service_type))}</td><td class="n">${c.dest_port}</td><td class="data" title="${esc(c.data)}">${esc(c.data || '—')}</td><td class="n">${outcomePill(c.action)}</td></tr>`).join('') : emptyRow(5, 'No connections from this IP.');
    } catch (e) { blockError($('#ip-facts'), ip, e); }
  }

  // ── containers ──────────────────────────────────────────────────────────
  // The patch bay: containers down the left, networks across the top. A cable hangs from a container's
  // socket to every network it is on; clicking a socket lifts a free cable that follows the pointer
  // until it is dropped on another container (they get a network in common) or on a network.
  const ct = { engine: '', data: null, patch: null, sheet: null, cur: null, hl: '', view: 'map', only: 'all', query: '', topos: {}, cabling: false, expanded: new Set(), stacks: new Map() };
  const ENGINE_NAMES = { docker: 'Docker', incus: 'Incus' };
  const RESTART_LABELS = { no: 'Stay stopped', 'on-failure': 'On failure', 'unless-stopped': 'Unless stopped by hand', always: 'Always', 'last-state': 'As before shutdown' };
  const STATE_TONE = { running: 'pos', paused: 'warn', restarting: 'warn', frozen: 'warn', dead: 'neg', error: 'neg' };
  const hostPart = (ip) => (ip ? (ip.includes(':') ? `[${ip}]` : ip) + ':' : '');
  const portLabel = (p) => `${hostPart(p.host_ip)}${p.host_port || 'any'}→${p.container_port}${p.proto === 'udp' ? '/udp' : ''}`;
  const engineName = (e) => ENGINE_NAMES[e] || e;
  const ctView = () => {
    const d = ct.data;
    return {
      eng: d.engines.find((e) => e.name === ct.engine),
      cs: d.containers.filter((c) => c.engine === ct.engine),
      ns: d.networks.filter((n) => n.engine === ct.engine),
    };
  };
  const findCt = (id, engine = ct.engine) => ct.data.containers.find((c) => c.engine === engine && c.id === id);
  const ctPost = (path, data) => post(`/api/containers/${path}`, Object.assign({ engine: ct.engine }, data));
  const ICON_PLAY = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5.5v13l11-6.5z"/></svg>';
  const ICON_STOP = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6.5" y="6.5" width="11" height="11" rx="1.5"/></svg>';

  async function loadContainers() {
    let d;
    try { d = await api('/api/containers'); } catch (e) {
      [['#bay', 'containers'], ['#host-ports', 'host ports'], ['#ct-networks', 'networks'], ['#open-ports', 'open ports']].forEach(([sel, what]) => blockError($(sel), what, e));
      $('#ct-sub').textContent = "Couldn't reach SkyGuard's container API.";
      return;
    }
    ct.data = d;
    $$('#screen-containers .grid, .map-tools, #ct-new').forEach((el) => { el.hidden = !d.enabled; });
    if (!d.enabled) {
      $('#ct-sub').textContent = 'Container management is off. Turn an engine on to see and wire the containers on this server.';
      $('#topo').hidden = true; $('#bay-wrap').hidden = false;
      $('#bay').innerHTML = `<div class="empty off-note"><div>
        <p>SkyGuard talks to the engine over its socket. Either socket is equivalent to root on this server, so this needs a strong dashboard password; with docker compose, mount the socket into SkyGuard's container first.</p>
        <div class="form-actions">${(d.engines || []).map((e) => `<button class="btn${e.name === 'docker' ? ' primary' : ''}" type="button" data-action="engine-on" data-engine="${esc(e.name)}">Manage ${esc(engineName(e.name))}</button><span class="stamp mono">${esc(e.socket || '')}</span>`).join('')}</div>
        </div></div>`;
      $('#ct-engines').hidden = true;
      return;
    }
    const on = d.engines.filter((e) => e.enabled);
    if (!on.some((e) => e.name === ct.engine)) ct.engine = (on.find((e) => e.available) || on[0]).name;
    renderEngines(); renderBay(); renderMap(); applyCtView(); renderHostPorts(); renderCtNetworks(); renderExposure(); renderCtFinding();
    $$('[data-stamp]').forEach((el) => { el.textContent = `Updated ${clock(new Date())}`; });
    if ($('#ct-sheet').open && ct.sheet) refreshSheet();
  }

  function renderEngines() {
    const g = $('#ct-engines'), list = ct.data.engines.filter((e) => e.enabled);
    g.hidden = list.length < 2;
    g.innerHTML = list.map((e) => `<button type="button" data-engine="${esc(e.name)}" aria-pressed="${e.name === ct.engine}">${esc(engineName(e.name))}</button>`).join('');
  }

  function renderCtFinding() {
    const { eng, cs, ns } = ctView(), sub = $('#ct-sub');
    const ports = ct.data.host_ports.filter((u) => u.conflict);
    const lost = ports.find((u) => u.owners.some((o) => o.kind === 'skyguard' && o.failed));
    if (lost) {
      const hp = lost.owners.find((o) => o.kind === 'skyguard'), holder = lost.owners.find((o) => o.kind !== 'skyguard');
      sub.innerHTML = `SkyGuard's <strong>${esc(hp.name)}</strong> could not start: port <span class="num">${lost.port}</span> is held by ${holder ? `${engineName(holder.kind)} container <strong>${esc(holder.name)}</strong>` : 'another program'}. Move the honeypot to a free port in the config file, or <a class="card-link" href="#services">switch it off</a>.`;
      return;
    }
    if (ports.length) {
      const u = ports[0];
      sub.innerHTML = `Port <span class="num">${u.port}</span> is claimed by ${u.owners.map((o) => `<strong>${esc(o.name)}</strong>`).join(' and ')}: only one of them can have it.`;
      return;
    }
    if (!eng.available) { sub.textContent = `${engineName(eng.name)} is not reachable: ${eng.error}`; return; }
    const running = cs.filter((c) => c.running), stopped = cs.filter((c) => !c.running);
    const stop = stopped.length ? ` ${num(stopped.length)} stopped: ${stopped.slice(0, 3).map((c) => `<strong>${esc(c.name)}</strong>`).join(', ')}${stopped.length > 3 ? ' and more' : ''}.` : ' Nothing is stopped.';
    sub.innerHTML = `${num(running.length)} of ${num(cs.length)} ${engineName(eng.name)} ${cs.length === 1 ? 'container is' : 'containers are'} running on ${num(ns.length)} ${ns.length === 1 ? 'network' : 'networks'}.${stop}${ct.data.read_only ? ' Changes are switched off in the config file.' : ''}`;
  }

  // what the search and the running-only switch leave on screen
  function ctMatches(c) {
    if (ct.only === 'running' && !c.running) return false;
    const q = ct.query.toLowerCase();
    if (!q) return true;
    return [c.name, c.image, c.project, ...c.ports.map(portLabel), ...c.ports.map((p) => String(p.host_port)), ...c.networks.map((e) => `${e.network} ${e.ip || ''}`)]
      .some((v) => String(v || '').toLowerCase().includes(q));
  }
  function renderBay() {
    const v = ctView(), { eng, ns } = v, cs = v.cs.filter(ctMatches), bay = $('#bay');
    $('#bay-help').textContent = '';
    if (!ns.some((n) => n.name === ct.hl)) ct.hl = '';
    if (ct.hl) bay.dataset.hl = ct.hl; else bay.removeAttribute('data-hl');
    if (!eng.available) { bay.innerHTML = `<div class="block-error">${esc(engineName(eng.name))} is not reachable: ${esc(eng.error)}</div>`; return; }
    if (!cs.length) { bay.innerHTML = `<div class="empty">${v.cs.length ? 'No container matches.' : `No ${esc(engineName(eng.name))} containers on this server yet.`}</div>`; return; }
    const ro = ct.data.read_only;
    $('#topo-hint').textContent = ro ? 'Read-only: changes are switched off in the config file. Drag to move, scroll to zoom, double-click to open.' : 'Select a container, then pull a cable from its plug onto another container or a switch. Drag to move, scroll to zoom, double-click to open.';
    const bad = new Set(ct.data.host_ports.filter((u) => u.conflict).map((u) => `${u.port}/${u.proto}`));
    bay.style.setProperty('--cols', String(Math.max(1, ns.length)));
    const head = `<div class="bay-head"><div class="bay-corner"><span>Container</span><span class="muted num">${num(cs.filter((c) => c.running).length)}/${num(cs.length)} running</span></div>${ns.map((n) => `
      <button class="net-head${ct.hl === n.name ? ' lit' : ''}" type="button" data-action="net-pick" data-net="${esc(n.name)}" aria-pressed="${ct.hl === n.name}" title="${esc(n.name)}${n.subnet ? ' · ' + esc(n.subnet) : ''}${n.attachable ? '' : ' (cannot be joined from here)'}">
        <b class="mono" translate="no">${esc(n.name)}</b><span>${esc(n.builtin ? 'default bridge' : n.driver)}${n.subnet ? ` · ${esc(n.subnet)}` : ''}</span></button>`).join('')}</div>`;
    const rows = cs.map((c) => {
      const member = new Map(c.networks.map((e) => [e.network, e]));
      const locked = !!c.network_mode;
      const chips = c.ports.map((p) => `<span class="chip mono${bad.has(`${p.host_port}/${p.proto}`) ? ' bad' : ''}" title="Host ${esc(hostPart(p.host_ip) + (p.host_port || 'any'))} → container ${p.container_port}/${esc(p.proto)}">${esc(portLabel(p))}</span>`).join('');
      const toggle = ro || c.self ? '' : c.running
        ? `<button class="icon-btn small" type="button" data-action="ct-stop" data-id="${esc(c.id)}" aria-label="Stop ${esc(c.name)}" title="Stop">${ICON_STOP}</button>`
        : `<button class="icon-btn small" type="button" data-action="ct-start" data-id="${esc(c.id)}" aria-label="Start ${esc(c.name)}" title="Start">${ICON_PLAY}</button>`;
      const socket = locked || ro
        ? `<span class="socket off" title="${esc(locked ? `Network mode ${c.network_mode}: no networks to join` : 'Read-only')}"></span>`
        : `<button class="socket" type="button" data-action="patch" data-id="${esc(c.id)}" aria-label="Connect ${esc(c.name)} to another container or a network" title="Connect"></button>`;
      const jacks = locked
        ? `<div class="mode-note">${c.network_mode === 'host' ? "Uses the host's network directly: its ports are the host's own" : `Network mode ${esc(c.network_mode)}`}</div>`
        : ns.map((n) => {
          const ep = member.get(n.name), can = !ro && n.attachable;
          const label = `${c.name} ${ep ? `is on ${n.name}${ep.ip ? ' at ' + ep.ip : ''}` : `is not on ${n.name}`}`;
          return `<div class="jack-cell${ct.hl === n.name ? ' lit' : ''}" data-net="${esc(n.name)}">${ep && ep.ip ? `<span class="jack-ip mono">${esc(ep.ip.replace(/\/\d+$/, ''))}</span>` : ''}${ep || can
            ? `<button class="jack${ep ? ' on' : ''}" type="button" data-action="jack" data-id="${esc(c.id)}" data-net="${esc(n.name)}" aria-pressed="${!!ep}" aria-label="${esc(label)}" title="${esc(label)}"${can ? '' : ' disabled'}></button>` : ''}</div>`;
        }).join('');
      return `<div class="bay-row${c.running ? '' : ' stopped'}" data-row="${esc(c.id)}">
        <div class="ct-cell" data-target="${esc(c.id)}">
          <div class="ct-main">
            <div class="ct-line"><span class="state-dot ${STATE_TONE[c.state] || ''}" title="${esc(c.state)}"></span><button class="ct-name" type="button" data-action="ct-open" data-id="${esc(c.id)}" translate="no">${esc(c.name)}</button>${c.self ? '<span class="pill">SkyGuard</span>' : ''}${c.project ? `<span class="muted tag" title="Docker Compose project">${esc(c.project)}</span>` : ''}</div>
            <div class="ct-sub"><span class="mono" translate="no">${esc(c.image || '—')}</span><span>${esc(c.status)}</span></div>
            ${chips ? `<div class="ct-ports">${chips}</div>` : ''}
          </div>
          <div class="ct-tools">${toggle}${socket}</div>
        </div>${jacks}</div>`;
    }).join('');
    bay.innerHTML = head + rows + '<svg class="cables" aria-hidden="true"></svg>';
    requestAnimationFrame(drawCables);
  }

  // A cable sags under its own weight: the longer the span, the deeper the curve.
  const sag = (x0, y0, x1, y1, extra = 0) => {
    const dx = x1 - x0, s = Math.min(22, Math.abs(dx) * 0.05 + 6) + extra, f = (n) => n.toFixed(1);
    return `M${f(x0)} ${f(y0)} C${f(x0 + dx * 0.32)} ${f(y0 + s)} ${f(x1 - dx * 0.32)} ${f(y1 + s)} ${f(x1)} ${f(y1)}`;
  };
  const centre = (el, box) => { const r = el.getBoundingClientRect(); return [r.left - box.left + r.width / 2, r.top - box.top + r.height / 2]; };

  function drawCables() {
    const bay = $('#bay'), svg = $('svg.cables', bay);
    if (!svg) return;
    const box = bay.getBoundingClientRect(), w = bay.scrollWidth, h = bay.scrollHeight;
    svg.setAttribute('width', w); svg.setAttribute('height', h); svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
    let out = '';
    $$('.bay-row', bay).forEach((row) => {
      const sock = $('.socket', row);
      if (!sock) return;
      const [x0, y0] = centre(sock, box);
      $$('.jack.on', row).forEach((j) => {
        const [x1, y1] = centre(j, box);
        out += `<path class="cable${ct.hl === j.dataset.net ? ' on-hl' : ''}" data-net="${esc(j.dataset.net)}" d="${sag(x0, y0, x1, y1)}"/>`;
      });
    });
    if (ct.patch) out += '<path class="cable live" id="live-cable" d=""/><circle class="plug" id="live-plug" r="5" cx="-20" cy="-20"/>';
    svg.innerHTML = out;
    if (ct.patch && ct.patch.last) movePatch(ct.patch.last);
  }

  function startPatch(id) {
    const c = findCt(id);
    ct.patch = { id, target: null };
    const bay = $('#bay');
    bay.classList.add('patching');
    $(`.bay-row[data-row="${CSS.escape(id)}"]`, bay).classList.add('source');
    $('#bay-help').textContent = `Connecting ${c.name}: click another container to give the two a network in common, or a network for ${c.name} to join. Esc cancels.`;
    drawCables();
    const sock = $(`.bay-row[data-row="${CSS.escape(id)}"] .socket`, bay), r = sock.getBoundingClientRect();
    movePatch({ clientX: r.right + 60, clientY: r.top + r.height / 2, target: sock });
  }
  function endPatch() {
    ct.patch = null;
    const bay = $('#bay');
    bay.classList.remove('patching');
    $$('.bay-row.source, .bay-row.hot, .jack-cell.hot, .net-head.hot', bay).forEach((el) => el.classList.remove('source', 'hot'));
    $('#bay-help').textContent = '';
    drawCables();
  }
  // What the free end of the cable would plug into at this point: another container, or a network column.
  function patchTarget(el) {
    const cell = el && el.closest && el.closest('[data-target], .net-head, .jack-cell');
    if (!cell || !ct.patch) return null;
    if (cell.dataset.target) return cell.dataset.target === ct.patch.id ? null : { kind: 'ct', id: cell.dataset.target };
    const src = findCt(ct.patch.id);
    if (!cell.dataset.net || src.networks.some((e) => e.network === cell.dataset.net)) return null;
    const n = ctView().ns.find((x) => x.name === cell.dataset.net);
    return n && n.attachable ? { kind: 'net', net: n.name } : null;
  }
  function movePatch(ev) {
    if (!ct.patch) return;
    ct.patch.last = { clientX: ev.clientX, clientY: ev.clientY, target: ev.target };
    const bay = $('#bay'), box = bay.getBoundingClientRect();
    const src = $(`.bay-row[data-row="${CSS.escape(ct.patch.id)}"] .socket`, bay), cable = $('#live-cable'), plug = $('#live-plug');
    if (!src || !cable) return;
    const [x0, y0] = centre(src, box);
    let x1 = ev.clientX - box.left, y1 = ev.clientY - box.top;
    $$('.bay-row.hot, .jack-cell.hot, .net-head.hot', bay).forEach((el) => el.classList.remove('hot'));
    const t = patchTarget(ev.target);
    ct.patch.target = t;
    if (t && t.kind === 'ct') {
      const row = $(`.bay-row[data-row="${CSS.escape(t.id)}"]`, bay);
      row.classList.add('hot');
      const s = $('.socket', row);
      if (s) [x1, y1] = centre(s, box);
    } else if (t && t.kind === 'net') {
      const j = $(`.bay-row[data-row="${CSS.escape(ct.patch.id)}"] .jack-cell[data-net="${CSS.escape(t.net)}"]`, bay);
      $$(`[data-net="${CSS.escape(t.net)}"]`, bay).forEach((el) => { if (el.matches('.jack-cell, .net-head')) el.classList.add('hot'); });
      const jack = j && $('.jack', j);
      if (jack) [x1, y1] = centre(jack, box);
    }
    // socket to socket runs down the same column: the cable loops out to the right instead of lying flat
    const loop = t && t.kind === 'ct', b = Math.min(90, 34 + Math.abs(y1 - y0) * 0.18), f = (n) => n.toFixed(1);
    cable.setAttribute('d', loop ? `M${f(x0)} ${f(y0)} C${f(x0 + b)} ${f(y0)} ${f(x1 + b)} ${f(y1)} ${f(x1)} ${f(y1)}` : sag(x0, y0, x1, y1, t ? 4 : 14));
    plug.setAttribute('cx', x1.toFixed(1)); plug.setAttribute('cy', y1.toFixed(1));
    cable.classList.toggle('snapped', !!t);
  }
  function dropPatch(el) {
    const t = patchTarget(el), from = ct.patch && ct.patch.id;
    endPatch();
    if (!t) return;
    if (t.kind === 'net') connectTo(from, t.net);
    else openConnect(from, t.id);
  }

  // ── the network map ─────────────────────────────────────────────────────
  function topoFor(engine) {
    if (ct.topos[engine]) return ct.topos[engine];
    const stage = document.createElement('div');
    stage.className = 'topo-stage'; stage.dataset.engine = engine;
    $('#topo').prepend(stage);
    const t = Topology.create(stage, {
      storageKey: `skyguard.map.${engine}`,
      onSelect: (n) => renderCard(n),
      onOpen: (n) => { if (n.kind === 'ct') openCt(n.ref); },
      onConnect: (a, b) => { if (b.kind === 'net') connectTo(a.ref, b.ref); else openConnect(a.ref, b.ref); },
      onEdge: (e) => { if (e.net) disconnectFrom(e.ct, e.net); },
      onCableStart: (n) => { ct.cabling = true; $('#bay-help').textContent = `Pulling a cable from ${n.label}: drop it on another container to give the two a network in common, or on a switch to join that network. Esc cancels.`; },
      onCableHover: (a, b) => { if (b) $('#bay-help').textContent = b.kind === 'net' ? `Release to plug ${a.label} into ${b.label}.` : `Release to connect ${a.label} with ${b.label}.`; },
      onCableEnd: () => { ct.cabling = false; $('#bay-help').textContent = ''; },
    });
    ct.topos[engine] = t;
    return t;
  }
  function renderMap() {
    const v = ctView(), cs = v.cs.filter((c) => ct.only === 'all' || c.running);
    const t = topoFor(ct.engine);
    $$('#topo .topo-stage').forEach((el) => { el.hidden = el.dataset.engine !== ct.engine; });
    const nodes = [], edges = [], shown = new Set(cs.map((c) => c.id));
    v.ns.forEach((n) => nodes.push({ id: 'net:' + n.name, ref: n.name, kind: 'net', label: n.name, sub: n.builtin ? 'default bridge' : (n.subnet || n.driver), locked: !n.attachable,
      title: `${n.name} · ${n.driver}${n.subnet ? ' · ' + n.subnet : ''} · ${n.members.filter((m) => shown.has(m)).length} connected` }));
    // Replicas (the same image, project and networks under a numbered name: queue-worker-1…40) fold
    // into one stacked device until it is opened, so forty workers read as one thing on the map.
    const base = (name) => name.replace(/[-_.]?\d+$/, '');
    const sigOf = (c) => [c.project, base(c.name), c.image, c.network_mode, c.networks.map((e) => e.network).sort().join(',')].join('|');
    const bySig = new Map();
    cs.forEach((c) => { if (base(c.name) !== c.name) { const k = sigOf(c); if (!bySig.has(k)) bySig.set(k, []); bySig.get(k).push(c); } });
    const stacked = new Set();
    ct.stacks = new Map();
    bySig.forEach((list, k) => {
      if (list.length < 4 || ct.expanded.has(k)) return;
      const c0 = list[0], up = list.filter((c) => c.running).length, id = 'stack:' + k;
      list.forEach((c) => stacked.add(c.id));
      ct.stacks.set(id, { key: k, list });
      nodes.push({ id, ref: k, kind: 'ct', stack: list.length, label: `${base(c0.name)}-*`, sub: `${up}/${list.length} running`, state: up ? 'running' : 'exited',
        group: c0.project, engine: c0.engine, locked: true, search: list.map((c) => c.name).join(' ') + ' ' + c0.image,
        title: `${list.length} × ${base(c0.name)} (${c0.image}): ${up} running. Click to see them, then Expand to place each one.` });
      c0.networks.forEach((e) => edges.push({ id: `${id}|${e.network}`, from: id, to: 'net:' + e.network, dead: !up, label: `${list.length} containers on ${e.network}` }));
    });
    let host = false;
    cs.forEach((c) => {
      if (stacked.has(c.id)) return;
      nodes.push({ id: 'ct:' + c.id, ref: c.id, kind: 'ct', label: c.name, sub: c.image ? c.image.replace(/^.*\//, '') : '', state: c.state, group: c.project, engine: c.engine,
        vm: c.kind === 'virtual-machine', self: c.self, locked: !!c.network_mode || ct.data.read_only,
        search: [c.image, c.project, ...c.ports.map(portLabel), ...c.networks.map((e) => `${e.network} ${e.ip || ''}`)].join(' '),
        title: `${c.name} · ${c.status}${c.ports.length ? ' · ' + c.ports.map(portLabel).join(', ') : ''}` });
      c.networks.forEach((e) => edges.push({ id: `${c.id}|${e.network}`, from: 'ct:' + c.id, to: 'net:' + e.network, ct: c.id, net: e.network, dead: !c.running,
        label: `${c.name} on ${e.network}${e.ip ? ' at ' + e.ip.replace(/\/\d+$/, '') : ''}. Click to disconnect.` }));
      if (c.network_mode === 'host') { host = true; edges.push({ id: `${c.id}|host`, from: 'ct:' + c.id, to: 'host', dead: !c.running, label: `${c.name} uses the host's network` }); }
    });
    if (host) nodes.push({ id: 'host', kind: 'host', label: (state.info && state.info.host) || 'This server', sub: 'host network', locked: true });
    t.setData({ nodes, edges, readOnly: ct.data.read_only });
    if (ct.query) t.search(ct.query);
    const sel = t.selected;
    renderCard(sel ? nodes.find((n) => n.id === sel) : null);
  }
  function applyCtView() {
    const map = ct.view === 'map';
    $('#topo').hidden = !map; $('#bay-wrap').hidden = map;
    $$('[data-ctview]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.ctview === ct.view)));
    $$('[data-ctfilter]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.ctfilter === ct.only)));
    $('#map-title').textContent = map ? 'Network map' : 'Patch bay';
    if (!map) requestAnimationFrame(drawCables);
  }
  // the inspector beside the map: what is selected, and what to do with it
  function renderCard(n) {
    const card = $('#topo-card');
    if (!n) { card.hidden = true; $('#topo-hint').hidden = false; return; }
    card.hidden = false; $('#topo-hint').hidden = true;
    const ro = ct.data.read_only;
    if (n.kind === 'ct' && n.stack) {
      const st = ct.stacks.get(n.id);
      if (!st) { card.hidden = true; return; }
      const up = st.list.filter((c) => c.running).length;
      card.innerHTML = `<div class="card-head"><span class="state-dot ${up ? 'pos' : ''}"></span><b translate="no">${esc(n.label)}</b><span class="muted">${num(st.list.length)} replicas</span></div>
        <div class="muted mono card-image" translate="no">${esc(st.list[0].image)}</div>
        <div class="muted">${num(up)} of ${num(st.list.length)} running · on ${esc(st.list[0].networks.map((e) => e.network).join(', ') || 'no network')}</div>
        <ul class="card-nets">${st.list.slice(0, 8).map((c) => `<li><button class="ip-link" type="button" data-action="ct-open" data-id="${esc(c.id)}" translate="no">${esc(c.name)}</button><span class="state-dot ${STATE_TONE[c.state] || ''}"></span></li>`).join('')}${st.list.length > 8 ? `<li class="muted">and ${num(st.list.length - 8)} more</li>` : ''}</ul>
        <div class="card-actions"><button class="btn small primary" type="button" data-action="stack-expand" data-key="${esc(st.key)}">Expand on the map</button></div>`;
      return;
    }
    if (n.kind === 'ct') {
      const c = findCt(n.ref);
      if (!c) { card.hidden = true; return; }
      const nets = c.networks.map((e) => `<li><span class="mono" translate="no">${esc(e.network)}</span><span class="num muted">${esc((e.ip || '').replace(/\/\d+$/, ''))}</span></li>`).join('');
      card.innerHTML = `<div class="card-head"><span class="state-dot ${STATE_TONE[c.state] || ''}"></span><b translate="no">${esc(c.name)}</b>${c.project ? `<span class="muted">${esc(c.project)}</span>` : ''}</div>
        <div class="muted mono card-image" translate="no">${esc(c.image || '—')}</div>
        <div class="muted">${esc(c.status)}</div>
        ${c.ports.length ? `<div class="ct-ports">${c.ports.map((p) => `<span class="chip mono">${esc(portLabel(p))}</span>`).join('')}</div>` : ''}
        ${c.network_mode ? `<p class="muted">Network mode ${esc(c.network_mode)}: it joins no networks.</p>` : nets ? `<ul class="card-nets">${nets}</ul>` : '<p class="muted">On no network.</p>'}
        <div class="card-actions">
          <button class="btn small primary" type="button" data-action="ct-open" data-id="${esc(c.id)}">Details</button>
          ${!ro && !c.network_mode ? `<button class="btn small" type="button" data-action="map-cable" data-id="${esc(c.id)}">Connect…</button>` : ''}
          ${ro || c.self ? '' : c.running ? `<button class="btn small" type="button" data-action="ct-stop" data-id="${esc(c.id)}">Stop</button>` : `<button class="btn small" type="button" data-action="ct-start" data-id="${esc(c.id)}">Start</button>`}
          ${[...ct.expanded].some((k) => k.split('|')[1] === c.name.replace(/[-_.]?\d+$/, '') && k.startsWith((c.project || '') + '|')) ? `<button class="card-link" type="button" data-action="stack-collapse" data-name="${esc(c.name)}">Fold the replicas</button>` : ''}
        </div>`;
      return;
    }
    if (n.kind === 'net') {
      const net = ctView().ns.find((x) => x.name === n.ref);
      if (!net) { card.hidden = true; return; }
      const members = net.members.map((id) => findCt(id)).filter(Boolean);
      card.innerHTML = `<div class="card-head"><svg class="card-glyph" viewBox="-32 -14 64 28" aria-hidden="true"><rect x="-30" y="-12" width="60" height="24" rx="4"/></svg><b class="mono" translate="no">${esc(net.name)}</b></div>
        <div class="muted">${esc(net.builtin ? "Docker's default bridge: containers on it reach each other by address only, not by name" : net.driver)}${net.subnet ? ` · <span class="num">${esc(net.subnet)}</span>` : ''}</div>
        <div class="muted">${num(members.length)} ${members.length === 1 ? 'container' : 'containers'}</div>
        ${members.length ? `<ul class="card-nets">${members.slice(0, 10).map((c) => `<li><button class="ip-link" type="button" data-action="map-focus" data-id="${esc(c.id)}" translate="no">${esc(c.name)}</button><span class="state-dot ${STATE_TONE[c.state] || ''}"></span></li>`).join('')}${members.length > 10 ? `<li class="muted">and ${num(members.length - 10)} more</li>` : ''}</ul>` : ''}
        <div class="card-actions">${!ro && !members.length && !net.builtin ? `<button class="btn small danger" type="button" data-action="net-delete" data-net="${esc(net.name)}">Delete network</button>` : ''}</div>`;
      return;
    }
    card.innerHTML = `<div class="card-head"><b>${esc(n.label)}</b></div><p class="muted">Containers on the host network share this server's own interfaces: whatever they listen on is open on the host directly, and SkyGuard's bans apply to them through INPUT.</p>`;
  }
  async function deleteNetwork(name) {
    if (!await confirmAction(`Delete network ${name}?`, 'No container is on it. It can be created again from the Networks panel.', 'Delete')) return;
    try { await ctPost('networks/delete', { name }); toast(`Network ${name} deleted`); renderCard(null); }
    catch (e) { toast(`Not deleted: ${e.message}`, false); }
    loadContainers();
  }

  async function connectTo(id, network, create = false) {
    const c = findCt(id);
    try {
      await ctPost('connect', { id, network, create: create ? '1' : '0' });
      toast(`${c.name} joined ${network}`);
      return true;
    } catch (e) { toast(`${c.name}: ${e.message}`, false); return false; }
    finally { loadContainers(); }
  }

  // Two containers reach each other by name once they share a network: join one of the target's,
  // or make a new one for the pair.
  function openConnect(fromId, toId) {
    const a = findCt(fromId), b = findCt(toId), { ns } = ctView();
    if (b.network_mode) { toast(`${b.name} uses network mode ${b.network_mode} and cannot share a network`, false); return; }
    const mine = new Set(a.networks.map((e) => e.network));
    const shared = b.networks.map((e) => e.network).filter((n) => mine.has(n) && !(ns.find((x) => x.name === n) || {}).builtin);
    if (shared.length) { toast(`${a.name} and ${b.name} already share ${shared.join(', ')}: they reach each other by name`); return; }
    const joinable = b.networks.map((e) => ns.find((n) => n.name === e.network)).filter((n) => n && n.attachable && !n.builtin && !mine.has(n.name));
    const max = ct.engine === 'incus' ? 15 : 63;
    const suggest = `${a.name}-${b.name}`.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, max).replace(/[-.]+$/, '');
    $('#connect-title').textContent = `Connect ${a.name} to ${b.name}`;
    $('#connect-text').textContent = joinable.length
      ? `They need a network in common. ${a.name} can join one of ${b.name}'s, or the two can get a network of their own.`
      : `They need a network in common, and ${b.name} has none that ${a.name} can join. SkyGuard makes a new one and plugs both in.`;
    $('#connect-options').innerHTML = joinable.map((n, i) => `<label class="option"><input type="radio" name="target" value="join" data-net="${esc(n.name)}" ${i === 0 ? 'checked' : ''}>
        <span><b class="mono" translate="no">${esc(n.name)}</b><span class="muted">Join ${esc(b.name)}'s network · ${num(n.members.length)} ${n.members.length === 1 ? 'container' : 'containers'}${n.subnet ? ` · ${esc(n.subnet)}` : ''}</span></span></label>`).join('')
      + `<label class="option"><input type="radio" name="target" value="new" ${joinable.length ? '' : 'checked'}>
        <span><b>A new network for the two</b><input class="input mono" name="newname" value="${esc(suggest)}" maxlength="${max}" aria-label="New network name" spellcheck="false" autocomplete="off" translate="no"></span></label>`;
    $('#connect-error').textContent = '';
    const f = $('#connect-form');
    f.dataset.from = fromId; f.dataset.to = toId;
    $('#connect-dialog').showModal();
    $('#connect-submit').focus();
  }
  async function submitConnect(f) {
    const a = findCt(f.dataset.from), b = findCt(f.dataset.to), pick = $('input[name="target"]:checked', f);
    const btn = $('#connect-submit');
    btn.disabled = true; btn.textContent = 'Connecting…';
    try {
      let net;
      if (pick.value === 'join') {
        net = pick.dataset.net;
        await ctPost('connect', { id: a.id, network: net });
      } else {
        net = f.elements.newname.value.trim();
        await ctPost('connect', { id: a.id, network: net, create: '1' });
        await ctPost('connect', { id: b.id, network: net });
      }
      $('#connect-dialog').close();
      toast(`${a.name} and ${b.name} now share ${net}`);
      loadContainers();
    } catch (e) { $('#connect-error').textContent = e.message; loadContainers(); }
    btn.disabled = false; btn.textContent = 'Connect';
  }

  async function jack(btn) {
    const c = findCt(btn.dataset.id), net = btn.dataset.net, ep = c.networks.find((e) => e.network === net);
    if (!ep) { connectTo(c.id, net); return; }
    disconnectFrom(c.id, net);
  }
  async function disconnectFrom(id, net) {
    const c = findCt(id), ep = c && c.networks.find((e) => e.network === net);
    if (!ep || ct.data.read_only) return;
    if (!await confirmAction(`Take ${c.name} off ${net}?`, `It loses ${ep.ip ? `its address ${ep.ip.replace(/\/\d+$/, '')} and ` : ''}its name on ${net}, so the containers there can no longer reach it.`, 'Disconnect')) return;
    try { await ctPost('disconnect', { id: c.id, network: net }); toast(`${c.name} left ${net}`); }
    catch (e) { toast(`${c.name}: ${e.message}`, false); }
    loadContainers();
  }

  async function ctAction(id, action, engine = ct.engine) {
    const c = findCt(id, engine) || ct.cur;
    if (action === 'stop' || action === 'restart') {
      const what = action === 'stop' ? 'Its published ports close until it is started again.' : 'It is stopped and started again; open connections drop.';
      if (!await confirmAction(`${action === 'stop' ? 'Stop' : 'Restart'} ${c.name}?`, what, action === 'stop' ? 'Stop' : 'Restart')) return;
    }
    try {
      const after = await post('/api/containers/action', { engine, id, action });
      toast(`${after.name} is ${['paused', 'frozen'].includes(after.state) ? 'paused' : after.running ? 'running' : 'stopped'}`);
    } catch (e) { toast(`${c.name}: ${e.message}`, false); }
    loadContainers();
  }

  function renderHostPorts() {
    const rows = ct.data.host_ports, conflicts = rows.filter((u) => u.conflict).length;
    $('#hp-meta').textContent = conflicts ? `${num(conflicts)} ${conflicts === 1 ? 'conflict' : 'conflicts'}` : `${num(rows.length)} ports in use, no conflicts`;
    const owner = (o) => (o.kind === 'skyguard'
      ? `<div>SkyGuard ${esc(o.name)}${o.failed ? ' <span class="muted">(could not start)</span>' : ''}</div>`
      : `<div><button class="ip-link" type="button" data-action="ct-open-any" data-engine="${esc(o.kind)}" data-id="${esc(o.id)}" translate="no">${esc(o.name)}</button> <span class="muted">${esc(engineName(o.kind))}${o.host_ip ? ` · ${esc(o.host_ip)}` : ''}${o.running ? '' : ' · stopped'}</span></div>`);
    $('#host-ports').innerHTML = rows.length ? rows.map((u) => {
      const failed = u.owners.some((o) => o.failed);
      const state = u.conflict ? '<span class="pill neg"><span class="dot"></span>Conflict</span>'
        : failed ? '<span class="pill neg"><span class="dot"></span>Not listening</span>'
        : u.owners.some((o) => o.running) ? '<span class="pill">In use</span>' : '<span class="muted">Free while stopped</span>';
      const targets = u.owners.map((o) => `<div>${o.target ? esc(o.target + (u.proto === 'udp' ? '/udp' : '')) : '—'}</div>`).join('');
      return `<tr class="stacked"><td class="n num">${u.port}${u.proto === 'udp' ? '/udp' : ''}</td><td>${u.owners.map(owner).join('')}</td><td class="num muted">${targets}</td><td class="n">${state}</td></tr>`;
    }).join('') : emptyRow(4, 'No container publishes a port and SkyGuard listens on none.');
  }

  function renderCtNetworks() {
    const { ns, eng } = ctView();
    $('#net-meta').textContent = eng.available ? `${num(ns.length)} on ${engineName(eng.name)}` : '';
    $('#net-form').hidden = ct.data.read_only || !eng.available;
    $('#net-form').elements.name.maxLength = ct.engine === 'incus' ? 15 : 63;
    if (!ns.length) { $('#ct-networks').innerHTML = emptyBlock('No networks.'); return; }
    const max = Math.max(1, ...ns.map((n) => n.members.length));
    $('#ct-networks').innerHTML = ns.map((n) => `<li>
      <span class="who"><button class="ip-link" type="button" data-action="net-pick" data-net="${esc(n.name)}" translate="no">${esc(n.name)}</button><span class="muted">${esc(n.builtin ? 'default bridge, no name lookup' : n.driver)}${n.subnet ? ` · ${esc(n.subnet)}` : ''}</span></span>
      <span class="n num">${num(n.members.length)}</span><span></span>
      <span class="bar" style="width:${(100 * n.members.length / max).toFixed(1)}%"></span></li>`).join('');
  }
  // Which container ports anyone on the internet can reach, and whether a ban stops them there.
  function renderExposure() {
    const open = ct.data.host_ports.filter((u) => u.owners.some((o) => o.kind !== 'skyguard' && o.running && !o.host_ip));
    const cov = ct.data.ban_coverage || {}, hasDocker = open.some((u) => u.owners.some((o) => o.kind === 'docker'));
    const el = $('#ban-cover');
    el.className = 'cover';
    if (!open.length) el.textContent = 'No container publishes a port on every address: they are reachable from this host only.';
    else if (cov.method === 'none' || cov.method === 'log') el.textContent = 'Auto-ban only logs (method none), so nothing stops a banned IP at these ports.';
    else if (hasDocker && cov.method === 'ufw') { el.classList.add('bad'); el.textContent = "Banned IPs can still reach the Docker ports below: ufw's rules never see traffic Docker forwards. Set auto_ban.method to iptables to cover them."; }
    else if (hasDocker && cov.docker_chain && !cov.docker_covered) { el.classList.add('bad'); el.innerHTML = 'Banned IPs can still reach the Docker ports below: SkyGuard\'s chain is missing from DOCKER-USER. Restart SkyGuard, or run <code>iptables -I DOCKER-USER 1 -j SKYGUARD</code>.'; }
    else el.textContent = hasDocker ? "Bans cover them: SkyGuard's chain sits at the top of DOCKER-USER, where Docker's forwarded traffic passes first." : 'Bans cover them: Incus proxies accept on the host, behind the SKYGUARD chain.';
    $('#open-meta').textContent = open.length ? `${num(open.length)} ${open.length === 1 ? 'port' : 'ports'}` : '';
    $('#open-ports').innerHTML = open.map((u) => {
      const o = u.owners.find((x) => x.kind !== 'skyguard' && x.running && !x.host_ip);
      return `<li><span class="who"><span class="num">${u.port}${u.proto === 'udp' ? '/udp' : ''}</span><button class="ip-link" type="button" data-action="ct-open-any" data-engine="${esc(o.kind)}" data-id="${esc(o.id)}" translate="no">${esc(o.name)}</button><span class="muted">${esc(engineName(o.kind))} · to ${esc(o.target)}</span></span><span></span><span></span></li>`;
    }).join('');
  }
  async function createNetwork(f) {
    const name = f.elements.name.value.trim(), btn = $('#net-submit');
    if (!name) { f.elements.name.focus(); return; }
    btn.disabled = true;
    try { await ctPost('networks', { name }); toast(`Network ${name} created`); f.reset(); }
    catch (e) { toast(`Not created: ${e.message}`, false); }
    btn.disabled = false;
    loadContainers();
  }

  // ── one container ───────────────────────────────────────────────────────
  async function openCt(id, engine = ct.engine) {
    if (engine !== ct.engine) { ct.engine = engine; writeHash(); renderEngines(); renderBay(); renderCtNetworks(); renderCtFinding(); }
    ct.sheet = id;
    const sheet = $('#ct-sheet');
    const c = findCt(id);
    $('#ct-title').textContent = c ? c.name : id;
    $('#ct-tags').innerHTML = ''; $('#ct-actions').innerHTML = ''; $('#ct-note').textContent = '';
    $('#ct-facts').innerHTML = ['State', 'Image', 'Created', 'Address'].map((k) => `<div><dt>${k}</dt><dd><span class="skeleton">000000</span></dd></div>`).join('');
    $('#port-rows').innerHTML = ''; $('#ct-nets').innerHTML = skeletonRows(4, 1); $('#ct-mounts').innerHTML = '';
    ['#ports-msg', '#limits-msg', '#logs-meta'].forEach((s) => { $(s).textContent = ''; });
    $('#ct-logs').hidden = true; $('[data-action="ct-logs"]').textContent = 'Load the last 200 lines'; ct.snapsFor = null;
    if (!sheet.open) sheet.showModal();
    await refreshSheet();
  }
  async function refreshSheet() {
    try { renderSheet(await api(`/api/containers/inspect?engine=${encodeURIComponent(ct.engine)}&id=${encodeURIComponent(ct.sheet)}`)); }
    catch (e) { blockError($('#ct-facts'), 'the container', e); }
  }
  function renderSheet(c) {
    ct.cur = c; ct.sheet = c.id;
    const ro = ct.data.read_only, docker = c.engine === 'docker', locked = !!c.network_mode;
    $('#ct-title').textContent = c.name;
    $('#ct-tags').innerHTML = `<span class="pill ${STATE_TONE[c.state] || ''}"><span class="dot"></span>${esc(c.state)}</span> <span class="pill">${esc(engineName(c.engine))}${c.kind === 'virtual-machine' ? ' VM' : ''}</span>${c.project ? ` <span class="pill" title="Docker Compose project">${esc(c.project)}</span>` : ''}${c.self ? ' <span class="pill">SkyGuard</span>' : ''}`;
    const addr = locked ? c.network_mode : (c.networks.find((e) => e.ip) || {}).ip;
    $('#ct-facts').innerHTML = [['State', c.status || c.state], ['Image', c.image || '—'], ['Created', c.created ? stamp(c.created) : '—'], ['Address', addr ? addr.replace(/\/\d+$/, '') : '—']]
      .map(([k, v]) => `<div><dt>${k}</dt><dd title="${esc(v)}">${esc(v)}</dd></div>`).join('');
    const btn = (action, label, primary) => `<button class="btn${primary ? ' primary' : ''}" type="button" data-action="ct-sheet-action" data-do="${action}">${label}</button>`;
    const paused = ['paused', 'frozen'].includes(c.state);
    $('#ct-actions').innerHTML = ro || c.self ? '' : paused ? btn('resume', 'Resume', true) + btn('stop', 'Stop')
      : c.running ? btn('restart', 'Restart') + btn('pause', 'Pause') + btn('stop', 'Stop') : btn('start', 'Start', true);
    $('#ct-note').textContent = c.self ? "This is SkyGuard's own container: restart or change it with docker compose on the host, or the dashboard would go down with it."
      : ro ? 'Read-only: containers.read_only is set in the config file.' : '';

    // ports
    const pf = $('#ports-form'), editable = !ro && !c.self && !locked && !(c.kind === 'virtual-machine');
    $('#port-rows').innerHTML = c.ports.length ? c.ports.map((p) => portRow(p, c)).join('') : `<div class="empty small">${locked ? "It uses the host's network: whatever it listens on is open on the host directly." : 'No published ports.'}</div>`;
    $$('input, select, button', pf).forEach((el) => { el.disabled = !editable; });
    $('[data-action="port-add"]').hidden = !editable;
    $('#ports-submit').hidden = !editable;
    $('#ports-submit').textContent = docker ? 'Save and recreate' : 'Save ports';
    $('#ports-hint').textContent = locked || c.self ? '' : c.kind === 'virtual-machine' ? 'Virtual machines take only NAT proxy devices with a fixed address; add them with incus config device add.'
      : docker ? `Docker cannot change the ports of an existing container, so saving recreates ${c.name} from the same image with the same settings, volumes and networks. It restarts once; if the new one fails to start, the old one is put back.${c.project ? ` It belongs to the Compose project ${c.project}: the next docker compose up puts the compose file's ports back, so change them there too.` : ''}`
      : 'Incus adds and removes proxy devices on the running instance; nothing restarts.';
    pf.dataset.exposed = (c.exposed || []).join(',');

    // networks
    $('#ct-nets').innerHTML = locked ? emptyRow(4, `Network mode ${c.network_mode}: it joins no networks.`) : c.networks.length ? c.networks.map((e) => `<tr><td class="mono" translate="no">${esc(e.network)}</td><td class="num">${esc((e.ip || '—').replace(/\/\d+$/, ''))}</td>
      <td class="data mono">${esc((e.aliases || []).join(', ') || '—')}</td><td class="n">${ro || c.self ? '' : `<button class="btn small" type="button" data-action="jack" data-id="${esc(c.id)}" data-net="${esc(e.network)}">Disconnect</button>`}</td></tr>`).join('')
      : emptyRow(4, 'On no network. Plug it in from the patch bay.');

    // restart and limits
    const eng = ct.data.engines.find((x) => x.name === c.engine), lf = $('#limits-form');
    $('#restart-group').innerHTML = (eng ? eng.restart_policies : [c.restart]).map((r) => `<button type="button" data-restart="${esc(r)}" aria-pressed="${r === c.restart}">${esc(RESTART_LABELS[r] || r)}</button>`).join('');
    lf.elements.memory_mb.value = c.memory_mb || 0;
    lf.elements.cpus.value = c.cpus || 0;
    lf.elements.cpus.step = docker ? '0.25' : '1';
    $('#cpu-hint').textContent = docker ? '0 = no limit; 0.5 is half a CPU' : '0 = no limit; whole CPUs';
    $('#limits-hint').textContent = docker ? 'Setting or raising a limit applies at once. Removing one recreates the container, because Docker cannot lift a limit in place.' : 'Applies at once.';
    $$('input, button', lf).forEach((el) => { el.disabled = ro || c.self; });
    $('#limits-submit').hidden = ro || c.self;

    $('#ct-mounts-block').hidden = !(c.mounts || []).length;
    $('#ct-mounts').innerHTML = (c.mounts || []).map((m) => `<li class="mono">${esc(m)}</li>`).join('');

    $('#ct-danger').hidden = ro || c.self;
    $('#remove-hint').textContent = docker ? 'Stops and deletes the container. Its volumes stay, named and anonymous; remove them yourself when you are sure.'
      : 'Stops and deletes the instance with its snapshots. Custom storage volumes attached to it stay.';
    const snaps = !!(eng && eng.snapshots);
    $('#ct-snaps-block').hidden = !snaps;
    $('#snap-form').hidden = ro;
    if (snaps && ct.snapsFor !== c.id) loadSnapshots(c);
  }
  const snapName = () => { const d = new Date(), p = (n) => String(n).padStart(2, '0'); return `snap-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`; }; // taste-skill-ignore: a date in a snapshot name
  async function loadSnapshots(c = ct.cur) {
    ct.snapsFor = c.id;
    $('#snap-form').elements.name.value = snapName();
    try {
      const list = await api(`/api/containers/snapshots?engine=${encodeURIComponent(c.engine)}&id=${encodeURIComponent(c.id)}`);
      $('#ct-snaps').innerHTML = list.length ? list.map((x) => `<tr><td class="mono" translate="no">${esc(x.name)}${x.stateful ? ' <span class="muted">with memory</span>' : ''}</td><td class="n" title="${esc(stamp(x.created))}">${esc(ago(x.created))}</td>
        <td class="n">${ct.data.read_only ? '' : `<button class="btn small" type="button" data-action="snap-restore" data-name="${esc(x.name)}">Roll back</button> <button class="btn small" type="button" data-action="snap-delete" data-name="${esc(x.name)}">Delete</button>`}</td></tr>`).join('')
        : emptyRow(3, 'No snapshots yet. Take one before a risky change.');
    } catch (e) { blockError($('#ct-snaps'), 'snapshots', e); }
  }
  async function snapshot(action, name) {
    const c = ct.cur;
    if (action === 'restore' && !await confirmAction(`Roll ${c.name} back to ${name}?`, 'Everything written since that snapshot is lost.', 'Roll back')) return;
    if (action === 'delete' && !await confirmAction(`Delete snapshot ${name}?`, 'It cannot be restored afterwards.', 'Delete')) return;
    const btn = $('#snap-submit');
    if (action === 'take') { btn.disabled = true; btn.textContent = 'Taking…'; }
    try {
      await post('/api/containers/snapshots', { engine: c.engine, id: c.id, action, name });
      toast(action === 'take' ? `Snapshot ${name} taken` : action === 'restore' ? `${c.name} rolled back to ${name}` : `Snapshot ${name} deleted`);
    } catch (e) { toast(`Snapshot: ${e.message}`, false); }
    btn.disabled = false; btn.textContent = 'Take snapshot';
    loadSnapshots(c);
    refreshSheet();
  }
  async function loadLogs() {
    const c = ct.cur, pre = $('#ct-logs');
    $('#logs-meta').textContent = 'Loading…';
    try {
      const r = await api(`/api/containers/logs?engine=${encodeURIComponent(c.engine)}&id=${encodeURIComponent(c.id)}&lines=200`);
      pre.textContent = r.text.trim() || '(nothing written yet)';
      pre.hidden = false;
      pre.scrollTop = pre.scrollHeight;
      $('#logs-meta').textContent = `Last ${num(r.lines)} lines at ${clock(new Date())}`;
      $('[data-action="ct-logs"]').textContent = 'Reload';
    } catch (e) { $('#logs-meta').textContent = e.message; }
  }
  async function removeCt() {
    const c = ct.cur;
    if (!await confirmAction(`Remove ${c.name}?`, c.engine === 'docker' ? 'The container is stopped and deleted; its volumes stay. This cannot be undone.' : 'The instance is stopped and deleted with its snapshots. This cannot be undone.', 'Remove')) return;
    try {
      await post('/api/containers/remove', { engine: c.engine, id: c.id });
      $('#ct-sheet').close();
      toast(`${c.name} removed`);
    } catch (e) { toast(`${c.name}: ${e.message}`, false); }
    loadContainers();
  }

  // ── a new container ─────────────────────────────────────────────────────
  const IMAGE_HINTS = {
    docker: ['nginx:alpine', 'caddy:2-alpine', 'redis:alpine', 'postgres:17-alpine', 'mariadb:11', 'jc21/nginx-proxy-manager:latest', 'louislam/uptime-kuma:2', 'portainer/portainer-ce:latest'],
    incus: ['images:debian/12', 'images:ubuntu/24.04', 'images:alpine/3.22', 'images:rockylinux/9', 'images:archlinux'],
  };
  function openCreate() {
    const f = $('#create-form'), { ns, eng } = ctView(), docker = ct.engine === 'docker';
    f.reset(); $('#create-error').textContent = '';
    $('#create-title').textContent = docker ? 'New Docker container' : 'New Incus instance';
    $('#image-hints').innerHTML = IMAGE_HINTS[ct.engine].map((i) => `<option value="${esc(i)}">`).join('');
    f.elements.image.placeholder = docker ? 'nginx:alpine…' : 'images:debian/12…';
    $('#image-hint').textContent = docker ? 'Pulled from the registry if it is not on this server yet.' : 'images:<distro>/<release> downloads from images.linuxcontainers.org; a bare name is an image already on this server.';
    $('#create-network').innerHTML = `<option value="">${docker ? "Docker's default bridge" : 'From the default profile'}</option>` + ns.filter((n) => n.attachable && !n.builtin).map((n) => `<option value="${esc(n.name)}">${esc(n.name)}${n.subnet ? ' · ' + esc(n.subnet) : ''}</option>`).join('');
    const def = docker ? 'unless-stopped' : 'last-state';
    $('#create-restart').innerHTML = eng.restart_policies.map((r) => `<button type="button" data-restart="${esc(r)}" aria-pressed="${r === def}">${esc(RESTART_LABELS[r] || r)}</button>`).join('');
    f.querySelector('.env-field').hidden = !docker;
    $('#create-vm-row').hidden = docker;
    f.elements.cpus.step = docker ? '0.25' : '1';
    $('#create-dialog').showModal();
    f.elements.name.focus();
  }
  async function submitCreate(f) {
    const el = f.elements, btn = $('#create-submit'), pressed = $('#create-restart [aria-pressed="true"]');
    const data = { engine: ct.engine, name: el.name.value.trim(), image: el.image.value.trim(), ports: el.ports.value.trim(), network: el.network.value,
      env: ct.engine === 'docker' ? el.env.value : '', restart: pressed ? pressed.dataset.restart : '', memory_mb: el.memory_mb.value || '0', cpus: el.cpus.value || '0',
      start: el.start.checked ? '1' : '0', vm: el.vm.checked ? '1' : '0' };
    btn.disabled = true; btn.textContent = ct.engine === 'docker' ? 'Pulling and creating…' : 'Downloading and creating…';
    $('#create-error').textContent = 'This can take a few minutes the first time an image is used.';
    try {
      const r = await post('/api/containers/create', data);
      $('#create-dialog').close();
      toast(r.warning ? `${data.name}: ${r.warning}` : `${data.name} is ${r.container.running ? 'running' : 'created'}`, !r.warning);
      await loadContainers();
      if (r.container && ct.topos[ct.engine]) ct.topos[ct.engine].focus('ct:' + r.container.id);
    } catch (e) { $('#create-error').textContent = e.message; }
    btn.disabled = false; btn.textContent = 'Create';
  }

  // ── engine switches (settings) ──────────────────────────────────────────
  async function loadEngineSwitches() {
    const box = $('#engine-switches');
    let d;
    try { d = await api('/api/containers'); } catch (e) { blockError(box, 'the container engines', e); return; }
    if (!d.engines) { box.innerHTML = '<div class="muted">Container management needs the dashboard.</div>'; return; }
    box.innerHTML = d.engines.map((e) => `<label class="switch-row engine-row"><span><b>${esc(engineName(e.name))}</b><br>
        <span class="muted mono">${esc(e.socket || '')}</span><br>
        <span class="${e.enabled && !e.available ? 'neg-text' : 'muted'}">${!e.enabled ? 'Off' : e.available ? `On · ${esc(engineName(e.name))} ${esc(e.version || '')}` : `On, but not reachable: ${esc(e.error || '')}`}</span></span>
        <input class="switch" type="checkbox" role="switch" data-action="engine-switch" data-engine="${esc(e.name)}" ${e.enabled ? 'checked' : ''} aria-label="Manage ${esc(engineName(e.name))}"></label>`).join('')
      + (d.read_only ? '<p class="hint">containers.read_only is set in the config file: the dashboard lists containers and changes nothing.</p>' : '');
  }
  async function switchEngine(engine, on, input) {
    if (input) input.disabled = true;
    try {
      await post('/api/containers/engines', { engine, enabled: on ? '1' : '0' });
      toast(on ? `${engineName(engine)} management is on` : `${engineName(engine)} management is off`);
      if (on) ct.engine = engine;
    } catch (e) { if (input) input.checked = !on; toast(`${engineName(engine)}: ${e.message}`, false); }
    if (input) input.disabled = false;
    if (current === 'settings') loadEngineSwitches(); else loadContainers();
  }
  function portRow(p = {}, c = ct.cur) {
    const inherited = p.inherited ? ' <span class="muted">from a profile</span>' : '';
    return `<div class="port-row">
      <input class="input mono" name="host_ip" value="${esc(p.host_ip || '')}" placeholder="All addresses" aria-label="Host address" spellcheck="false" autocomplete="off">
      <input class="input mono" name="host_port" type="number" min="${c && c.engine === 'docker' ? 0 : 1}" max="65535" value="${p.host_port == null ? '' : p.host_port}" placeholder="8080" aria-label="Host port" required>
      <span class="arrow" aria-hidden="true">→</span>
      <input class="input mono" name="container_port" type="number" min="1" max="65535" value="${p.container_port || ''}" placeholder="80" aria-label="Container port" required>
      <select class="input" name="proto" aria-label="Protocol"><option value="tcp"${p.proto === 'udp' ? '' : ' selected'}>TCP</option><option value="udp"${p.proto === 'udp' ? ' selected' : ''}>UDP</option></select>
      <button class="icon-btn small" type="button" data-action="port-remove" aria-label="Remove this port"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>${inherited}
    </div>`;
  }
  function addPortRow() {
    const rows = $('#port-rows'), first = (($('#ports-form').dataset.exposed || '').split(',')[0] || '').split('/');
    if ($('.empty', rows)) rows.innerHTML = '';
    rows.insertAdjacentHTML('beforeend', portRow({ container_port: Number(first[0]) || '', proto: first[1] || 'tcp', host_port: null }));
    $('.port-row:last-child input[name="host_port"]', rows).focus();
  }
  async function savePorts(f) {
    const c = ct.cur, specs = [];
    for (const row of $$('.port-row', f)) {
      const v = (n) => $(`[name="${n}"]`, row).value.trim();
      if (!v('host_port') && !v('container_port')) continue;
      specs.push(`${hostPart(v('host_ip'))}${v('host_port')}:${v('container_port')}/${v('proto')}`);
    }
    const msg = $('#ports-msg'), btn = $('#ports-submit'), label = btn.textContent;
    btn.disabled = true; btn.textContent = c.engine === 'docker' ? 'Recreating…' : 'Saving…'; msg.textContent = '';
    try {
      const after = await post('/api/containers/ports', { engine: c.engine, id: c.id, ports: specs.join(',') });
      renderSheet(after);
      $('#ports-msg').textContent = `Saved at ${clock(new Date())}`;
      toast(`${after.name}: ${after.ports.length ? after.ports.map(portLabel).join(', ') : 'no published ports'}`);
    } catch (e) { msg.textContent = e.message; toast(`Ports not changed: ${e.message}`, false); }
    btn.disabled = false; btn.textContent = label;
    loadContainers();
  }
  async function saveLimits(f) {
    const c = ct.cur, pressed = $('#restart-group [aria-pressed="true"]');
    const msg = $('#limits-msg'), btn = $('#limits-submit');
    btn.disabled = true; btn.textContent = 'Saving…'; msg.textContent = '';
    try {
      const after = await post('/api/containers/settings', { engine: c.engine, id: c.id, restart: pressed ? pressed.dataset.restart : '', memory_mb: f.elements.memory_mb.value.trim() || '0', cpus: f.elements.cpus.value.trim() || '0' });
      renderSheet(after);
      $('#limits-msg').textContent = `Saved at ${clock(new Date())}`;
      toast(`${after.name}: restart ${RESTART_LABELS[after.restart] ? RESTART_LABELS[after.restart].toLowerCase() : after.restart}, ${after.memory_mb ? `${num(after.memory_mb)} MB` : 'no memory limit'}, ${after.cpus ? `${after.cpus} CPUs` : 'no CPU limit'}`);
    } catch (e) { msg.textContent = e.message; toast(`Not saved: ${e.message}`, false); }
    btn.disabled = false; btn.textContent = 'Save';
    loadContainers();
  }

  // ── routing ─────────────────────────────────────────────────────────────
  const SCREENS = {
    overview: { title: 'Overview', load: loadOverview, live: true },
    connections: { title: 'Connections', load: loadConnections, live: false },
    attackers: { title: 'Attackers and bans', load: loadAttackers, live: true },
    credentials: { title: 'Captured credentials', load: loadCredentials, live: true },
    services: { title: 'Honeypots and services', load: loadServices, live: true },
    containers: { title: 'Containers', load: loadContainers, live: true },
    settings: { title: 'Auto-ban and firewall', load: loadSettings, live: false },
  };
  let current = 'overview';
  // The screen and its state live in the hash, so a view can be bookmarked, shared and reloaded:
  // #overview?range=7d&metric=credentials, #connections?ip=203.0.113.9&action=dropped
  function parseHash() {
    const [name, q] = location.hash.slice(1).split('?');
    return [name, new URLSearchParams(q || '')];
  }
  function writeHash() {
    const p = new URLSearchParams();
    if (current === 'overview' || current === 'credentials') {
      if (state.range !== '24h') p.set('range', state.range);
      if (current === 'overview' && state.metric !== 'total') p.set('metric', state.metric);
    }
    if (current === 'connections') {
      const f = $('#conn-filters');
      for (const k of ['ip', 'service', 'country']) { const v = f.elements[k].value.trim(); if (v) p.set(k, v); }
      if (state.conn.action) p.set('action', state.conn.action);
    }
    if (current === 'containers' && ct.engine && ct.data && ct.data.engines && ct.data.engines.filter((e) => e.enabled).length > 1) p.set('engine', ct.engine);
    if (current === 'containers' && ct.view === 'table') p.set('view', 'table');
    const hash = '#' + current + (p.toString() ? '?' + p : '');
    if (location.hash !== hash) history.replaceState(null, '', hash);
  }
  function applyParams(name, p) {
    if (['24h', '7d', '30d'].includes(p.get('range'))) state.range = p.get('range');
    else if (name === 'overview' || name === 'credentials') state.range = '24h';
    $$('[data-range]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === state.range)));
    if (name === 'containers' && ['docker', 'incus'].includes(p.get('engine'))) ct.engine = p.get('engine');
    if (name === 'containers') ct.view = p.get('view') === 'table' ? 'table' : 'map';
    if (name === 'overview') state.metric = METRICS.some((m) => m.key === p.get('metric')) ? p.get('metric') : 'total';
    if (name === 'connections') {
      const f = $('#conn-filters');
      for (const k of ['ip', 'service', 'country']) f.elements[k].value = p.get(k) || '';
      state.conn.action = ['honeypot', 'dropped', 'forwarded'].includes(p.get('action')) ? p.get('action') : '';
      $$('[data-filter-group] button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.value === state.conn.action)));
      state.conn.offset = 0;
    }
  }
  function show(name, params = new URLSearchParams()) {
    if (!SCREENS[name]) name = 'overview';
    current = name;
    applyParams(name, params);
    $$('[data-screen]').forEach((s) => { s.hidden = s.dataset.screen !== name; });
    const sec = $(`[data-screen="${name}"]`), main = $('#main');
    if (main.querySelector('[data-screen]') !== sec) main.insertBefore(sec, main.querySelector('[data-screen]'));
    $$('[data-nav]').forEach((a) => { if (a.dataset.nav === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    document.title = `${SCREENS[name].title} · SkyGuard`;
    writeHash();
    refresh();
  }
  let refreshing = false;
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    const btn = $('[data-action="refresh"]'); btn && btn.classList.add('spin');
    try { await SCREENS[current].load(); } finally { refreshing = false; btn && btn.classList.remove('spin'); }
  }
  function pressOnly(group, value, attr = 'duration') {
    $$('button', group).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset[attr] === value)));
  }

  // ── events ──────────────────────────────────────────────────────────────
  document.addEventListener('click', (ev) => {
    const t = ev.target;
    // While a cable is lifted, the next click drops it: on a container, on a network, or nowhere.
    if (ct.patch) { ev.preventDefault(); dropPatch(t); return; }
    const engBtn = t.closest('[data-engine]:not([data-action])');
    if (engBtn) { ct.engine = engBtn.dataset.engine; writeHash(); loadContainers(); return; }
    const cv = t.closest('[data-ctview]');
    if (cv) { ct.view = cv.dataset.ctview; applyCtView(); writeHash(); if (ct.view === 'map' && ct.data) renderMap(); return; }
    const cf = t.closest('[data-ctfilter]');
    if (cf) { ct.only = cf.dataset.ctfilter; applyCtView(); renderBay(); renderMap(); return; }
    const restart = t.closest('[data-restart]');
    if (restart) { pressOnly(restart.parentElement, restart.dataset.restart, 'restart'); return; }
    const range = t.closest('[data-range]');
    if (range) {
      state.range = range.dataset.range;
      $$('[data-range]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === state.range)));
      writeHash();
      refresh();
      return;
    }
    const metric = t.closest('[data-metric]');
    if (metric) {
      state.metric = metric.dataset.metric;
      $$('[data-metric]').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.metric === state.metric)));
      writeHash();
      if (lastSeries) renderSeries();
      return;
    }
    const dur = t.closest('[data-duration]');
    if (dur) { pressOnly(dur.parentElement, dur.dataset.duration); if (dur.closest('[data-duration-group]')) $('#set-duration').value = dur.dataset.duration; return; }
    const filt = t.closest('[data-filter-group] button');
    if (filt) {
      state.conn.action = filt.dataset.value; state.conn.offset = 0;
      $$('button', filt.parentElement).forEach((b) => b.setAttribute('aria-pressed', String(b === filt)));
      writeHash();
      loadConnections();
      return;
    }
    const step = t.closest('[data-step]');
    if (step) { const i = $('#set-threshold'); i.value = Math.max(1, (parseInt(i.value, 10) || 0) + parseInt(step.dataset.step, 10)); return; }
    const a = t.closest('[data-action]');
    if (!a) return;
    const ip = a.dataset.ip;
    switch (a.dataset.action) {
      case 'refresh': refresh(); break;
      case 'ip': openIP(ip); break;
      case 'ban': openBan(ip); break;
      case 'ban-dialog': openBan(''); break;
      case 'unban': unban(ip); break;
      case 'close-dialog': a.closest('dialog').close(); break;
      case 'search-ip':
        if ($('#ip-sheet').open) $('#ip-sheet').close();
        location.hash = '#connections?ip=' + encodeURIComponent(ip);
        break;
      case 'export': location.href = '/api/export?' + connParams(); break;
      case 'page-next': state.conn.offset += state.conn.limit; loadConnections(); break;
      case 'page-prev': state.conn.offset = Math.max(0, state.conn.offset - state.conn.limit); loadConnections(); break;
      case 'patch': startPatch(a.dataset.id); break;
      case 'jack': jack(a); break;
      case 'net-pick': {
        // one network lit at a time: its bus, its jacks and its cables; the rest step back
        ct.hl = ct.hl === a.dataset.net ? '' : a.dataset.net;
        const bay = $('#bay');
        if (ct.hl) bay.dataset.hl = ct.hl; else bay.removeAttribute('data-hl');
        $$('.jack-cell, .net-head', bay).forEach((el) => el.classList.toggle('lit', !!ct.hl && el.dataset.net === ct.hl));
        $$('.net-head', bay).forEach((el) => el.setAttribute('aria-pressed', String(el.dataset.net === ct.hl)));
        drawCables();
        break;
      }
      case 'ct-open': openCt(a.dataset.id); break;
      case 'ct-open-any': openCt(a.dataset.id, a.dataset.engine); break;
      case 'ct-start': ctAction(a.dataset.id, 'start'); break;
      case 'ct-stop': ctAction(a.dataset.id, 'stop'); break;
      case 'ct-sheet-action': ctAction(ct.cur.id, a.dataset.do, ct.cur.engine).then(() => { if ($('#ct-sheet').open) refreshSheet(); }); break;
      case 'port-add': addPortRow(); break;
      case 'ct-new': openCreate(); break;
      case 'ct-logs': loadLogs(); break;
      case 'ct-remove': removeCt(); break;
      case 'snap-restore': snapshot('restore', a.dataset.name); break;
      case 'snap-delete': snapshot('delete', a.dataset.name); break;
      case 'map-cable': topoFor(ct.engine).startCable('ct:' + a.dataset.id); break;
      case 'map-focus': topoFor(ct.engine).focus('ct:' + a.dataset.id); renderCard({ kind: 'ct', ref: a.dataset.id }); break;
      case 'net-delete': deleteNetwork(a.dataset.net); break;
      case 'stack-expand': ct.expanded.add(a.dataset.key); renderMap(); renderCard(null); break;
      case 'stack-collapse': {
        const b = a.dataset.name.replace(/[-_.]?\d+$/, '');
        [...ct.expanded].forEach((k) => { if (k.split('|')[1] === b) ct.expanded.delete(k); });
        renderMap(); renderCard(null);
        break;
      }
      case 'engine-on': switchEngine(a.dataset.engine, true); break;
      case 'port-remove': {
        a.closest('.port-row').remove();
        if (!$('.port-row', $('#port-rows'))) $('#port-rows').innerHTML = '<div class="empty small">No published ports. Save to unpublish them all.</div>';
        break;
      }
    }
  });
  document.addEventListener('change', (ev) => {
    if (ev.target.matches('[data-action="toggle-service"]')) toggleService(ev.target);
    if (ev.target.matches('[data-action="engine-switch"]')) switchEngine(ev.target.dataset.engine, ev.target.checked, ev.target);
    if (ev.target.closest('#conn-filters')) { state.conn.offset = 0; writeHash(); loadConnections(); }
    if (ev.target.id === 'set-enabled') $('#set-state').textContent = ev.target.checked ? 'On once you save' : 'Off once you save';
  });
  $('#conn-filters').addEventListener('submit', (ev) => { ev.preventDefault(); state.conn.offset = 0; writeHash(); loadConnections(); });
  $('#ban-form').addEventListener('submit', (ev) => { ev.preventDefault(); submitBan(ev.target); });
  $('#ban-form').addEventListener('input', () => { $('#ban-error').textContent = ''; });
  $('#settings-form').addEventListener('submit', (ev) => { ev.preventDefault(); saveSettings(ev.target); });
  $('#connect-form').addEventListener('submit', (ev) => { ev.preventDefault(); submitConnect(ev.target); });
  $('#connect-form').addEventListener('input', () => { $('#connect-error').textContent = ''; });
  $('#connect-form').addEventListener('focusin', (ev) => { if (ev.target.name === 'newname') $('#connect-form input[value="new"]').checked = true; });
  $('#ports-form').addEventListener('submit', (ev) => { ev.preventDefault(); savePorts(ev.target); });
  $('#limits-form').addEventListener('submit', (ev) => { ev.preventDefault(); saveLimits(ev.target); });
  $('#net-form').addEventListener('submit', (ev) => { ev.preventDefault(); createNetwork(ev.target); });
  $('#create-form').addEventListener('submit', (ev) => { ev.preventDefault(); submitCreate(ev.target); });
  $('#snap-form').addEventListener('submit', (ev) => { ev.preventDefault(); const n = ev.target.elements.name.value.trim(); if (n) snapshot('take', n); });
  let searchTimer;
  $('#ct-search').addEventListener('input', (ev) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      ct.query = ev.target.value.trim();
      renderBay();
      const n = ct.topos[ct.engine] ? ct.topos[ct.engine].search(ct.query) : 0;
      $('#bay-help').textContent = ct.query ? `${num(ctView().cs.filter(ctMatches).length)} ${ctView().cs.filter(ctMatches).length === 1 ? 'container matches' : 'containers match'} "${ct.query}"` : '';
      void n;
    }, 120);
  });
  $('#bay').addEventListener('pointermove', movePatch);
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && ct.patch) { ev.preventDefault(); endPatch(); } });
  $('#ct-sheet').addEventListener('click', (ev) => { if (ev.target === ev.currentTarget) ev.currentTarget.close(); });
  // KPI tabs follow the arrow keys, as a tablist should.
  $('#kpis').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const tabs = $$('[data-metric]'), i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const next = tabs[(i + (ev.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
    next.focus(); next.click();
  });
  // The sheet closes when the backdrop is clicked.
  $('#ip-sheet').addEventListener('click', (ev) => { if (ev.target === ev.currentTarget) ev.currentTarget.close(); });
  window.addEventListener('hashchange', () => show(...parseHash()));
  let resizeTimer;
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (current === 'connections') loadConnections(); if (current === 'containers') drawCables(); }, 200); });
  if (document.fonts) document.fonts.ready.then(() => { if (current === 'containers') drawCables(); });

  api('/api/info').then((info) => {
    state.info = info;
    if (info.host) $$('[data-host]').forEach((el) => { el.textContent = info.host; });
  }).catch(() => {});
  show(...parseHash());
  // Live screens refresh every 30 seconds while the tab is visible; old values stay until new ones arrive.
  setInterval(() => { if (!document.hidden && SCREENS[current].live && !ct.patch && !ct.cabling && !document.querySelector('dialog[open]')) refresh(); }, 30000);
})();
