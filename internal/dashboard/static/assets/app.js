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
    const r = await fetch(url, Object.assign({ credentials: 'same-origin' }, opts));
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

  // ── routing ─────────────────────────────────────────────────────────────
  const SCREENS = {
    overview: { title: 'Overview', load: loadOverview, live: true },
    connections: { title: 'Connections', load: loadConnections, live: false },
    attackers: { title: 'Attackers and bans', load: loadAttackers, live: true },
    credentials: { title: 'Captured credentials', load: loadCredentials, live: true },
    services: { title: 'Honeypots and services', load: loadServices, live: true },
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
    const hash = '#' + current + (p.toString() ? '?' + p : '');
    if (location.hash !== hash) history.replaceState(null, '', hash);
  }
  function applyParams(name, p) {
    if (['24h', '7d', '30d'].includes(p.get('range'))) state.range = p.get('range');
    else if (name === 'overview' || name === 'credentials') state.range = '24h';
    $$('[data-range]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === state.range)));
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
    }
  });
  document.addEventListener('change', (ev) => {
    if (ev.target.matches('[data-action="toggle-service"]')) toggleService(ev.target);
    if (ev.target.closest('#conn-filters')) { state.conn.offset = 0; writeHash(); loadConnections(); }
    if (ev.target.id === 'set-enabled') $('#set-state').textContent = ev.target.checked ? 'On once you save' : 'Off once you save';
  });
  $('#conn-filters').addEventListener('submit', (ev) => { ev.preventDefault(); state.conn.offset = 0; writeHash(); loadConnections(); });
  $('#ban-form').addEventListener('submit', (ev) => { ev.preventDefault(); submitBan(ev.target); });
  $('#ban-form').addEventListener('input', () => { $('#ban-error').textContent = ''; });
  $('#settings-form').addEventListener('submit', (ev) => { ev.preventDefault(); saveSettings(ev.target); });
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
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (current === 'connections') loadConnections(); }, 200); });

  api('/api/info').then((info) => {
    state.info = info;
    if (info.host) $$('[data-host]').forEach((el) => { el.textContent = info.host; });
  }).catch(() => {});
  show(...parseHash());
  // Live screens refresh every 30 seconds while the tab is visible; old values stay until new ones arrive.
  setInterval(() => { if (!document.hidden && SCREENS[current].live && !document.querySelector('dialog[open]')) refresh(); }, 30000);
})();
