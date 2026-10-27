'use strict';
// SkyGuard network map: containers as devices, networks as switches, memberships as cables, in the manner
// of a network simulator's logical view. Built to stay readable at a hundred containers and more:
// a force layout that keeps Compose projects together (drawn as soft hulls), pan and zoom with a minimap,
// labels that give way as you zoom out, search, and a focus mode that dims everything but one node's links.
// Positions the operator drags are pinned and remembered per browser.

window.Topology = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
  const rand = (seed) => () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const R_CT = 15; // container radius
  const SNAP = 34; // how close the free end of a cable must come to plug in

  // ── layout: a plain force simulation, deterministic for the same graph ─────
  function layout(nodes, edges, fixed) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const nets = nodes.filter((n) => n.kind !== 'ct');
    const R = 140 + 70 * Math.sqrt(nets.length);
    nets.forEach((n, i) => {
      if (n.x != null) return;
      const a = (2 * Math.PI * i) / Math.max(1, nets.length) - Math.PI / 2;
      n.x = Math.cos(a) * R; n.y = Math.sin(a) * R * 0.72;
    });
    const nbrs = new Map(nodes.map((n) => [n.id, []]));
    edges.forEach((e) => { nbrs.get(e.from).push(e.to); nbrs.get(e.to).push(e.from); });
    const loose = nodes.filter((n) => n.kind === 'ct' && !nbrs.get(n.id).length);
    nodes.forEach((n) => {
      if (n.x != null) return;
      const r = rand(hash(n.id));
      const ns = nbrs.get(n.id).map((id) => byId.get(id)).filter((m) => m.x != null);
      if (ns.length) {
        n.x = ns.reduce((a, m) => a + m.x, 0) / ns.length + (r() - 0.5) * 120;
        n.y = ns.reduce((a, m) => a + m.y, 0) / ns.length + (r() - 0.5) * 120;
      } else {
        const i = loose.indexOf(n);
        n.x = (i % 10 - 4.5) * 70; n.y = R + 120 + Math.floor(i / 10) * 70;
      }
    });
    const moving = nodes.filter((n) => !fixed.has(n.id));
    if (!moving.length) return;
    const groups = new Map();
    nodes.forEach((n) => { if (n.group) { if (!groups.has(n.group)) groups.set(n.group, []); groups.get(n.group).push(n); } });
    const big = nodes.length > 260;
    const iters = big ? 160 : 320;
    for (let it = 0; it < iters; it++) {
      const alpha = 1 - it / iters;
      nodes.forEach((n) => { n.vx = 0; n.vy = 0; });
      // repulsion (every pair; with a grid cut-off on very large graphs)
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (big && d2 > 160000) continue;
          if (d2 < 1) { dx = (hash(a.id + b.id) % 7) - 3 || 1; dy = 1; d2 = dx * dx + dy * dy; }
          const both = a.kind !== 'ct' && b.kind !== 'ct';
          const f = (both ? 9000 : 2600) / d2;
          const d = Math.sqrt(d2), fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
          const min = (a.kind === 'ct' && b.kind === 'ct') ? 52 : 70;
          if (d < min) { const push = (min - d) / 2, px = (dx / d) * push, py = (dy / d) * push; a.vx += px; a.vy += py; b.vx -= px; b.vy -= py; }
        }
      }
      // cables are springs
      edges.forEach((e) => {
        const a = byId.get(e.from), b = byId.get(e.to);
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
        const rest = 86 + Math.min(60, 4 * Math.sqrt(nbrs.get(e.to).length + nbrs.get(e.from).length));
        const f = (d - rest) * 0.06, fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      });
      // a Compose project holds together
      groups.forEach((g) => {
        if (g.length < 2) return;
        const cx = g.reduce((s, n) => s + n.x, 0) / g.length, cy = g.reduce((s, n) => s + n.y, 0) / g.length;
        g.forEach((n) => { n.vx += (cx - n.x) * 0.03; n.vy += (cy - n.y) * 0.03; });
      });
      // a little gravity keeps islands from drifting off
      nodes.forEach((n) => { n.vx -= n.x * 0.004; n.vy -= n.y * 0.004; });
      const step = 0.85 * alpha + 0.05;
      moving.forEach((n) => {
        const v = Math.sqrt(n.vx * n.vx + n.vy * n.vy), cap = 40;
        const s = v > cap ? cap / v : 1;
        n.x += n.vx * s * step; n.y += n.vy * s * step;
      });
    }
  }

  // Convex hull (monotone chain) of points, for the project outlines.
  function hull(pts) {
    if (pts.length < 3) return pts.slice();
    const p = pts.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
    const lo = [], up = [];
    for (const q of p) { while (lo.length >= 2 && cross(lo[lo.length - 2], lo[lo.length - 1], q) <= 0) lo.pop(); lo.push(q); }
    for (const q of p.reverse()) { while (up.length >= 2 && cross(up[up.length - 2], up[up.length - 1], q) <= 0) up.pop(); up.push(q); }
    return lo.slice(0, -1).concat(up.slice(0, -1));
  }

  // ── glyphs ──────────────────────────────────────────────────────────────
  // a switch: a flat box with its port row, the way a network simulator draws one
  const switchGlyph = () => `<rect class="sw-body" x="-30" y="-12" width="60" height="24" rx="4"/>${[-20, -10, 0, 10, 20].map((x) => `<rect class="sw-port" x="${x - 3}" y="-4" width="6" height="8" rx="1"/>`).join('')}`;
  const serverGlyph = () => '<rect class="sw-body" x="-22" y="-20" width="44" height="40" rx="4"/><path class="glyph" d="M-14 -9h28M-14 0h28M-14 9h28"/><circle class="led" cx="11" cy="-14" r="2"/>';
  const ctGlyph = (n) => (n.vm
    ? '<path class="glyph" d="M-7 -5h14v9h-14z M-3 7h6"/>'
    : n.engine === 'incus'
      ? '<path class="glyph" d="M-7 -6h14v12h-14z M-7 -1h14"/>'
      : '<path class="glyph" d="M0 -8 7 -4v8L0 8l-7-4v-8z M-7 -4 0 0l7-4 M0 0v8"/>');

  function create(root, opts) {
    root.innerHTML = `<svg class="topo-svg" tabindex="-1" aria-hidden="true"><defs></defs><g class="vp"><g class="l-hulls"></g><g class="l-edges"></g><g class="l-live"></g><g class="l-nodes"></g></g></svg>
      <svg class="topo-mini" aria-hidden="true"><g class="m-nodes"></g><rect class="m-view"/></svg>
      <div class="topo-tools" role="toolbar" aria-label="Map view">
        <button class="icon-btn small" type="button" data-topo="in" aria-label="Zoom in" title="Zoom in">+</button>
        <button class="icon-btn small" type="button" data-topo="out" aria-label="Zoom out" title="Zoom out">−</button>
        <button class="icon-btn small" type="button" data-topo="fit" aria-label="Fit everything" title="Fit everything"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg></button>
        <button class="icon-btn small" type="button" data-topo="relayout" aria-label="Arrange again" title="Arrange again (forget dragged positions)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="8" r="2"/><circle cx="10" cy="18" r="2"/><path d="M8 6.5 16 8M7 8l2.3 8M17 9.8 11.6 16.6"/></svg></button>
      </div>`;
    const svg = root.querySelector('.topo-svg'), vp = svg.querySelector('.vp');
    const L = { hulls: svg.querySelector('.l-hulls'), edges: svg.querySelector('.l-edges'), live: svg.querySelector('.l-live'), nodes: svg.querySelector('.l-nodes') };
    const mini = root.querySelector('.topo-mini'), miniNodes = mini.querySelector('.m-nodes'), miniView = mini.querySelector('.m-view');
    const S = { nodes: [], edges: [], byId: new Map(), view: { x: 0, y: 0, k: 1 }, sel: null, query: '', cable: null, pinned: new Set(), fitted: false, readOnly: false };

    const store = {
      load() { try { return JSON.parse(localStorage.getItem(opts.storageKey) || '{}'); } catch { return {}; } },
      save() {
        try {
          const pos = {};
          S.nodes.forEach((n) => { if (S.pinned.has(n.id)) pos[n.id] = [Math.round(n.x * 10) / 10, Math.round(n.y * 10) / 10]; });
          localStorage.setItem(opts.storageKey, JSON.stringify(pos));
        } catch { /* private mode: positions just are not remembered */ }
      },
    };

    // ── data ────────────────────────────────────────────────────────────
    function setData(data) {
      const old = S.byId, saved = store.load();
      S.readOnly = !!data.readOnly;
      S.nodes = data.nodes.map((n) => {
        const prev = old.get(n.id);
        const pos = prev ? [prev.x, prev.y] : saved[n.id];
        if (saved[n.id]) S.pinned.add(n.id);
        return Object.assign({}, n, pos ? { x: pos[0], y: pos[1] } : { x: null, y: null });
      });
      S.byId = new Map(S.nodes.map((n) => [n.id, n]));
      S.edges = data.edges.filter((e) => S.byId.has(e.from) && S.byId.has(e.to));
      const fixed = new Set(S.nodes.filter((n) => n.x != null).map((n) => n.id));
      if (fixed.size < S.nodes.length) layout(S.nodes, S.edges, fixed);
      if (S.sel && !S.byId.has(S.sel)) S.sel = null;
      render();
      if (!S.fitted) { fit(); S.fitted = true; }
    }

    function neighbours(id) {
      const out = new Set([id]);
      S.edges.forEach((e) => { if (e.from === id) out.add(e.to); if (e.to === id) out.add(e.from); });
      return out;
    }

    // a cable bends a little, always the same way for the same pair, so parallel runs do not overlap
    function edgePath(a, b, id) {
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      const bend = ((hash(id) % 21) - 10) * 0.012 * d;
      const mx = (a.x + b.x) / 2 - (dy / d) * bend, my = (a.y + b.y) / 2 + (dx / d) * bend;
      return `M${a.x.toFixed(1)} ${a.y.toFixed(1)} Q${mx.toFixed(1)} ${my.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
    }

    function nodeMarkup(n) {
      const label = `<text class="t-label" y="${n.kind === 'ct' ? R_CT + 15 : n.kind === 'host' ? 34 : 26}">${esc(n.label)}</text>`;
      const sub = n.sub ? `<text class="t-sub" y="${n.kind === 'ct' ? R_CT + 28 : n.kind === 'host' ? 47 : 39}">${esc(n.sub)}</text>` : '';
      if (n.kind === 'net') return `${switchGlyph()}${label}${sub}`;
      if (n.kind === 'host') return `${serverGlyph()}${label}${sub}`;
      const stack = n.stack ? `<circle class="ct-ring back" r="${R_CT}" cx="6" cy="-5"/><circle class="ct-ring back" r="${R_CT}" cx="3" cy="-2.5"/>` : '';
      const count = n.stack ? `<text class="t-count" x="${R_CT + 2}" y="${R_CT}">${n.stack}</text>` : '';
      const tone = n.state === 'running' ? 'pos' : ['paused', 'frozen', 'restarting'].includes(n.state) ? 'warn' : ['dead', 'error'].includes(n.state) ? 'neg' : 'off';
      return `${stack}<circle class="ct-ring" r="${R_CT}"/>${ctGlyph(n)}<circle class="st ${tone}" cx="${R_CT - 3}" cy="${-R_CT + 3}" r="3.5"/>${count}${n.self ? `<text class="t-badge" y="${-R_CT - 6}">SkyGuard</text>` : ''}${label}${sub}`;
    }

    function render() {
      const focus = S.sel ? neighbours(S.sel) : null;
      const q = S.query.toLowerCase();
      const match = (n) => !q || n.label.toLowerCase().includes(q) || (n.search || '').toLowerCase().includes(q);
      // project outlines
      const groups = new Map();
      S.nodes.forEach((n) => { if (n.group && n.kind === 'ct') { if (!groups.has(n.group)) groups.set(n.group, []); groups.get(n.group).push(n); } });
      L.hulls.innerHTML = [...groups].filter(([, ns]) => ns.length > 1).map(([g, ns]) => {
        const h = hull(ns.map((n) => [n.x, n.y]));
        const d = h.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join('') + 'Z';
        const top = ns.reduce((a, n) => (n.y < a.y ? n : a), ns[0]);
        const dim = (focus && !ns.some((n) => focus.has(n.id))) || (q && !ns.some(match));
        return `<g class="hull${dim ? ' dim' : ''}"><path d="${d}"/><text x="${top.x.toFixed(1)}" y="${(top.y - 40).toFixed(1)}">${esc(g)}</text></g>`;
      }).join('');
      L.edges.innerHTML = S.edges.map((e) => {
        const a = S.byId.get(e.from), b = S.byId.get(e.to);
        const on = focus ? focus.has(e.from) && focus.has(e.to) && (e.from === S.sel || e.to === S.sel) : true;
        const dim = !on || (q && !(match(a) || match(b)));
        return `<g class="edge${e.dead ? ' dead' : ''}${dim ? ' dim' : ''}" data-edge="${esc(e.id)}"><path class="e-hit" d="${edgePath(a, b, e.id)}"/><path class="e-line" d="${edgePath(a, b, e.id)}"/>${e.label ? `<title>${esc(e.label)}</title>` : ''}</g>`;
      }).join('');
      L.nodes.innerHTML = S.nodes.map((n) => {
        const dim = (focus && !focus.has(n.id)) || (q && !match(n));
        const cls = `tn ${n.kind}${n.state && n.state !== 'running' && n.kind === 'ct' ? ' stopped' : ''}${S.sel === n.id ? ' sel' : ''}${dim ? ' dim' : ''}${q && match(n) ? ' match' : ''}`;
        return `<g class="${cls}" data-node="${esc(n.id)}" transform="translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})">${n.title ? `<title>${esc(n.title)}</title>` : ''}${nodeMarkup(n)}</g>`;
      }).join('');
      drawHandle();
      renderMini();
      scheduleCull();
    }

    // the plug: a small handle on the selected device to pull a cable from
    function drawHandle() {
      const old = L.nodes.querySelector('.handle');
      if (old) old.remove();
      const n = S.sel && S.byId.get(S.sel);
      if (!n || S.readOnly || n.kind !== 'ct' || n.locked || S.cable) return;
      const g = document.createElementNS(NS, 'g');
      g.setAttribute('class', 'handle');
      g.setAttribute('transform', `translate(${(n.x + R_CT + 13).toFixed(1)} ${n.y.toFixed(1)})`);
      g.innerHTML = '<circle r="9"/><path d="M-4 0h8M0 -4v8"/><title>Pull a cable: drop it on a container or a network</title>';
      L.nodes.appendChild(g);
    }

    function applyView() {
      const { x, y, k } = S.view;
      vp.setAttribute('transform', `translate(${x.toFixed(1)} ${y.toFixed(1)}) scale(${k.toFixed(4)})`);
      // past 100% the type stops growing: labels keep their size on screen, as on a map
      root.style.setProperty('--ls', String(k > 1 ? 1 / k : 1));
      root.classList.toggle('lod-sub', k >= 1.15);
      root.classList.toggle('lod-tiny', k < 0.32);
      renderMiniView();
      scheduleCull();
    }
    // labels that would print over each other give way, the less important first: the selection and
    // search matches, then switches, then the best-connected devices
    let cullQueued = false;
    function scheduleCull() { if (!cullQueued) { cullQueued = true; requestAnimationFrame(() => { cullQueued = false; cull(); }); } }
    function cull() {
      const { x, y, k } = S.view, px = 12 * Math.min(1, k); // label size on screen
      const deg = new Map();
      S.edges.forEach((e) => { deg.set(e.from, (deg.get(e.from) || 0) + 1); deg.set(e.to, (deg.get(e.to) || 0) + 1); });
      const q = S.query.toLowerCase();
      const rank = (n) => (n.id === S.sel ? 0 : q && (n.label.toLowerCase().includes(q) || (n.search || '').toLowerCase().includes(q)) ? 1 : n.kind !== 'ct' ? 2 : 3);
      const order = S.nodes.slice().sort((a, b) => rank(a) - rank(b) || (deg.get(b.id) || 0) - (deg.get(a.id) || 0));
      const placed = [];
      const els = new Map([...L.nodes.querySelectorAll('[data-node]')].map((el) => [el.dataset.node, el]));
      order.forEach((n) => {
        const el = els.get(n.id);
        if (!el) return;
        const off = n.kind === 'ct' ? R_CT + 15 : n.kind === 'host' ? 34 : 26;
        const cx = n.x * k + x, cy = (n.y + off) * k + y;
        const w = n.label.length * px * 0.58 + 6, h = px + 4;
        const r = [cx - w / 2, cy - px, cx + w / 2, cy + 4];
        const hit = px < 6.5 && rank(n) > 1 || placed.some((p) => r[0] < p[2] && r[2] > p[0] && r[1] < p[3] && r[3] > p[1]);
        el.classList.toggle('nolabel', hit && rank(n) > 0);
        if (!hit || rank(n) === 0) placed.push(r);
        void h;
      });
    }

    function bounds() {
      if (!S.nodes.length) return { x0: -100, y0: -100, x1: 100, y1: 100 };
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      S.nodes.forEach((n) => { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); });
      return { x0: x0 - 60, y0: y0 - 60, x1: x1 + 60, y1: y1 + 70 };
    }
    function fit() {
      const b = bounds(), w = svg.clientWidth || 800, h = svg.clientHeight || 500;
      const k = Math.min(1.4, Math.max(0.12, Math.min(w / (b.x1 - b.x0), h / (b.y1 - b.y0))));
      S.view = { k, x: w / 2 - ((b.x0 + b.x1) / 2) * k, y: h / 2 - ((b.y0 + b.y1) / 2) * k };
      applyView();
    }
    function zoomAt(f, px, py) {
      const k = Math.min(3, Math.max(0.08, S.view.k * f));
      const r = k / S.view.k;
      S.view.x = px - (px - S.view.x) * r; S.view.y = py - (py - S.view.y) * r; S.view.k = k;
      applyView();
    }
    function centreOn(n, k) {
      const w = svg.clientWidth, h = svg.clientHeight;
      if (k) S.view.k = k;
      S.view.x = w / 2 - n.x * S.view.k; S.view.y = h / 2 - n.y * S.view.k;
      applyView();
    }

    // ── minimap ─────────────────────────────────────────────────────────
    let miniScale = 1, miniB = null;
    function renderMini() {
      const b = bounds(), W = 168, H = 108;
      miniScale = Math.min(W / (b.x1 - b.x0), H / (b.y1 - b.y0)); miniB = b;
      const p = (n) => [((n.x - b.x0) * miniScale).toFixed(1), ((n.y - b.y0) * miniScale).toFixed(1)];
      miniNodes.innerHTML = S.nodes.map((n) => { const [x, y] = p(n); return n.kind === 'ct' ? `<circle cx="${x}" cy="${y}" r="1.6"${n.state === 'running' ? '' : ' class="off"'}/>` : `<rect x="${x - 3}" y="${y - 2}" width="6" height="4" class="net"/>`; }).join('');
      root.classList.toggle('mini-on', S.nodes.length > 24);
      renderMiniView();
    }
    function renderMiniView() {
      if (!miniB) return;
      const w = svg.clientWidth, h = svg.clientHeight, { x, y, k } = S.view;
      miniView.setAttribute('x', (((-x / k) - miniB.x0) * miniScale).toFixed(1));
      miniView.setAttribute('y', (((-y / k) - miniB.y0) * miniScale).toFixed(1));
      miniView.setAttribute('width', ((w / k) * miniScale).toFixed(1));
      miniView.setAttribute('height', ((h / k) * miniScale).toFixed(1));
    }
    function miniJump(ev) {
      const r = mini.getBoundingClientRect();
      const wx = (ev.clientX - r.left) / miniScale + miniB.x0, wy = (ev.clientY - r.top) / miniScale + miniB.y0;
      centreOn({ x: wx, y: wy });
    }
    mini.addEventListener('pointerdown', (ev) => { ev.preventDefault(); mini.setPointerCapture(ev.pointerId); miniJump(ev); });
    mini.addEventListener('pointermove', (ev) => { if (mini.hasPointerCapture(ev.pointerId)) miniJump(ev); });

    // ── pointer: pan, zoom, drag a node, pull a cable ───────────────────
    const world = (ev) => { const r = svg.getBoundingClientRect(); return [(ev.clientX - r.left - S.view.x) / S.view.k, (ev.clientY - r.top - S.view.y) / S.view.k]; };
    const nodeAt = (ev) => { const el = ev.target.closest && ev.target.closest('[data-node]'); return el ? S.byId.get(el.dataset.node) : null; };
    // the free end snaps to the nearest valid target within reach
    function snapTarget(wx, wy) {
      const from = S.byId.get(S.cable.from);
      let best = null, bd = SNAP / Math.min(1, S.view.k);
      S.nodes.forEach((n) => {
        if (n.id === from.id || n.kind === 'host' || (n.kind === 'ct' && n.locked)) return;
        if (n.kind === 'net' && (n.locked || S.edges.some((e) => (e.from === from.id && e.to === n.id) || (e.to === from.id && e.from === n.id)))) return;
        const d = Math.hypot(n.x - wx, n.y - wy);
        if (d < bd) { bd = d; best = n; }
      });
      return best;
    }
    function drawCable(wx, wy) {
      const from = S.byId.get(S.cable.from), t = snapTarget(wx, wy);
      S.cable.target = t;
      const ex = t ? t.x : wx, ey = t ? t.y : wy;
      const dx = ex - from.x, sag = Math.min(60, Math.abs(dx) * 0.12 + Math.hypot(dx, ey - from.y) * 0.08 + 8);
      const d = `M${from.x.toFixed(1)} ${from.y.toFixed(1)} C${(from.x + dx * 0.3).toFixed(1)} ${(from.y + sag).toFixed(1)} ${(ex - dx * 0.3).toFixed(1)} ${(ey + sag).toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}`;
      L.live.innerHTML = `<path class="live-cable${t ? ' snapped' : ''}" d="${d}"/><circle class="live-plug" cx="${ex.toFixed(1)}" cy="${ey.toFixed(1)}" r="5"/>`;
      L.nodes.querySelectorAll('.tn.target').forEach((el) => el.classList.remove('target'));
      if (t) { const el = L.nodes.querySelector(`[data-node="${CSS.escape(t.id)}"]`); if (el) el.classList.add('target'); }
      if (opts.onCableHover) opts.onCableHover(from, t);
    }
    function startCable(id, ev) {
      if (S.readOnly) return;
      const n = S.byId.get(id);
      if (!n || n.kind !== 'ct' || n.locked) return;
      S.cable = { from: id, target: null, armed: !ev };
      root.classList.add('cabling');
      drawHandle();
      if (ev) { const [wx, wy] = world(ev); drawCable(wx, wy); } else drawCable(n.x + 80, n.y + 20);
      if (opts.onCableStart) opts.onCableStart(n);
    }
    function endCable(drop) {
      if (!S.cable) return;
      const { from, target } = S.cable;
      S.cable = null;
      L.live.innerHTML = '';
      root.classList.remove('cabling');
      L.nodes.querySelectorAll('.tn.target').forEach((el) => el.classList.remove('target'));
      drawHandle();
      if (opts.onCableEnd) opts.onCableEnd();
      if (drop && target) opts.onConnect(S.byId.get(from), target);
    }

    let drag = null; const pointers = new Map();
    svg.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0 && ev.pointerType === 'mouse') return;
      pointers.set(ev.pointerId, [ev.clientX, ev.clientY]);
      svg.setPointerCapture(ev.pointerId);
      if (pointers.size === 2) { drag = { pinch: true, d0: dist(), k0: S.view.k }; return; }
      if (S.cable && S.cable.armed) return; // click-to-target: the click on pointerup decides
      if (ev.target.closest('.handle')) { startCable(S.sel, ev); drag = { cable: true, x: ev.clientX, y: ev.clientY, moved: false }; return; }
      const n = nodeAt(ev), edgeEl = ev.target.closest && ev.target.closest('[data-edge]');
      drag = n ? { node: n, x: ev.clientX, y: ev.clientY, moved: false }
        : { pan: true, edge: edgeEl ? edgeEl.dataset.edge : null, x: ev.clientX, y: ev.clientY, vx: S.view.x, vy: S.view.y, moved: false };
    });
    const dist = () => { const [a, b] = [...pointers.values()]; return Math.hypot(a[0] - b[0], a[1] - b[1]); };
    svg.addEventListener('pointermove', (ev) => {
      if (pointers.has(ev.pointerId)) pointers.set(ev.pointerId, [ev.clientX, ev.clientY]);
      if (S.cable) { const [wx, wy] = world(ev); drawCable(wx, wy); if (drag && drag.cable && Math.hypot(ev.clientX - drag.x, ev.clientY - drag.y) > 4) drag.moved = true; return; }
      if (!drag) return;
      if (drag.pinch && pointers.size === 2) { const r = svg.getBoundingClientRect(), [a, b] = [...pointers.values()]; zoomAt((drag.k0 * dist() / drag.d0) / S.view.k, (a[0] + b[0]) / 2 - r.left, (a[1] + b[1]) / 2 - r.top); return; }
      const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
      if (!drag.moved && Math.hypot(dx, dy) < 4) return;
      drag.moved = true;
      if (drag.pan) { S.view.x = drag.vx + dx; S.view.y = drag.vy + dy; applyView(); root.classList.add('panning'); return; }
      if (drag.node) {
        const [wx, wy] = world(ev);
        drag.node.x = wx; drag.node.y = wy; S.pinned.add(drag.node.id);
        moveNode(drag.node);
      }
    });
    function moveNode(n) {
      const el = L.nodes.querySelector(`[data-node="${CSS.escape(n.id)}"]`);
      if (el) el.setAttribute('transform', `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`);
      S.edges.forEach((e) => {
        if (e.from !== n.id && e.to !== n.id) return;
        const g = L.edges.querySelector(`[data-edge="${CSS.escape(e.id)}"]`);
        if (g) { const d = edgePath(S.byId.get(e.from), S.byId.get(e.to), e.id); g.querySelectorAll('path').forEach((p) => p.setAttribute('d', d)); }
      });
      drawHandle();
    }
    svg.addEventListener('pointerup', (ev) => {
      pointers.delete(ev.pointerId);
      root.classList.remove('panning');
      if (S.cable) {
        if (S.cable.armed) { endCable(true); drag = null; return; }      // second click of click-to-target
        if (drag && drag.cable && !drag.moved) { S.cable.armed = true; drag = null; return; } // a click on the handle: cable follows until the next click
        endCable(true); drag = null; return;                               // drag-and-drop
      }
      const d = drag; drag = null;
      if (!d || d.pinch) return;
      if (d.node && d.moved) { store.save(); render(); return; }
      if (d.moved) return;
      // pointer capture retargets click and dblclick, so both are read from the pointer here
      const now = Date.now(), id = d.node ? d.node.id : '';
      const double = lastClick && lastClick.id === id && now - lastClick.t < 380;
      lastClick = { id, t: now };
      if (d.edge && opts.onEdge) { const e = S.edges.find((x) => x.id === d.edge); if (e) { opts.onEdge(e); return; } }
      if (double) { if (d.node && opts.onOpen) opts.onOpen(d.node); else if (!d.node) fit(); return; }
      select(id || null);
      if (opts.onSelect) opts.onSelect(d.node || null);
    });
    let lastClick = null;
    svg.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const r = svg.getBoundingClientRect();
      zoomAt(Math.exp(-ev.deltaY * (ev.ctrlKey ? 0.01 : 0.0015)), ev.clientX - r.left, ev.clientY - r.top);
    }, { passive: false });
    root.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-topo]');
      if (!b) return;
      const w = svg.clientWidth / 2, h = svg.clientHeight / 2;
      if (b.dataset.topo === 'in') zoomAt(1.3, w, h);
      if (b.dataset.topo === 'out') zoomAt(1 / 1.3, w, h);
      if (b.dataset.topo === 'fit') fit();
      if (b.dataset.topo === 'relayout') relayout();
    });
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && S.cable) { ev.preventDefault(); endCable(false); } });
    new ResizeObserver(() => renderMiniView()).observe(svg);

    function select(id) { S.sel = id; render(); }
    function relayout() {
      S.pinned.clear(); store.save();
      S.nodes.forEach((n) => { n.x = null; n.y = null; });
      layout(S.nodes, S.edges, new Set());
      render(); fit();
    }
    // search: matches keep their colour and the rest steps back; the first match comes into view
    function search(q) {
      S.query = q.trim();
      render();
      const qq = S.query.toLowerCase();
      const first = qq && S.nodes.find((n) => n.label.toLowerCase().includes(qq) || (n.search || '').toLowerCase().includes(qq));
      if (first) centreOn(first, Math.max(S.view.k, 0.9));
      return S.nodes.filter((n) => !qq || n.label.toLowerCase().includes(qq) || (n.search || '').toLowerCase().includes(qq)).length;
    }
    return { setData, select, search, fit, relayout, startCable: (id) => startCable(id, null), cancelCable: () => endCable(false), focus: (id) => { const n = S.byId.get(id); if (n) { select(id); centreOn(n, Math.max(S.view.k, 0.9)); } }, get selected() { return S.sel; } };
  }

  return { create, _layout: layout, _hull: hull };
})();
