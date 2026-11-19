'use strict';
/* NetMonitor UI. Talks to the Rust backend through invoke('api', {path, body}). */
const T = window.__TAURI__;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api = (path, body) => T ? T.core.invoke('api', {path, body: body ?? null}) : Promise.reject('sin Tauri');
const DPR = () => window.devicePixelRatio || 1;
const COL = {down:'#5AA9FF', up:'#FFA94D', ok:'#3DD68C', warn:'#F5C451', bad:'#FF6B6B', line:'#1E232B', mute:'#8D96A6', dim:'#5D6675'};
const REGION = (() => { try { return new Intl.DisplayNames(['es'], {type: 'region'}); } catch { return null; } })();
const country = cc => { try { return (cc && REGION && REGION.of(cc)) || cc || '—'; } catch { return cc; } };

/* ================================================================ format */
function rate(Bps) {
  const b = (Bps || 0) * 8;
  if (b >= 1e9) return [(b / 1e9).toFixed(2), 'Gb/s'];
  if (b >= 1e6) return [(b / 1e6).toFixed(b >= 1e8 ? 0 : 1), 'Mb/s'];
  if (b >= 1e3) return [(b / 1e3).toFixed(b >= 1e5 ? 0 : 1), 'kb/s'];
  return [Math.round(b).toString(), 'b/s'];
}
const rateT = x => rate(x).join(' ');
function bytes(n) {
  n = n || 0; const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n >= 100 ? 0 : 1) : n) + ' ' + u[i];
}
function ago(ms) {
  if (!ms) return '—';
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 45) return 'ahora';
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} d`;
}
function dur(s) {
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} d`;
}
const hhmm = t => new Date(t).toLocaleTimeString('es-ES', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
const dateT = (t, withTime = true) => new Date(t).toLocaleString('es-ES', withTime ? {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'} : {weekday:'short', day:'numeric', month:'short'});

/* ================================================================ canvas helpers */
function fit(cv) {
  const r = cv.getBoundingClientRect(), d = DPR();
  const w = Math.max(1, Math.round(r.width * d)), h = Math.max(1, Math.round(r.height * d));
  if (cv.width !== w || cv.height !== h) { cv.width = w; cv.height = h; }
  const ctx = cv.getContext('2d'); ctx.setTransform(d, 0, 0, d, 0, 0);
  return [ctx, r.width, r.height];
}
function smooth(ctx, pts, move = true) {
  if (!pts.length) return;
  if (move) ctx.moveTo(pts[0][0], pts[0][1]); else ctx.lineTo(pts[0][0], pts[0][1]);
  for (let i = 1; i < pts.length; i++) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], mx = (x0 + x1) / 2;
    ctx.bezierCurveTo(mx, y0, mx, y1, x1, y1);
  }
}
function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p;
}
function hoverOn(boxId) {
  const st = {x: null, y: null};
  const b = $(boxId);
  b.addEventListener('mousemove', e => { const r = b.getBoundingClientRect(); st.x = e.clientX - r.left; st.y = e.clientY - r.top; });
  b.addEventListener('mouseleave', () => { st.x = st.y = null; });
  return st;
}
function tip(el, html, x, y, w) {
  if (html == null) { el.style.opacity = 0; return; }
  el.innerHTML = html; el.style.opacity = 1;
  el.style.left = Math.max(0, Math.min(w - el.offsetWidth - 4, x + 14)) + 'px';
  el.style.top = Math.max(0, y) + 'px';
}
function spark(cv, vals, col, fixedMax) {
  const [ctx, w, h] = fit(cv); ctx.clearRect(0, 0, w, h);
  const good = vals.filter(x => x != null); if (good.length < 2) return;
  const mx = fixedMax || Math.max(...good) * 1.15 || 1;
  const P = []; vals.forEach((x, i) => { if (x != null) P.push([i / (vals.length - 1) * w, h - 2 - Math.min(1, x / mx) * (h - 4)]); });
  const g = ctx.createLinearGradient(0, 0, 0, h); g.addColorStop(0, col + '40'); g.addColorStop(1, col + '00');
  ctx.beginPath(); ctx.moveTo(P[0][0], h); smooth(ctx, P, false); ctx.lineTo(P[P.length - 1][0], h); ctx.closePath(); ctx.fillStyle = g; ctx.fill();
  ctx.beginPath(); smooth(ctx, P); ctx.strokeStyle = col; ctx.lineWidth = 1.4; ctx.stroke();
}

/* ================================================================ state */
const S = {
  view: 'live',
  hist: [], rt: [], rate: null, ping: {gw: [], net: []}, router: {devices: [], ok: false, blocked: []},
  lan: [], conns: [], listen: [], procRates: null, elevated: false, ifc: {}, pub: null, pubCc: null,
  seenConn: new Set(), firstConns: true, devUp: new Map(), toasted: new Set(),
  sort: 'rate', editing: null, routerErr: null,
  H: null, hRange: '24h', speed: null, dns: null, dFilter: 'all', exposure: null, alerts: [], seenAlerts: 0, cfg: null, upd: null,
};
const WINDOW = 15 * 60 * 1000;

/* ================================================================ devices: names, kinds, colours */
const PAL = ['#4FD1C5','#B39DFF','#6FD08C','#FF7AA8','#E9C46A','#F28B66','#7FB4FF','#D9A6FF','#9BD45E','#FFB38A','#8FA3BF','#5EC9E8'];
const COLORS = new Map();
function colorOf(mac) {
  if (mac === 'PC') return '#8FA3BF';
  if (!COLORS.has(mac)) {
    let h = 0; for (const c of mac || '') h = (h * 31 + c.charCodeAt(0)) >>> 0;
    const used = new Set(COLORS.values());
    let pick = PAL[h % PAL.length];
    for (let i = 0; i < PAL.length; i++) { const c = PAL[(h + i) % PAL.length]; if (!used.has(c)) { pick = c; break; } }
    COLORS.set(mac, pick);
  }
  return COLORS.get(mac);
}
const realName = s => (s && !/^(unknown|desconocido|\*|-)$/i.test(String(s).trim())) ? s : '';
function nameOf(d) {
  if (!d) return '—';
  return d.label || realName(d.rname) || realName(d.name) || realName(d.auto) || d.h || (d.me ? 'Este PC' : d.gw ? 'Router' : d.vendor ? `Dispositivo ${d.vendor}` : 'Desconocido');
}
function kindOf(d) {
  const s = `${d.label || ''} ${d.rname || ''} ${d.name || ''} ${d.h || ''} ${d.auto || ''} ${d.vendor || ''} ${d.model || ''}`.toLowerCase();
  if (d.gw || /router|archer|gateway/.test(s)) return 'router';
  if (d.me || /\bpc\b|desktop|laptop|port[aá]til|ordenador/.test(s)) return 'pc';
  if (/repetidor|repeater|re\d{3}|extender|mesh/.test(s)) return 'wifi';
  if (/\btv\b|televisor|chromecast|fire ?stick|roku|sei box|android ?tv|bravia|smart ?tv/.test(s)) return 'tv';
  if (/enchufe|plug|meross|shelly|tapo|sonoff|bombilla|bulb|espressif|tuya/.test(s)) return 'plug';
  if (/robot|roomba|irobot|aspirador|vacuum/.test(s)) return 'robot';
  if (/m[oó]vil|phone|pixel|iphone|oneplus|galaxy|xiaomi|redmi|android|ipad|tablet/.test(s)) return 'phone';
  return 'unk';
}
const GLYPH = {
  router:'<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 13 5 6M17 13l2-7"/><path d="M7 16.5h.01M10.5 16.5h.01"/>',
  pc:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  phone:'<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M11 18.5h2"/>',
  tv:'<rect x="2.5" y="5" width="19" height="12.5" rx="2"/><path d="M8 21h8"/>',
  plug:'<path d="M9 2.5v5M15 2.5v5"/><path d="M6.5 7.5h11v3.5a5.5 5.5 0 0 1-11 0z"/><path d="M12 16.5v5"/>',
  robot:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="9" r="2.2"/><path d="M7 15.5h10"/>',
  wifi:'<path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M9 16a4.5 4.5 0 0 1 6 0"/><path d="M12 19.5h.01"/>',
  unk:'<circle cx="12" cy="12" r="9"/><path d="M9.6 9.2a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.6M12 17h.01"/>',
};
const glyph = k => `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${GLYPH[k]}</svg>`;
const ICON_BLOCK = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>';

function devMap() {
  const m = new Map();
  for (const d of S.lan) m.set(d.mac, {...d});
  for (const r of S.router.devices) if (!m.has(r.mac)) m.set(r.mac, {mac: r.mac, ip: r.ip, name: r.name, label: r.label, up: true});
  for (const r of S.router.devices) { const d = m.get(r.mac); if (d && !d.rname) d.rname = r.name; }
  [...m.keys()].sort().forEach(colorOf);
  return m;
}
function devName(mac) { if (mac === 'PC') return 'Este PC (total, IPv4+IPv6)'; return nameOf(devMap().get(mac) || {mac}); }

/* ================================================================ modal / toast / activity */
function confirmBox(title, text, yes = 'Aceptar') {
  return new Promise(res => {
    $('mT').textContent = title; $('mP').textContent = text; $('mYes').textContent = yes;
    $('modal').classList.add('on');
    const done = v => { $('modal').classList.remove('on'); $('mYes').onclick = $('mNo').onclick = null; res(v); };
    $('mYes').onclick = () => done(true); $('mNo').onclick = () => done(false);
  });
}
function toast(title, body, kind = '') {
  const el = document.createElement('div'); el.className = 'toast ' + kind;
  el.innerHTML = `<b>${esc(title)}</b>${esc(body)}`; $('toasts').append(el);
  setTimeout(() => el.remove(), 7000);
}
function logEv(kind, html, t = Date.now()) {
  const col = {conn: COL.down, lan: COL.ok, off: COL.dim, warn: COL.warn, bad: COL.bad}[kind] || COL.mute;
  const el = document.createElement('div'); el.className = 'ev fresh';
  el.innerHTML = `<span class="t">${hhmm(t).slice(0, 5)}</span><i class="k" style="background:${col}"></i><span class="x">${html}</span>`;
  const box = $('log'); box.prepend(el);
  while (box.children.length > 250) box.lastChild.remove();
}

/* ================================================================ LIVE: main chart */
const mainH = hoverOn('mainBox');
function drawMain() {
  const [ctx, w, h] = fit($('main'));
  ctx.clearRect(0, 0, w, h);
  const now = Date.now(), t0 = now - WINDOW;
  const pts = S.hist.filter(p => p[0] >= t0);
  const padL = 58, padR = 6, padT = 8, padB = 22;
  const mid = padT + (h - padT - padB) * 0.62;
  const hD = mid - padT - 4, hU = h - padB - mid - 4;
  const mxD = niceMax(Math.max(...pts.map(p => p[1]), 1e4) * 1.1);
  const mxU = niceMax(Math.max(...pts.map(p => p[2]), 1e4) * 1.1);
  const X = t => padL + (t - t0) / WINDOW * (w - padL - padR);
  ctx.font = '11px Segoe UI, sans-serif'; ctx.textBaseline = 'middle'; ctx.textAlign = 'right';
  ctx.strokeStyle = COL.line; ctx.lineWidth = 1;
  for (const f of [0.5, 1]) {
    const yd = mid - 4 - hD * f, yu = mid + 4 + hU * f;
    ctx.beginPath(); ctx.moveTo(padL, yd); ctx.lineTo(w - padR, yd); ctx.moveTo(padL, yu); ctx.lineTo(w - padR, yu); ctx.stroke();
    ctx.fillStyle = COL.dim; ctx.fillText(rateT(mxD * f), padL - 8, yd); ctx.fillText(rateT(mxU * f), padL - 8, yu);
  }
  ctx.strokeStyle = '#2A313B'; ctx.beginPath(); ctx.moveTo(padL, mid); ctx.lineTo(w - padR, mid); ctx.stroke();
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic'; ctx.fillStyle = COL.dim;
  for (let m = 15; m >= 0; m -= 5) ctx.fillText(m ? `−${m} min` : 'ahora', Math.min(w - 22, Math.max(padL + 18, X(now - m * 60000))), h - 5);
  if (pts.length < 2) return;
  const series = (idx, sign, mx, hh, col) => {
    const P = pts.map(p => [X(p[0]), mid + sign * (4 + Math.min(1, p[idx] / mx) * hh)]);
    const g = ctx.createLinearGradient(0, mid, 0, mid + sign * hh);
    g.addColorStop(0, col + '08'); g.addColorStop(1, col + '55');
    ctx.beginPath(); ctx.moveTo(P[0][0], mid + sign * 4); smooth(ctx, P, false); ctx.lineTo(P[P.length - 1][0], mid + sign * 4); ctx.closePath();
    ctx.fillStyle = g; ctx.fill();
    ctx.beginPath(); smooth(ctx, P); ctx.strokeStyle = col; ctx.lineWidth = 1.6; ctx.stroke();
    const L = P[P.length - 1];
    ctx.beginPath(); ctx.arc(L[0], L[1], 3.2, 0, 7); ctx.fillStyle = col; ctx.fill();
  };
  series(1, -1, mxD, hD, COL.down);
  series(2, 1, mxU, hU, COL.up);
  if (mainH.x != null && mainH.x > padL) {
    const t = t0 + (mainH.x - padL) / (w - padL - padR) * WINDOW;
    let best = pts[0]; for (const p of pts) if (Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
    const x = X(best[0]);
    ctx.strokeStyle = 'rgba(230,233,239,.25)'; ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, h - padB); ctx.stroke();
    tip($('mainTip'), `<span class="mute">${hhmm(best[0])}</span><br><span class="c-down">↓ ${rateT(best[1])}</span> &nbsp; <span class="c-up">↑ ${rateT(best[2])}</span>`, x, 6, w);
  } else tip($('mainTip'), null);
}

/* ================================================================ LIVE: streamgraph */
const streamH = hoverOn('streamBox');
function drawStream() {
  const [ctx, w, h] = fit($('stream')); ctx.clearRect(0, 0, w, h);
  const now = Date.now(), span = 10 * 60 * 1000, t0 = now - span;
  const smp = S.rt.filter(s => s.t >= t0);
  if (smp.length < 2) {
    ctx.fillStyle = COL.dim; ctx.font = '13px Segoe UI, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText(S.router.ok ? 'Reuniendo datos del router…' : (S.router.error || 'Sin datos del router'), w / 2, h / 2);
    $('streamLeg').innerHTML = ''; return;
  }
  const tot = {};
  for (const s of smp) for (const [m, [a, b]] of Object.entries(s.d)) tot[m] = (tot[m] || 0) + a + b;
  const macs = Object.keys(tot).filter(m => tot[m] > 0).sort((a, b) => tot[b] - tot[a]);
  const X = t => (t - t0) / span * w;
  const v = (s, m) => (s.d[m] || [0, 0])[0] + (s.d[m] || [0, 0])[1];
  const sums = smp.map(s => macs.reduce((acc, m) => acc + v(s, m), 0));
  const mx = Math.max(...sums, 2e4) * 1.08;
  const H = h - 20, mid = H / 2, K = x => x / mx * H;
  const base = smp.map((s, i) => mid - K(sums[i]) / 2);
  const acc = smp.map(() => 0);
  const byMac = devMap();
  let hit = null;
  for (const m of macs) {
    const top = [], bot = [];
    smp.forEach((s, i) => {
      const y0 = base[i] + K(acc[i]); acc[i] += v(s, m); const y1 = base[i] + K(acc[i]);
      top.push([X(s.t), y0]); bot.push([X(s.t), y1]);
    });
    ctx.beginPath(); smooth(ctx, top); smooth(ctx, bot.slice().reverse(), false); ctx.closePath();
    ctx.fillStyle = colorOf(m) + 'CC'; ctx.fill();
    ctx.strokeStyle = 'rgba(11,13,16,.55)'; ctx.lineWidth = 1; ctx.stroke();
    if (streamH.x != null && !hit && ctx.isPointInPath(streamH.x * DPR(), streamH.y * DPR())) hit = m;
  }
  ctx.fillStyle = COL.dim; ctx.font = '11px Segoe UI, sans-serif'; ctx.textAlign = 'center';
  for (let m = 10; m >= 0; m -= 5) ctx.fillText(m ? `−${m} min` : 'ahora', Math.min(w - 20, Math.max(22, X(now - m * 60000))), h - 4);
  const all = macs.reduce((a, m) => a + tot[m], 0) || 1;
  if (hit) {
    const last = S.router.devices.find(x => x.mac === hit) || {};
    tip($('streamTip'), `<b>${esc(nameOf(byMac.get(hit) || {mac: hit}))}</b><br><span class="c-down">↓ ${rateT(last.rateRx)}</span> &nbsp; <span class="c-up">↑ ${rateT(last.rateTx)}</span><br><span class="mute">${Math.round(tot[hit] / all * 100)}% del tráfico en 10 min</span>`, streamH.x, streamH.y - 20, w);
  } else tip($('streamTip'), null);
  $('streamLeg').innerHTML = macs.slice(0, 10).map(m => `<span><i style="background:${colorOf(m)}"></i>${esc(nameOf(byMac.get(m) || {mac: m}))} <span class="dim num">${Math.round(tot[m] / all * 100)}%</span></span>`).join('');
}

/* ================================================================ LIVE: devices */
function devHist(mac) { return S.rt.slice(-200).map(s => { const v = s.d[mac]; return v ? v[0] + v[1] : 0; }); }
function renderDevices() {
  if (S.editing) return;
  const rmap = new Map(S.router.devices.map(r => [r.mac, r]));
  const blocked = new Set(S.router.blocked || []);
  const list = [...devMap().values()];
  const val = d => { const r = rmap.get(d.mac); return r ? r.rateRx + r.rateTx : 0; };
  const ipn = d => (d.ip || '0.0.0.0').split('.').reduce((a, x) => a * 256 + (+x || 0), 0);
  list.sort(S.sort === 'rate' ? (a, b) => (val(b) - val(a)) || ((b.up !== false) - (a.up !== false)) || (ipn(a) - ipn(b)) : (a, b) => ipn(a) - ipn(b));
  const mx = Math.max(...list.map(d => { const r = rmap.get(d.mac); return r ? Math.max(r.rateRx, r.rateTx) : 0; }), 125000);
  const up = list.filter(d => d.up !== false).length, unk = list.filter(d => !d.known && !d.me && !d.gw).length;
  $('devSub').textContent = `${up} activos de ${list.length}` + (unk ? ` · ${unk} sin identificar` : '');
  $('nDev').innerHTML = `${up}<small>/ ${list.length}</small>`;
  $('nDevS').textContent = unk ? `${unk} sin identificar` : 'todos identificados';
  $('devs').innerHTML = list.map(d => {
    const r = rmap.get(d.mac), on = d.up !== false, blk = blocked.has(d.mac) || d.blocked;
    const w = v => Math.min(100, Math.sqrt((v || 0) / mx) * 100).toFixed(1);
    const nm = nameOf(d);
    const extra = [d.vendor, d.model, (realName(d.auto) && d.auto !== nm) ? d.auto : '', (d.h && d.h !== nm) ? d.h : ''].filter(Boolean);
    const sub = [d.ip ? `<span class="mono">${esc(d.ip)}</span>` : '', esc([...new Set(extra)].join(' · ')), `<span class="mono dim">${esc(d.mac)}</span>`].filter(Boolean).join(' · ');
    const tags = (blk ? '<span class="tag bad">Bloqueado</span>' : '') + (d.new ? '<span class="tag new">Nuevo</span>' : '') + (!d.known && !d.me && !d.gw ? '<span class="tag warn">Sin identificar</span>' : '') + (d.randomMac ? '<span class="tag" title="MAC aleatoria (privacidad del móvil)">MAC aleatoria</span>' : '');
    const canBlock = !d.me && !d.gw;
    return `<div class="dv ${on ? '' : 'off'} ${blk ? 'blk' : ''}">
      <div class="gl" style="color:${colorOf(d.mac)}">${glyph(kindOf(d))}<i class="sd ${on ? 'on' : ''}"></i></div>
      <div class="nm"><div class="n"><span class="t" data-mac="${esc(d.mac)}" title="Clic para renombrar">${esc(nm)}</span>${tags}</div>
        <div class="m">${sub}${on ? '' : ` · <span class="dim">${d.last ? 'visto ' + ago(d.last) : 'inactivo'}</span>`}</div></div>
      <div class="rt">${r ? `
        <div class="row"><span class="c-down" style="text-align:left">↓</span><div class="tr"><i style="width:${w(r.rateRx)}%;background:var(--down)"></i></div><span class="num">${rateT(r.rateRx)}</span></div>
        <div class="row"><span class="c-up" style="text-align:left">↑</span><div class="tr"><i style="width:${w(r.rateTx)}%;background:var(--up)"></i></div><span class="num">${rateT(r.rateTx)}</span></div>`
        : `<div class="dim" style="font-size:12px">${d.me ? 'ver gráfico principal' : 'sin datos del router'}</div>`}</div>
      <canvas class="spk" data-mac="${esc(d.mac)}"></canvas>
      ${canBlock ? `<button class="act ${blk ? 'unb' : ''}" data-block="${esc(d.mac)}" data-on="${blk ? 0 : 1}" title="${blk ? 'Desbloquear' : 'Bloquear en el router'}">${ICON_BLOCK}</button>` : '<span></span>'}
    </div>`;
  }).join('');
  document.querySelectorAll('.spk').forEach(cv => { const h = devHist(cv.dataset.mac); spark(cv, h, colorOf(cv.dataset.mac), Math.max(50000, ...h) * 1.15); });
}
$('devs').addEventListener('click', async e => {
  const b = e.target.closest('[data-block]');
  if (b) return blockFlow(b.dataset.block, b.dataset.on === '1');
  const t = e.target.closest('span.t'); if (!t || S.editing) return;
  const mac = t.dataset.mac, d = devMap().get(mac) || {};
  S.editing = mac;
  const inp = document.createElement('input'); inp.value = d.label || ''; inp.placeholder = nameOf(d);
  t.replaceWith(inp); inp.focus(); inp.select();
  const done = async save => {
    if (!S.editing) return; S.editing = null;
    if (save) { try { await api('known', {mac, label: inp.value}); } catch {} await pollLan(); }
    renderDevices();
  };
  inp.addEventListener('keydown', ev => { if (ev.key === 'Enter') done(true); if (ev.key === 'Escape') done(false); });
  inp.addEventListener('blur', () => done(true));
});
async function blockFlow(mac, block) {
  const name = devName(mac);
  const ok = await confirmBox(block ? `¿Bloquear ${name}?` : `¿Desbloquear ${name}?`,
    block ? 'El router le cortará el acceso a internet (control de acceso, lista negra) hasta que lo desbloquees aquí o en la web del router.'
          : 'Volverá a tener acceso a internet.', block ? 'Bloquear' : 'Desbloquear');
  if (!ok) return;
  toast(block ? 'Bloqueando…' : 'Desbloqueando…', name);
  try {
    const r = await api('block', {mac, name, block});
    if (r.ok) toast(block ? 'Bloqueado' : 'Desbloqueado', name, 'ok'); else toast('No se pudo', r.error || 'error', 'bad');
  } catch (e) { toast('No se pudo', String(e), 'bad'); }
  pollRouter(); pollLan(); if (S.view === 'sec') loadSec();
}
$('devSort').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  S.sort = b.dataset.k; [...$('devSort').children].forEach(x => x.classList.toggle('on', x === b)); renderDevices();
});

/* ================================================================ LIVE: tables */
function renderConns() {
  const q = $('filter').value.trim().toLowerCase();
  const rows = S.conns.filter(x => !q || `${x.p} ${x.ra} ${x.h} ${x.rp} ${x.cc || ''} ${country(x.cc)}`.toLowerCase().includes(q))
    .sort((a, b) => (a.lan - b.lan) || a.p.localeCompare(b.p) || (a.h || a.ra).localeCompare(b.h || b.ra));
  $('connSub').textContent = q ? `${rows.length} de ${S.conns.length}` : `${S.conns.length} establecidas`;
  $('conns').innerHTML = rows.map(x => `<tr><td><b>${esc(x.p)}</b></td><td title="${esc(x.ra)}">${x.h ? esc(x.h) + ` <span class="mono dim">${esc(x.ra)}</span>` : `<span class="mono">${esc(x.ra)}</span>`}</td><td class="hide-n">${x.cc ? `<span class="tag cc" title="${esc(country(x.cc))}">${esc(x.cc)}</span>` : ''}</td><td class="hide-n mono">${x.rp}</td><td>${x.lan ? '<span class="tag">LAN</span>' : '<span class="tag ok">Internet</span>'}${x.v6 ? ' <span class="dim" style="font-size:11px">v6</span>' : ''}</td></tr>`).join('')
    || `<tr><td colspan="5" class="empty">Sin coincidencias</td></tr>`;
}
$('filter').addEventListener('input', renderConns);
function renderProcs() {
  const g = new Map();
  for (const x of S.conns) {
    const e = g.get(x.p) || {n: 0, hosts: new Map(), rx: 0, tx: 0};
    e.n++;
    const h = x.h ? x.h.split('.').slice(-3).join('.') : x.ra;
    e.hosts.set(h, (e.hosts.get(h) || 0) + 1); g.set(x.p, e);
  }
  const rates = S.procRates || [];
  for (const r of rates) { const e = g.get(r.p) || {n: 0, hosts: new Map(), rx: 0, tx: 0}; e.rx = r.rx; e.tx = r.tx; g.set(r.p, e); }
  const byRate = S.elevated;
  const list = [...g.entries()].sort((a, b) => byRate ? (b[1].rx + b[1].tx) - (a[1].rx + a[1].tx) || b[1].n - a[1].n : b[1].n - a[1].n);
  const mx = Math.max(1, ...list.map(([, e]) => byRate ? e.rx + e.tx : e.n));
  $('procSub').textContent = `${list.length} programas`;
  $('procs').innerHTML = list.slice(0, 14).map(([p, e]) => {
    const hosts = [...e.hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([h]) => esc(h)).join(' · ');
    const right = byRate ? `<span class="c-down">↓ ${rateT(e.rx)}</span> · <span class="c-up">↑ ${rateT(e.tx)}</span>` : `${e.n} conexión${e.n > 1 ? 'es' : ''}`;
    const bar = byRate ? `<i style="width:${e.rx / mx * 100}%;background:var(--down)"></i><i style="width:${e.tx / mx * 100}%;background:var(--up)"></i>` : `<i style="width:${e.n / mx * 100}%;background:linear-gradient(90deg,var(--down),#8AC3FF)"></i>`;
    return `<div class="pr"><div class="n">${esc(p)}</div><div class="c num">${right}</div><div class="b">${bar}</div><div class="h">${hosts}${byRate && e.n ? ` · ${e.n} conex.` : ''}</div></div>`;
  }).join('') || '<div class="empty">Sin conexiones</div>';
  $('procNote').innerHTML = S.elevated ? 'Bytes por programa medidos con las estadísticas TCP de Windows (solo TCP).'
    : 'Ordenado por número de conexiones. Para ver los bytes por programa, <a href="#" id="lnkElev" style="color:var(--down)">reinicia como administrador</a>.';
  const l = $('lnkElev'); if (l) l.onclick = e => { e.preventDefault(); elevFlow(); };
}

/* ================================================================ LIVE: polling */
async function pollRate() {
  try {
    const r = await api('rate'); S.rate = r;
    if (r.t && (!S.hist.length || r.t > S.hist[S.hist.length - 1][0])) S.hist.push([r.t, r.rx, r.tx]);
    while (S.hist.length && S.hist[0][0] < Date.now() - WINDOW - 5000) S.hist.shift();
    const a = rate(r.rx), b = rate(r.tx);
    $('vDown').innerHTML = `${a[0]}<small>${a[1]}</small>`; $('vUp').innerHTML = `${b[0]}<small>${b[1]}</small>`;
    $('pDown').textContent = rateT(Math.max(...S.hist.map(p => p[1]), 0));
    $('pUp').textContent = rateT(Math.max(...S.hist.map(p => p[2]), 0));
    $('sDown').textContent = bytes(r.sessRx); $('sUp').textContent = bytes(r.sessTx);
  } catch {}
}
async function pollPing() {
  try {
    const p = await api('ping'); S.ping = p;
    const show = (arr, id, sid, cv, col, base) => {
      const ok = arr.filter(x => x != null), last = arr[arr.length - 1];
      $(id).innerHTML = last == null ? '<span style="color:var(--bad)">sin respuesta</span>' : `${last.toFixed(1)}<small>ms</small>`;
      if (ok.length > 2) {
        const avg = ok.reduce((a, b) => a + b, 0) / ok.length;
        const jit = ok.slice(1).reduce((a, x, i) => a + Math.abs(x - ok[i]), 0) / (ok.length - 1);
        const loss = Math.round((arr.length - ok.length) / arr.length * 100);
        $(sid).textContent = `${base}media ${avg.toFixed(1)} · jitter ${jit.toFixed(1)}${loss ? ` · ${loss}% perdidos` : ''}`;
      }
      spark($(cv), arr.slice(-45), col);
    };
    show(p.gw, 'lGw', 'lGwS', 'kGw', COL.ok, '');
    show(p.net, 'lNet', 'lNetS', 'kNet', COL.warn, '');
    const last = p.net[p.net.length - 1];
    $('sNet').className = 'dot ' + (last == null ? 'bad' : last > 80 ? 'warn' : 'ok');
  } catch {}
}
async function pollRouter() {
  try {
    const r = await api('router'); S.router = r;
    if (r.ok && r.t && (!S.rt.length || r.t > S.rt[S.rt.length - 1].t)) {
      const d = {}; for (const x of r.devices) d[x.mac] = [x.rateRx, x.rateTx];
      S.rt.push({t: r.t, d}); while (S.rt.length > 220) S.rt.shift();
    }
    $('sRouter').className = 'dot ' + (r.ok && r.enabled ? 'ok' : r.ok ? 'warn' : 'bad');
    const err = r.ok ? (r.enabled ? null : r.error) : r.error;
    if (err !== S.routerErr) { if (err) logEv('warn', 'Router: ' + esc(err)); else if (S.routerErr) logEv('lan', 'Router: conectado'); S.routerErr = err; }
    $('devNote').textContent = err ? `Router: ${err}` : 'Tráfico por dispositivo del monitor del router (solo IPv4). Clic en un nombre para renombrarlo; el icono de la derecha lo bloquea.';
    renderDevices();
  } catch {}
}
async function pollLan() {
  try {
    const l = await api('lan'); S.lan = l.devices;
    $('sLan').className = 'dot ' + (l.lastScan ? 'ok' : '');
    $('sLanT').textContent = l.scanning ? 'Escaneando…' : 'Red local';
    for (const d of l.devices) {
      const prev = S.devUp.get(d.mac);
      if (prev !== undefined && prev !== d.up && d.last != null) logEv(d.up ? 'lan' : 'off', `${esc(nameOf(d))} ${d.up ? 'se ha conectado' : 'se ha desconectado'} <span class="dim mono">${esc(d.ip)}</span>`);
      S.devUp.set(d.mac, d.up);
      if (d.new && !S.toasted.has(d.mac)) { S.toasted.add(d.mac); toast('Dispositivo nuevo en la red', `${d.ip} · ${d.vendor || d.h || d.mac}`); logEv('warn', `Dispositivo <b>nuevo</b>: ${esc(d.ip)} <span class="mono dim">${esc(d.mac)}</span>`); }
    }
    renderDevices();
  } catch {}
}
async function pollConns() {
  try {
    const c = await api('conns'); S.conns = c.conns; S.listen = c.listen;
    const keys = new Set();
    for (const x of c.conns) {
      const k = `${x.p}|${x.ra}|${x.rp}`; keys.add(k);
      if (!S.seenConn.has(k) && !S.firstConns) logEv('conn', `<b>${esc(x.p)}</b> → ${esc(x.h || x.ra)}<span class="dim">:${x.rp}</span>${x.cc ? ` <span class="dim">${esc(x.cc)}</span>` : ''}`);
    }
    S.seenConn = keys; S.firstConns = false;
    const inet = c.conns.filter(x => !x.lan).length;
    $('nCon').textContent = c.conns.length; $('nConS').textContent = `${inet} a internet · ${c.conns.length - inet} locales`;
    if (S.elevated) { try { S.procRates = (await api('procs')).rates; } catch {} }
    renderConns(); renderProcs(); renderPorts();
    if (S.view === 'world') renderWorldLists();
  } catch {}
}
async function pollInfo() {
  try {
    const i = await api('info'); S.ifc = i.ifc; S.pub = i.publicIp; S.pubCc = i.publicCc; S.elevated = i.elevated;
    $('ifc').innerHTML = i.ifc.ip ? `<b>${esc(i.ifc.name || 'red')}</b>${i.ifc.speed ? ' · ' + esc(i.ifc.speed) : ''} · <span class="mono">${esc(i.ifc.ip)}</span> · gw <span class="mono">${esc(i.ifc.gw)}</span>${i.elevated ? ' · <span class="c-warn">administrador</span>' : ''}` : 'detectando interfaz…';
    $('pub').textContent = i.publicIp || '—';
    $('pubS').textContent = i.publicCc ? `${country(i.publicCc)} · pasa el ratón` : 'pasa el ratón';
  } catch {}
}
async function loadHistory() {
  try { const h = await api('history'); S.hist = h.rate.map(p => [p[0], p[1], p[2]]); S.rt = h.router; } catch {}
}
function renderPorts() {
  $('ports').innerHTML = S.listen.map(l => `<span class="port"><b>${l.port}</b> ${esc(l.p)}</span>`).join('') || '<span class="dim">Ninguno</span>';
}

/* ================================================================ HISTORY */
const hH = hoverOn('hBox'), qH = hoverOn('qBox'), spH = hoverOn('spBox');
async function loadHist() {
  try {
    S.H = await api('hist', {range: S.hRange, off: -new Date().getTimezoneOffset() * 60});
    renderHist();
  } catch (e) { $('hSub').textContent = 'Error: ' + e; }
}
$('hRange').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  S.hRange = b.dataset.r; [...$('hRange').children].forEach(x => x.classList.toggle('on', x === b)); loadHist();
});
function histDevices() {
  const H = S.H; if (!H) return [];
  return Object.entries(H.series).filter(([m]) => m !== 'PC').map(([m, s]) => ({mac: m, ...s, total: s.totalRx + s.totalTx})).sort((a, b) => b.total - a.total);
}
function renderHist() {
  const H = S.H; if (!H) return;
  const devs = histDevices(), pc = H.series.PC;
  const total = devs.reduce((a, d) => a + d.total, 0);
  const labels = {'24h': 'últimas 24 h', '7d': 'últimos 7 días', '30d': 'últimos 30 días', '90d': 'últimos 90 días'};
  $('hSub').textContent = labels[H.range];
  const outs = H.outages.filter(o => o.kind !== 'ppp');
  $('hKpis').innerHTML = [
    ['Red (router, IPv4)', bytes(total)],
    ['Este PC (total)', pc ? bytes(pc.totalRx + pc.totalTx) : '—'],
    ['Disponibilidad', `${H.uptime.toFixed(H.uptime > 99.9 ? 3 : 2)}<small>%</small>`],
    ['Cortes', `${outs.length}<small>${outs.length ? dur(H.downSeconds) : ''}</small>`],
    ['Velocidad media', H.speeds.length ? `${Math.round(H.speeds.reduce((a, s) => a + s.down, 0) / H.speeds.length)}<small>Mb/s ↓</small>` : '—'],
  ].map(([l, v]) => `<div class="kpi"><div class="l">${l}</div><div class="v num">${v}</div></div>`).join('');
  const mx = Math.max(1, ...devs.map(d => d.total));
  $('hTop').innerHTML = devs.slice(0, 20).map(d => `<tr><td><span style="display:inline-block;width:9px;height:9px;border-radius:3px;background:${colorOf(d.mac)};margin-right:8px"></span>${esc(devName(d.mac))}</td><td class="r num">${bytes(d.totalRx)}</td><td class="r num">${bytes(d.totalTx)}</td><td><div class="bar2"><i style="width:${d.totalRx / mx * 100}%;background:var(--down)"></i><i style="width:${d.totalTx / mx * 100}%;background:var(--up)"></i></div></td></tr>`).join('')
    || '<tr><td colspan="4" class="empty">Aún no hay historial: se guarda cada minuto.</td></tr>';
  $('qSub').textContent = `${H.uptime.toFixed(2)}% disponible · ${outs.length} cortes`;
  $('oSub').textContent = H.outages.length ? '' : 'ninguno en este periodo';
  $('outages').innerHTML = H.outages.map(o => {
    const kind = o.kind === 'ppp' ? 'Reconexión de la fibra (PPPoE)' : o.kind === 'router' ? 'Router inaccesible' : 'Sin internet';
    const d = o.end ? (o.kind === 'ppp' ? '' : ` · ${dur(o.end - o.start)}`) : ' · en curso';
    return `<div class="ev"><span class="t">${dateT(o.start * 1000).replace(',', '')}</span><i class="k" style="background:${o.kind === 'ppp' ? COL.warn : COL.bad}"></i><span class="x">${kind}${d}</span></div>`;
  }).join('') || '<div class="empty">Sin cortes registrados 🎉</div>';
  renderSpeedTop();
}
function drawHist() {
  const H = S.H; if (!H) return;
  const [ctx, w, h] = fit($('hChart')); ctx.clearRect(0, 0, w, h);
  const devs = histDevices(), top = devs.slice(0, 8), rest = devs.slice(8);
  const n = H.buckets.length, padL = 58, padB = 22, padT = 6;
  const val = (d, i) => d.rx[i] + d.tx[i];
  const sums = H.buckets.map((_, i) => devs.reduce((a, d) => a + val(d, i), 0));
  const mx = niceMax(Math.max(...sums, 1e6) * 1.05);
  const bw = (w - padL) / n, Y = v => h - padB - v / mx * (h - padB - padT);
  ctx.font = '11px Segoe UI, sans-serif'; ctx.fillStyle = COL.dim; ctx.textAlign = 'right'; ctx.textBaseline = 'middle'; ctx.strokeStyle = COL.line;
  for (const f of [0.25, 0.5, 0.75, 1]) { const y = Y(mx * f); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w, y); ctx.stroke(); ctx.fillText(bytes(mx * f), padL - 8, y); }
  let hoverI = hH.x != null ? Math.floor((hH.x - padL) / bw) : -1;
  if (hoverI >= n) hoverI = -1;
  for (let i = 0; i < n; i++) {
    let y0 = h - padB;
    const x = padL + i * bw + Math.max(1, bw * 0.12), bwi = Math.max(1, bw * 0.76);
    for (const d of top) { const v = val(d, i); if (!v) continue; const y = Y(v) - (h - padB - y0); ctx.fillStyle = colorOf(d.mac) + (i === hoverI ? 'FF' : 'CC'); ctx.fillRect(x, y, bwi, y0 - y); y0 = y; }
    const r = rest.reduce((a, d) => a + val(d, i), 0);
    if (r) { const y = Y(r) - (h - padB - y0); ctx.fillStyle = '#3A424E'; ctx.fillRect(x, y, bwi, y0 - y); }
  }
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic'; ctx.fillStyle = COL.dim;
  const step = Math.ceil(n / Math.max(2, Math.floor(w / 90)));
  for (let i = 0; i < n; i += step) {
    const t = H.buckets[i] * 1000;
    const lab = H.bucket < 86400 ? (H.bucket < 3600 * 2 ? new Date(t).toLocaleTimeString('es-ES', {hour: '2-digit', minute: '2-digit'}) : new Date(t).toLocaleString('es-ES', {weekday: 'short', hour: '2-digit'})) : new Date(t).toLocaleDateString('es-ES', {day: 'numeric', month: 'short'});
    ctx.fillText(lab, padL + i * bw + bw / 2, h - 5);
  }
  if (hoverI >= 0) {
    const rows = devs.filter(d => val(d, hoverI) > 0).slice(0, 8).map(d => `<span style="color:${colorOf(d.mac)}">■</span> ${esc(devName(d.mac))}: ${bytes(val(d, hoverI))}`);
    tip($('hTip'), `<span class="mute">${dateT(H.buckets[hoverI] * 1000)}</span> · <b>${bytes(sums[hoverI])}</b><br>${rows.join('<br>') || 'sin tráfico'}`, hH.x, 4, w);
  } else tip($('hTip'), null);
  $('hLeg').innerHTML = top.map(d => `<span><i style="background:${colorOf(d.mac)}"></i>${esc(devName(d.mac))}</span>`).join('') + (rest.length ? '<span><i style="background:#3A424E"></i>Otros</span>' : '');
}
function drawQuality() {
  const H = S.H; if (!H) return;
  const [ctx, w, h] = fit($('qChart')); ctx.clearRect(0, 0, w, h);
  const L = H.latency, padL = 44, padB = 20, padT = 6;
  const t0 = H.buckets[0], t1 = Date.now() / 1000;
  const X = t => padL + (t - t0) / (t1 - t0) * (w - padL - 4);
  const mx = niceMax(Math.max(10, ...L.map(r => r[2] || 0)) * 1.15);
  const Y = v => h - padB - Math.min(1, v / mx) * (h - padB - padT);
  ctx.font = '11px Segoe UI, sans-serif'; ctx.fillStyle = COL.dim; ctx.textAlign = 'right'; ctx.textBaseline = 'middle'; ctx.strokeStyle = COL.line;
  for (const f of [0.5, 1]) { const y = Y(mx * f); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w, y); ctx.stroke(); ctx.fillText(`${Math.round(mx * f)} ms`, padL - 6, y); }
  for (const o of H.outages) {
    if (o.kind === 'ppp') { ctx.fillStyle = COL.warn; ctx.fillRect(X(o.start) - 1, padT, 2, h - padB - padT); continue; }
    const a = X(Math.max(o.start, t0)), b = X(o.end || t1);
    ctx.fillStyle = 'rgba(255,107,107,.25)'; ctx.fillRect(a, padT, Math.max(2, b - a), h - padB - padT);
  }
  for (const r of L) if (r[3] > 0) { const x = X(r[0]); ctx.fillStyle = 'rgba(255,107,107,.8)'; const bh = Math.max(2, r[3] * 40); ctx.fillRect(x - 1, h - padB - bh, 2, bh); }
  const line = (idx, col) => {
    const P = L.filter(r => r[idx] != null).map(r => [X(r[0]), Y(r[idx])]);
    if (!P.length) return;
    if (P.length === 1) { ctx.beginPath(); ctx.arc(P[0][0], P[0][1], 3, 0, 7); ctx.fillStyle = col; ctx.fill(); return; }
    ctx.beginPath(); smooth(ctx, P); ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.stroke();
  };
  line(1, COL.ok); line(2, COL.warn);
  if (!L.length) { ctx.textAlign = 'center'; ctx.fillStyle = COL.dim; ctx.fillText('Aún no hay datos: se guarda cada minuto.', w / 2, h / 2); }
  if (qH.x != null && L.length) {
    const t = t0 + (qH.x - padL) / (w - padL - 4) * (t1 - t0);
    let best = L[0]; for (const r of L) if (Math.abs(r[0] - t) < Math.abs(best[0] - t)) best = r;
    tip($('qTip'), `<span class="mute">${dateT(best[0] * 1000)}</span><br><span class="c-ok">router ${best[1] != null ? best[1].toFixed(1) + ' ms' : '—'}</span> · <span class="c-warn">internet ${best[2] != null ? best[2].toFixed(1) + ' ms' : '—'}</span>${best[3] > 0 ? `<br><span class="c-bad">${(best[3] * 100).toFixed(1)}% perdidos</span>` : ''}`, qH.x, 4, w);
  } else tip($('qTip'), null);
}
function renderSpeedTop() {
  const sp = S.H ? S.H.speeds : [];
  const live = S.speed && S.speed.running;
  if (!live) {
    const last = (S.speed && S.speed.result) || sp[sp.length - 1];
    $('spD').innerHTML = last ? `${Math.round(last.down)}<small>Mb/s</small>` : '—';
    $('spU').innerHTML = last ? `${Math.round(last.up)}<small>Mb/s</small>` : '—';
    $('spP').innerHTML = last ? `${last.ping.toFixed(1)}<small>ms</small>` : '—';
    $('spState').textContent = last ? `último test ${ago((last.ts || 0) * 1000)}` + (S.speed && S.speed.phase === 'error' ? ` · error: ${S.speed.error}` : '') : 'Aún no se ha medido.';
  }
  $('bSpeed').disabled = !!live;
}
function drawSpeed() {
  const sp = S.H ? S.H.speeds : [];
  const [ctx, w, h] = fit($('spChart')); ctx.clearRect(0, 0, w, h);
  const cfg = (S.cfg && S.cfg.speed) || {};
  const padL = 52, padB = 20, padT = 8;
  ctx.font = '11px Segoe UI, sans-serif';
  if (!sp.length) { ctx.textAlign = 'center'; ctx.fillStyle = COL.dim; ctx.fillText('Pulsa "Medir ahora" o programa tests automáticos en Ajustes.', w / 2, h / 2); return; }
  const mx = niceMax(Math.max(...sp.map(s => Math.max(s.down, s.up)), cfg.contractDown || 0, cfg.contractUp || 0) * 1.1);
  const t0 = S.H.buckets[0], t1 = Date.now() / 1000;
  const X = t => padL + (t - t0) / (t1 - t0) * (w - padL - 8), Y = v => h - padB - v / mx * (h - padB - padT);
  ctx.fillStyle = COL.dim; ctx.textAlign = 'right'; ctx.textBaseline = 'middle'; ctx.strokeStyle = COL.line;
  for (const f of [0.25, 0.5, 0.75, 1]) { const y = Y(mx * f); ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w, y); ctx.stroke(); ctx.fillText(`${Math.round(mx * f)}`, padL - 8, y); }
  ctx.setLineDash([5, 5]); ctx.lineWidth = 1;
  if (cfg.contractDown) { ctx.strokeStyle = COL.down + '88'; ctx.beginPath(); ctx.moveTo(padL, Y(cfg.contractDown)); ctx.lineTo(w, Y(cfg.contractDown)); ctx.stroke(); }
  if (cfg.contractUp) { ctx.strokeStyle = COL.up + '88'; ctx.beginPath(); ctx.moveTo(padL, Y(cfg.contractUp)); ctx.lineTo(w, Y(cfg.contractUp)); ctx.stroke(); }
  ctx.setLineDash([]);
  for (const [k, col] of [['down', COL.down], ['up', COL.up]]) {
    const P = sp.map(s => [X(s.ts), Y(s[k])]);
    if (P.length > 1) { ctx.beginPath(); ctx.moveTo(P[0][0], P[0][1]); P.forEach(p => ctx.lineTo(p[0], p[1])); ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.stroke(); }
    for (const p of P) { ctx.beginPath(); ctx.arc(p[0], p[1], 3.5, 0, 7); ctx.fillStyle = col; ctx.fill(); }
  }
  if (spH.x != null) {
    let best = sp[0]; for (const s of sp) if (Math.abs(X(s.ts) - spH.x) < Math.abs(X(best.ts) - spH.x)) best = s;
    tip($('spTip'), `<span class="mute">${dateT(best.ts * 1000)}</span><br><span class="c-down">↓ ${best.down.toFixed(0)} Mb/s</span> · <span class="c-up">↑ ${best.up.toFixed(0)} Mb/s</span><br>ping ${best.ping.toFixed(1)} ms · jitter ${best.jitter.toFixed(1)} ms`, X(best.ts), 4, w);
  } else tip($('spTip'), null);
}
let speedTimer = null;
async function pollSpeed() {
  try {
    S.speed = await api('speed');
    const s = S.speed;
    if (s.running) {
      const ph = {ping: 'Midiendo latencia…', down: 'Midiendo bajada…', up: 'Midiendo subida…'}[s.phase] || 'Midiendo…';
      $('spState').textContent = ph;
      if (s.phase === 'down') $('spD').innerHTML = `${Math.round(s.mbps || 0)}<small>Mb/s</small>`;
      if (s.phase === 'up') $('spU').innerHTML = `${Math.round(s.mbps || 0)}<small>Mb/s</small>`;
      if (!speedTimer) speedTimer = setInterval(pollSpeed, 400);
    } else {
      if (speedTimer) { clearInterval(speedTimer); speedTimer = null; if (S.view === 'hist') loadHist(); }
    }
    renderSpeedTop();
  } catch {}
}
$('bSpeed').onclick = async () => {
  const ok = await confirmBox('¿Medir la velocidad ahora?', 'Descarga y sube datos durante unos 15 s a toda velocidad (puede ser más de 1 GB con fibra de 1 Gb/s).', 'Medir');
  if (!ok) return;
  await api('speed', {run: true}); pollSpeed();
};

/* ================================================================ WORLD */
const W = {paths: null, size: '', cent: {}, names: {}};
const wH = hoverOn('wBox');
function decodeWorld() {
  if (W.geo || !window.WORLD) return;
  const topo = window.WORLD, [sx, sy] = topo.transform.scale, [tx, ty] = topo.transform.translate;
  const arcs = topo.arcs.map(a => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
  const ring = idx => { const pts = []; for (const i of idx) { const a = i >= 0 ? arcs[i] : arcs[~i].slice().reverse(); pts.push(...(pts.length ? a.slice(1) : a)); } return pts; };
  W.geo = topo.objects.countries.geometries.filter(g => g.id !== '010').map(g => {
    const polys = g.type === 'Polygon' ? [g.arcs] : g.type === 'MultiPolygon' ? g.arcs : [];
    const rings = polys.map(p => p.map(ring));
    let best = null, area = -1;
    for (const p of rings) { const r = p[0]; let a = 0; for (let i = 0; i < r.length - 1; i++) a += r[i][0] * r[i + 1][1] - r[i + 1][0] * r[i][1]; a = Math.abs(a); if (a > area) { area = a; best = r; } }
    let cx = 0, cy = 0; if (best) { for (const p of best) { cx += p[0]; cy += p[1]; } cx /= best.length; cy /= best.length; }
    const cc = window.ISO_NUM[g.id] || null;
    if (cc) W.cent[cc] = [cx, cy];
    return {cc, name: g.properties && g.properties.name, rings};
  });
}
function worldAgg() {
  const by = {};
  for (const c of S.conns) {
    if (c.lan || !c.cc) continue;
    const e = by[c.cc] || (by[c.cc] = {n: 0, procs: new Set(), hosts: new Set()});
    e.n++; e.procs.add(c.p); e.hosts.add(c.h || c.ra);
  }
  return by;
}
function drawWorld(now) {
  decodeWorld(); if (!W.geo) return;
  const [ctx, w, h] = fit($('world')); ctx.clearRect(0, 0, w, h);
  const latMax = 80, latMin = -58;
  const sc = Math.min(w / 360, h / (latMax - latMin)), ox = (w - 360 * sc) / 2, oy = (h - (latMax - latMin) * sc) / 2;
  const P = ([lon, lat]) => [ox + (lon + 180) * sc, oy + (latMax - lat) * sc];
  const key = `${w}x${h}`;
  if (W.size !== key) {
    W.size = key;
    // rings that cross the antimeridian are split where longitude jumps, so no line runs across the map
    W.paths = W.geo.map(g => { const p = new Path2D(); for (const poly of g.rings) for (const r of poly) { r.forEach((pt, i) => { const [x, y] = P(pt); (i && Math.abs(pt[0] - r[i - 1][0]) < 180) ? p.lineTo(x, y) : p.moveTo(x, y); }); } return p; });
  }
  const agg = worldAgg();
  const mxN = Math.max(1, ...Object.values(agg).map(e => e.n));
  let hit = null;
  W.geo.forEach((g, i) => {
    const e = g.cc && agg[g.cc];
    ctx.fillStyle = e ? `rgba(90,169,255,${0.25 + 0.6 * Math.sqrt(e.n / mxN)})` : '#171B22';
    ctx.fill(W.paths[i]);
    ctx.strokeStyle = '#242B35'; ctx.lineWidth = 0.6; ctx.stroke(W.paths[i]);
    if (wH.x != null && !hit && ctx.isPointInPath(W.paths[i], wH.x * DPR(), wH.y * DPR())) hit = g;
  });
  const home = S.pubCc && W.cent[S.pubCc] ? W.cent[S.pubCc] : W.cent.ES;
  if (home) {
    const [hx, hy] = P(home);
    for (const [cc, e] of Object.entries(agg)) {
      const c = W.cent[cc]; if (!c || cc === S.pubCc) continue;
      const [x, y] = P(c);
      const mx = (hx + x) / 2, my = (hy + y) / 2 - Math.hypot(x - hx, y - hy) * 0.25;
      ctx.beginPath(); ctx.moveTo(hx, hy); ctx.quadraticCurveTo(mx, my, x, y);
      ctx.strokeStyle = 'rgba(255,169,77,.45)'; ctx.lineWidth = 1 + Math.sqrt(e.n / mxN) * 2; ctx.stroke();
      const k = ((now / 2200) + (cc.charCodeAt(0) + cc.charCodeAt(1)) / 50) % 1;
      const qx = (1 - k) * (1 - k) * hx + 2 * (1 - k) * k * mx + k * k * x, qy = (1 - k) * (1 - k) * hy + 2 * (1 - k) * k * my + k * k * y;
      ctx.beginPath(); ctx.arc(qx, qy, 2.4, 0, 7); ctx.fillStyle = '#FFC98A'; ctx.fill();
      ctx.beginPath(); ctx.arc(x, y, 3, 0, 7); ctx.fillStyle = '#FFA94D'; ctx.fill();
    }
    ctx.beginPath(); ctx.arc(hx, hy, 5, 0, 7); ctx.fillStyle = '#3DD68C'; ctx.fill();
    ctx.beginPath(); ctx.arc(hx, hy, 9 + 3 * Math.sin(now / 400), 0, 7); ctx.strokeStyle = 'rgba(61,214,140,.5)'; ctx.lineWidth = 1.5; ctx.stroke();
  }
  if (hit) {
    const e = hit.cc && agg[hit.cc];
    tip($('wTip'), `<b>${esc(country(hit.cc) || hit.name)}</b>${e ? `<br>${e.n} conexiones · ${[...e.procs].slice(0, 4).map(esc).join(', ')}` : '<br><span class="mute">sin conexiones</span>'}`, wH.x, wH.y - 30, w);
  } else tip($('wTip'), null);
}
function renderWorldLists() {
  const agg = worldAgg(), list = Object.entries(agg).sort((a, b) => b[1].n - a[1].n);
  const total = list.reduce((a, [, e]) => a + e.n, 0);
  $('wSub').textContent = list.length ? `${total} conexiones a ${list.length} países` : 'sin conexiones geolocalizadas todavía';
  const mx = Math.max(1, ...list.map(([, e]) => e.n));
  $('wList').innerHTML = list.map(([cc, e]) => `<div class="pr"><div class="n"><span class="tag cc">${esc(cc)}</span> ${esc(country(cc))}</div><div class="c num">${e.n}</div><div class="b"><i style="width:${e.n / mx * 100}%;background:var(--down)"></i></div><div class="h">${[...e.procs].map(esc).join(' · ')}</div></div>`).join('') || '<div class="empty">Sin datos</div>';
  const hosts = new Map();
  for (const c of S.conns) { if (c.lan) continue; const k = c.h || c.ra; const e = hosts.get(k) || {n: 0, cc: c.cc, procs: new Set()}; e.n++; e.procs.add(c.p); hosts.set(k, e); }
  $('wHosts').innerHTML = [...hosts.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 30).map(([hst, e]) => `<tr><td title="${esc(hst)}">${esc(hst)}</td><td>${e.cc ? `<span class="tag cc">${esc(e.cc)}</span>` : ''}</td><td>${[...e.procs].map(esc).join(', ')}</td><td class="r">${e.n}</td></tr>`).join('');
}

/* ================================================================ DNS */
async function loadDns() {
  try { S.dns = await api('dns'); renderDns(); } catch {}
}
$('dSearch').addEventListener('input', () => renderDns());
$('dFilter').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  S.dFilter = b.dataset.f; [...$('dFilter').children].forEach(x => x.classList.toggle('on', x === b)); renderDns();
});
function renderDns() {
  const D = S.dns; if (!D) return;
  const q = $('dSearch').value.trim().toLowerCase();
  const rows = D.local.filter(r => (S.dFilter === 'all' || r.tracker) && (!q || r.d.includes(q)));
  $('dSub').textContent = `${D.local.length} dominios · ${D.local.filter(r => r.tracker).length} posibles rastreadores`;
  const none = !D.local.length && !D.elevated
    ? '<tr><td colspan="2" class="empty" style="white-space:normal">Windows solo deja leer la caché DNS a programas con permisos de administrador. <a href="#" id="lnkElevDns" style="color:var(--down)">Reiniciar como administrador</a></td></tr>'
    : '<tr><td colspan="2" class="empty">Nada que mostrar</td></tr>';
  $('dLocal').innerHTML = rows.slice(0, 400).map(r => `<tr><td title="${esc(r.d)}">${r.tracker ? '<span class="tag warn" style="margin-right:6px">rastreador</span>' : ''}${esc(r.d)}</td><td class="dim">${ago(r.last)}</td></tr>`).join('') || none;
  const le = $('lnkElevDns'); if (le) le.onclick = e => { e.preventDefault(); elevFlow(); };
  const A = D.adguard;
  if (!A) {
    $('aSub').textContent = 'sin configurar';
    $('aBody').innerHTML = `<p class="mute" style="margin-top:0">Para ver qué dominios consulta cada dispositivo de casa (móviles, TV, enchufes…) y bloquear rastreadores para toda la red hace falta un servidor DNS propio.</p>
      <ol class="mute" style="padding-left:18px;line-height:1.7"><li>Instala <b>AdGuard Home</b> en un equipo siempre encendido (este PC, una Raspberry Pi…).</li><li>En el router, pon su IP como DNS del DHCP (Network → LAN → DNS).</li><li>Escribe su URL, usuario y contraseña en Ajustes → AdGuard Home.</li></ol>
      <p class="note">NetMonitor no cambia el DNS del router: si ese equipo se apaga, toda la red se quedaría sin DNS.</p>`;
  } else if (!A.ok) {
    $('aSub').textContent = 'error'; $('aBody').innerHTML = `<div class="c-bad">No se pudo conectar: ${esc(A.error)}</div>`;
  } else {
    const ipName = ip => { const d = S.lan.find(x => x.ip === ip); return d ? nameOf(d) : ip; };
    const pairs = arr => (arr || []).map(o => Object.entries(o)[0]);
    $('aSub').textContent = `${A.queries} consultas · ${A.blocked} bloqueadas`;
    const list = (title, arr, fmt) => `<div class="hd" style="margin:14px 0 6px"><h2>${title}</h2></div>` + (pairs(arr).slice(0, 10).map(([k, v]) => `<div class="pr"><div class="n">${fmt(k)}</div><div class="c num">${v}</div></div>`).join('') || '<div class="empty">—</div>');
    $('aBody').innerHTML = `<div class="kpis"><div class="kpi"><div class="l">Consultas</div><div class="v num">${A.queries}</div></div><div class="kpi"><div class="l">Bloqueadas</div><div class="v num">${A.blocked}<small>${A.queries ? Math.round(A.blocked / A.queries * 100) + '%' : ''}</small></div></div></div>`
      + list('Dispositivos', A.topClients, k => esc(ipName(k))) + list('Dominios más consultados', A.topDomains, esc) + list('Más bloqueados', A.topBlocked, esc)
      + `<div class="hd" style="margin:14px 0 6px"><h2>Últimas consultas</h2></div><div class="log">` + A.log.slice(0, 120).map(r => `<div class="ev"><span class="t">${new Date(r.time).toLocaleTimeString('es-ES').slice(0, 5)}</span><i class="k" style="background:${r.blocked ? COL.bad : COL.dim}"></i><span class="x">${esc(ipName(r.client))} → ${esc(r.d)}</span></div>`).join('') + '</div>';
  }
}

/* ================================================================ SECURITY */
async function loadSec() {
  try {
    const [e, al] = await Promise.all([api('exposure'), api('alerts')]);
    S.exposure = e; S.alerts = al; renderSec();
  } catch {}
}
function renderSec() {
  const ok = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M20 6 9 17l-5-5"/></svg>';
  const wr = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>';
  const E = S.exposure;
  if (E && E.items) {
    $('eSub').textContent = `leído del router ${ago(E.t)}`;
    $('exp').innerHTML = E.items.map(i => `<div class="chk ${i.good ? 'ok' : 'warn'}">${i.good ? ok : wr}<div>${esc(i.title)}<small>${esc(i.value)}</small></div></div>`).join('');
  } else {
    $('eSub').textContent = E && E.error ? 'error: ' + E.error : 'esperando al router…';
    $('exp').innerHTML = '<div class="empty">Se lee del router al conectar y cada 10 minutos.</div>';
  }
  const kindName = {newDevice: 'Dispositivo nuevo', nightUnknown: 'Madrugada', upload: 'Subida', outage: 'Conexión', exposure: 'Exposición', speed: 'Velocidad', update: 'Actualización'};
  const kindCol = {newDevice: COL.warn, nightUnknown: COL.warn, upload: COL.bad, outage: COL.bad, exposure: COL.bad, speed: COL.warn, update: COL.down};
  $('alSub').textContent = S.alerts.length ? `${S.alerts.length} recientes` : 'ninguna todavía';
  $('alerts').innerHTML = S.alerts.map(a => `<div class="ev" title="${esc(a.body)}"><span class="t">${dateT(a.ts * 1000).replace(',', '')}</span><i class="k" style="background:${kindCol[a.kind] || COL.mute}"></i><span class="x"><b>${esc(a.title)}</b> <span class="mute">${esc(a.body)}</span></span></div>`).join('') || '<div class="empty">Sin alertas</div>';
  const bl = S.router.blocked || [];
  $('blocked').innerHTML = bl.map(m => `<div class="dv blk" style="grid-template-columns:minmax(0,1fr) auto"><div class="nm"><div class="n">${esc(devName(m))}</div><div class="m mono">${esc(m)}</div></div><button class="btn" data-unblock="${esc(m)}">Desbloquear</button></div>`).join('') || '<div class="empty">Ningún dispositivo bloqueado. Usa el icono ⊘ en la lista de dispositivos.</div>';
  renderPorts();
}
$('blocked').addEventListener('click', e => { const b = e.target.closest('[data-unblock]'); if (b) blockFlow(b.dataset.unblock, false); });
$('bExp').onclick = async () => { $('eSub').textContent = 'comprobando…'; try { S.exposure = await api('exposure', {refresh: true}); } catch {} renderSec(); };
$('bShields').onclick = () => api('open', {url: 'https://www.grc.com/shieldsup'});
async function pollAlertsBadge() {
  try {
    const al = await api('alerts'); S.alerts = al;
    const seen = +(localStorage.getItem('seenAlert') || 0);
    const fresh = al.filter(a => a.ts > seen).length;
    $('secBadge').hidden = !fresh; $('secBadge').textContent = fresh;
    if (S.view === 'sec') { localStorage.setItem('seenAlert', al.length ? al[0].ts : 0); $('secBadge').hidden = true; renderSec(); }
  } catch {}
}

/* ================================================================ SETTINGS */
async function loadSettings() {
  try {
    const [s, c, u] = await Promise.all([api('settings'), api('config'), api('update')]);
    S.cfg = c; S.upd = u;
    $('tAuto').classList.toggle('on', s.autostart); $('tMin').classList.toggle('on', s.startMinimized); $('tPanel').classList.toggle('on', s.panel);
    setPanelUi(s.panel);
    const al = c.alerts || {};
    $('alertToggles').innerHTML = c.alertKinds.map(k => `<div class="opt"><div>${esc(k.title)}</div><button class="tg ${al[k.key] === false ? '' : 'on'}" data-alert="${k.key}"></button></div>`).join('');
    $('cNs').value = al.nightStart ?? 0; $('cNe').value = al.nightEnd ?? 7; $('cUp').value = al.uploadMbps ?? 2;
    const n = c.notify || {};
    $('cNtfy').value = n.ntfyUrl || ''; $('cTgTok').value = ''; $('cTgTok').placeholder = n.telegramToken ? 'guardado (escribe para cambiarlo)' : '123456:ABC…'; $('cTgChat').value = n.telegramChat || '';
    const sp = c.speed || {};
    $('cSpI').value = String(sp.intervalHours ?? 0); $('cCD').value = sp.contractDown ?? ''; $('cCU').value = sp.contractUp ?? '';
    const ag = c.adguard || {};
    $('cAgU').value = ag.url || ''; $('cAgUser').value = ag.user || ''; $('cAgPass').value = ''; $('cAgPass').placeholder = ag.pass ? 'guardada' : '';
    $('elevTxt').textContent = c.elevated ? 'Activo: NetMonitor se está ejecutando como administrador' : 'Requiere ejecutar como administrador (Windows pedirá permiso)';
    $('bElev').hidden = c.elevated;
    $('tUpd').classList.toggle('on', c.autoUpdateCheck);
    renderUpd();
    $('kv').innerHTML = `<b>Versión</b> ${esc(s.version)}${s.frozen ? '' : ' (desarrollo)'}<br><b>Datos</b> ${esc(s.dataDir)}<br><b>Router</b> ${S.router.ok ? 'conectado' : esc(S.router.error || 'sin conexión')}<br><b>Interfaz</b> ${esc(S.ifc.desc || S.ifc.name || '—')}<br><b>Geolocalización</b> ${esc(c.geo.status)}${c.geo.month ? ' · ' + esc(c.geo.month) : ''} (DB-IP, CC BY 4.0)`;
  } catch (e) { console.error(e); }
}
function renderUpd() {
  const u = S.upd || {};
  $('updTxt').textContent = u.error ? `Error: ${u.error}` : u.available ? `Disponible ${u.latest} (tienes ${u.current})` : u.checked ? `Al día (${u.current}) · comprobado ${ago(u.checked)}` : `Versión ${u.current || ''}`;
  $('bInstall').hidden = !u.available; $('bInstall').textContent = `Instalar ${u.latest || ''}`;
  $('upd').innerHTML = u.available ? `<a href="#" id="updLink" class="tag ok" style="text-decoration:none">Actualización ${esc(u.latest)} disponible</a>` : '';
  const l = $('updLink'); if (l) l.onclick = e => { e.preventDefault(); drawer(true); };
}
const saveCfg = patch => api('config', patch).then(c => { S.cfg = c; }).catch(() => {});
$('alertToggles').addEventListener('click', e => {
  const b = e.target.closest('[data-alert]'); if (!b) return;
  b.classList.toggle('on'); saveCfg({alerts: {[b.dataset.alert]: b.classList.contains('on')}});
});
$('cNs').onchange = () => saveCfg({alerts: {nightStart: +$('cNs').value}});
$('cNe').onchange = () => saveCfg({alerts: {nightEnd: +$('cNe').value}});
$('cUp').onchange = () => saveCfg({alerts: {uploadMbps: +$('cUp').value}});
$('cNtfy').onchange = () => saveCfg({notify: {ntfyUrl: $('cNtfy').value.trim()}});
$('cTgTok').onchange = () => { if ($('cTgTok').value.trim()) saveCfg({notify: {telegramToken: $('cTgTok').value.trim()}}).then(loadSettings); };
$('cTgChat').onchange = () => saveCfg({notify: {telegramChat: $('cTgChat').value.trim()}});
$('cSpI').onchange = () => saveCfg({speed: {intervalHours: +$('cSpI').value}});
$('cCD').onchange = () => saveCfg({speed: {contractDown: +$('cCD').value || 0}});
$('cCU').onchange = () => saveCfg({speed: {contractUp: +$('cCU').value || 0}});
$('cAgU').onchange = () => saveCfg({adguard: {url: $('cAgU').value.trim()}});
$('cAgUser').onchange = () => saveCfg({adguard: {user: $('cAgUser').value.trim()}});
$('cAgPass').onchange = () => { if ($('cAgPass').value) saveCfg({adguard: {pass: $('cAgPass').value}}).then(loadSettings); };
$('tUpd').onclick = () => { $('tUpd').classList.toggle('on'); saveCfg({autoUpdateCheck: $('tUpd').classList.contains('on')}); };
$('bTest').onclick = async () => { $('testMsg').textContent = 'Enviando…'; try { const r = await api('notifyTest'); $('testMsg').textContent = r.msg; $('testMsg').style.color = r.ok ? 'var(--ok)' : 'var(--bad)'; } catch (e) { $('testMsg').textContent = String(e); } };
$('bCheck').onclick = async () => { $('updTxt').textContent = 'Buscando…'; try { S.upd = await api('update', {check: true}); } catch {} renderUpd(); };
$('bInstall').onclick = async () => {
  if (!await confirmBox(`¿Instalar ${S.upd.latest}?`, 'NetMonitor se cerrará, se instalará la nueva versión y volverá a abrirse solo.', 'Instalar')) return;
  const r = await api('update', {install: true}); if (!r.ok) toast('No se pudo actualizar', r.error || '', 'bad');
};
async function elevFlow() {
  if (!await confirmBox('¿Reiniciar como administrador?', 'Windows pedirá permiso. Con permisos de administrador NetMonitor puede medir los bytes que usa cada programa. El arranque con Windows sigue siendo sin permisos.', 'Reiniciar')) return;
  const r = await api('elevate'); if (!r.ok) toast('No se reinició', r.error || '', 'bad');
}
$('bElev').onclick = elevFlow;
$('tAuto').onclick = async () => { await api('settings', {autostart: !$('tAuto').classList.contains('on')}); loadSettings(); };
$('tMin').onclick = async () => { await api('settings', {startMinimized: !$('tMin').classList.contains('on')}); loadSettings(); };
$('tPanel').onclick = async () => { await api('settings', {panel: !$('tPanel').classList.contains('on')}); loadSettings(); };
function setPanelUi(on) { document.body.classList.toggle('panel', !!on); $('bPanel').classList.toggle('on', !!on); $('tPanel').classList.toggle('on', !!on); }
const drawer = open => { $('drawer').classList.toggle('open', open); $('scrim').classList.toggle('on', open); if (open) loadSettings(); };
$('bSet').onclick = () => drawer(!$('drawer').classList.contains('open'));
$('scrim').onclick = () => drawer(false);
const fullscreen = () => T ? T.core.invoke('toggle_fullscreen') : null;
$('bFull').onclick = fullscreen;
$('bPanel').onclick = async () => { if (T) setPanelUi(await T.core.invoke('toggle_panel')); };
document.addEventListener('keydown', e => {
  if (e.key === 'F11') { e.preventDefault(); fullscreen(); }
  if (e.key === 'Escape') { drawer(false); $('modal').classList.remove('on'); }
});
if (T) {
  T.event.listen('panel', e => setPanelUi(e.payload));
  T.event.listen('visible', e => { if (e.payload) { pollRate(); pollRouter(); } });
}

/* ================================================================ views */
function showView(v) {
  S.view = v;
  document.querySelectorAll('.view').forEach(x => x.classList.toggle('on', x.id === 'v-' + v));
  [...$('tabs').children].forEach(b => b.classList.toggle('on', b.dataset.v === v));
  try { localStorage.setItem('view', v); } catch {}
  if (v === 'hist') { loadHist(); pollSpeed(); }
  if (v === 'world') renderWorldLists();
  if (v === 'dns') loadDns();
  if (v === 'sec') { loadSec(); try { localStorage.setItem('seenAlert', S.alerts.length ? S.alerts[0].ts : 0); } catch {} $('secBadge').hidden = true; }
  window.scrollTo(0, 0);
}
$('tabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) showView(b.dataset.v); });

let lastFrame = 0;
function frame(now) {
  if (!document.hidden && now - lastFrame > 90) {
    lastFrame = now;
    if (S.view === 'live') { drawMain(); drawStream(); }
    else if (S.view === 'hist') { drawHist(); drawQuality(); drawSpeed(); }
    else if (S.view === 'world') drawWorld(now);
  }
  requestAnimationFrame(frame);
}
(async () => {
  logEv('lan', 'NetMonitor iniciado');
  await loadHistory();
  pollInfo(); pollRate(); pollPing(); pollRouter(); pollLan(); pollConns(); loadSettings(); pollAlertsBadge();
  setInterval(pollRate, 1000); setInterval(pollPing, 2000); setInterval(pollRouter, 3000);
  setInterval(pollConns, 3000); setInterval(pollLan, 8000); setInterval(pollInfo, 30000);
  setInterval(pollAlertsBadge, 20000);
  setInterval(() => { if (S.view === 'hist' && !speedTimer) loadHist(); if (S.view === 'dns') loadDns(); if (S.view === 'sec') loadSec(); }, 60000);
  setInterval(async () => { try { S.upd = await api('update'); renderUpd(); } catch {} }, 300000);
  let v = 'live'; try { v = localStorage.getItem('view') || 'live'; } catch {}
  showView(v);
  requestAnimationFrame(frame);
})();
