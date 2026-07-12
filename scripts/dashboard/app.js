(function () {
  'use strict';

  const PALETTE = [
    '#00bceb','#3070E7','#00d68f','#ff7e3f','#ec4899',
    '#a855f7','#f59e0b','#10b981','#6366f1','#f43f5e',
    '#0ea5e9','#84cc16','#14b8a6','#fb923c','#8b5cf6',
    '#22d3ee','#a3e635','#fb7185','#fbbf24','#34d399'
  ];

  let state = { rules: [], fileName: '', charts: {} };

  function parseRules(text) {
    const rules = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const m = line.match(/^(alert|drop|pass|block|reject|sdrop|activate|dynamic)\s+(\S+)\s+/i);
      if (!m) continue;
      const parenIdx = line.lastIndexOf('(');
      const opts = parenIdx >= 0 ? line.slice(parenIdx + 1).replace(/\)\s*$/, '') : '';
      rules.push({
        action:    m[1].toLowerCase(),
        protocol:  m[2].toLowerCase(),
        msg:       (opts.match(/\bmsg\s*:\s*"([^"]+)"/)  || [])[1] || '',
        gid:       parseInt((opts.match(/\bgid\s*:\s*(\d+)/)  || [])[1] || '1',  10),
        sid:       parseInt((opts.match(/\bsid\s*:\s*(\d+)/)  || [])[1] || '0',  10),
        rev:       parseInt((opts.match(/\brev\s*:\s*(\d+)/)  || [])[1] || '0',  10),
        classtype: ((opts.match(/\bclasstype\s*:\s*([^;,)]+)/) || [])[1] || '').trim() || '(none)',
      });
    }
    return rules;
  }

  function category(msg) {
    if (!msg) return '(Unknown)';
    const w = msg.split(' ')[0] || '';
    const p = w.split('-');
    if (p.length >= 2 && /^[A-Z]+$/.test(p[0]) && /^[A-Z0-9]+$/.test(p[1]))
      return `${p[0]}-${p[1]}`;
    if (/^[A-Z]{3,}$/.test(p[0])) return p[0];
    return '(Other)';
  }

  function sidBucket(sid) {
    if (!sid) return '(Unknown)';
    const b = Math.floor(sid / 10000) * 10000;
    return `${b.toLocaleString()}–${(b + 9999).toLocaleString()}`;
  }

  function tally(rules, keyFn) {
    const m = new Map();
    for (const r of rules) {
      const k = keyFn(r);
      m.set(k, (m.get(k) || 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function destroyCharts() {
    Object.values(state.charts).forEach(c => { try { c.destroy(); } catch (_) {} });
    state.charts = {};
  }

  function makeChart(id, cfg) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return null;
    return new Chart(el, cfg);
  }

  const GRID_COLOR  = '#1a2d55';
  const TICK_COLOR  = '#8fa4c8';
  const LABEL_COLOR = '#ffffff';

  function barCfg(labels, data, color, axisY = false) {
    return {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Rules',
          data,
          backgroundColor: color + 'bb',
          borderColor: color,
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: axisY ? 'y' : 'x',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => {
                const n = +ctx.raw;
                const t = state.rules.length;
                return ` ${n.toLocaleString()} rules (${t ? ((n/t)*100).toFixed(1) : 0}%)`;
              },
            },
          },
        },
        scales: {
          x: { ticks: { color: axisY ? TICK_COLOR : LABEL_COLOR, font: { size: 11 } }, grid: { color: GRID_COLOR } },
          y: { ticks: { color: axisY ? LABEL_COLOR : TICK_COLOR, font: { size: 10 } }, grid: { color: GRID_COLOR } },
        },
      },
    };
  }

  function doughnutCfg(labels, data, colors) {
    return {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data, backgroundColor: colors.map(c => c + 'bb'), borderColor: colors, borderWidth: 1 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: LABEL_COLOR, font: { size: 11 }, boxWidth: 14, padding: 10 },
          },
          tooltip: {
            callbacks: {
              label: ctx => {
                const n = +ctx.raw;
                const t = state.rules.length;
                return ` ${ctx.label}: ${n.toLocaleString()} (${t ? ((n/t)*100).toFixed(1) : 0}%)`;
              },
            },
          },
        },
      },
    };
  }

  function renderCharts(rules) {
    destroyCharts();
    const total = rules.length;
    if (!total) return;

    const actions    = tally(rules, r => r.action);
    const protos     = tally(rules, r => r.protocol).slice(0, 10);
    const cats       = tally(rules, r => category(r.msg)).slice(0, 20);
    const sidBuckets = tally(rules, r => sidBucket(r.sid));
    const classtypes = tally(rules, r => r.classtype).slice(0, 15);
    const gids       = tally(rules, r => String(r.gid));

    state.charts.action = makeChart('dashChartAction',
      barCfg(actions.map(a => a[0].toUpperCase()), actions.map(a => a[1]), '#00bceb', true));

    state.charts.protocol = makeChart('dashChartProtocol',
      doughnutCfg(
        protos.map(p => p[0].toUpperCase()),
        protos.map(p => p[1]),
        PALETTE.slice(0, protos.length)
      ));

    state.charts.category = makeChart('dashChartCategory',
      barCfg(cats.map(c => c[0]), cats.map(c => c[1]), '#00bceb', true));

    state.charts.sid = makeChart('dashChartSid',
      barCfg(sidBuckets.map(s => s[0]), sidBuckets.map(s => s[1]), '#3070E7'));

    state.charts.classtype = makeChart('dashChartClasstype',
      barCfg(classtypes.map(c => c[0]), classtypes.map(c => c[1]), '#ec4899', true));

    state.charts.gid = makeChart('dashChartGid',
      doughnutCfg(
        gids.map(g => `GID ${g[0]}`),
        gids.map(g => g[1]),
        ['#00bceb', '#ff7e3f', '#a855f7'].slice(0, gids.length)
      ));
  }

  function renderKpis(rules) {
    const el = document.getElementById('dashKpiBar');
    if (!el) return;
    const total = rules.length;
    el.innerHTML = [
      { v: total.toLocaleString(),                              l: 'Total Rules',  cls: 'cyan'   },
      { v: new Set(rules.map(r => r.sid)).size.toLocaleString(), l: 'Unique SIDs',  cls: 'blue'   },
      { v: new Set(rules.map(r => category(r.msg))).size,       l: 'Categories',   cls: 'green'  },
      { v: new Set(rules.map(r => r.protocol)).size,             l: 'Protocols',    cls: 'orange' },
      { v: new Set(rules.map(r => r.action)).size,               l: 'Actions',      cls: 'gray'   },
    ].map(k => `
      <div class="mig-kpi-card ${k.cls}">
        <div class="kpi-val">${k.v}</div>
        <div class="kpi-lbl">${k.l}</div>
      </div>`).join('');
  }

  function renderTable(rules) {
    const tbody = document.querySelector('#dashCategoryTable tbody');
    if (!tbody) return;
    const total = rules.length;
    const cats = tally(rules, r => category(r.msg));
    tbody.innerHTML = cats.slice(0, 50).map((c, i) => {
      const sub = rules.filter(r => category(r.msg) === c[0]);
      const topA = tally(sub, r => r.action)[0]?.[0]?.toUpperCase() || '—';
      const topP = tally(sub, r => r.protocol)[0]?.[0]?.toUpperCase() || '—';
      return `<tr>
        <td>${i + 1}</td>
        <td style="font-weight:600;color:var(--primary)">${esc(c[0])}</td>
        <td>${c[1].toLocaleString()}</td>
        <td>${((c[1] / total) * 100).toFixed(1)}%</td>
        <td>${esc(topA)}</td>
        <td>${esc(topP)}</td>
      </tr>`;
    }).join('');
  }

  function processFile(text, name) {
    state.fileName = name;
    state.rules = parseRules(text);

    const dropZone = document.getElementById('dashDropZone');
    const content  = document.getElementById('dashContent');
    const dlBtn    = document.getElementById('dashDownloadBtn');
    const fileInfo = document.getElementById('dashFileInfo');

    if (!state.rules.length) {
      if (dropZone) {
        dropZone.querySelector('.dash-drop-title').textContent = '⚠ No rules found in file';
        dropZone.querySelector('.dash-drop-sub').textContent   = 'Check that the file contains valid Snort rules';
      }
      return;
    }

    if (dropZone) dropZone.style.display = 'none';
    if (content)  content.style.display  = 'block';
    if (dlBtn)    dlBtn.style.display    = 'inline-flex';
    if (fileInfo) { fileInfo.textContent = `${esc(name)} — ${state.rules.length.toLocaleString()} rules`; fileInfo.style.display = 'block'; }
    const resetEl = document.getElementById('dashResetBtn');
    if (resetEl) resetEl.style.display = 'inline-flex';

    renderKpis(state.rules);
    requestAnimationFrame(() => {
      renderCharts(state.rules);
      renderTable(state.rules);
    });
  }

  function buildDownloadHtml() {
    const rules    = state.rules;
    const total    = rules.length;
    const fname    = state.fileName;
    const actions  = tally(rules, r => r.action);
    const protos   = tally(rules, r => r.protocol).slice(0, 10);
    const cats     = tally(rules, r => category(r.msg));
    const catTop20 = cats.slice(0, 20);
    const sids     = tally(rules, r => sidBucket(r.sid));
    const ctypes   = tally(rules, r => r.classtype).slice(0, 15);
    const gids     = tally(rules, r => String(r.gid));

    const tableRows = cats.slice(0, 50).map((c, i) => {
      const sub  = rules.filter(r => category(r.msg) === c[0]);
      const topA = tally(sub, r => r.action)[0]?.[0]?.toUpperCase()   || '—';
      const topP = tally(sub, r => r.protocol)[0]?.[0]?.toUpperCase() || '—';
      return `<tr><td>${i+1}</td><td>${esc(c[0])}</td><td>${c[1].toLocaleString()}</td><td>${((c[1]/total)*100).toFixed(1)}%</td><td>${esc(topA)}</td><td>${esc(topP)}</td></tr>`;
    }).join('');

    const uniqueSids = new Set(rules.map(r => r.sid)).size;
    const uniqueCats = new Set(rules.map(r => category(r.msg))).size;
    const uniqueProtos = new Set(rules.map(r => r.protocol)).size;
    const uniqueActions = new Set(rules.map(r => r.action)).size;

    const J = v => JSON.stringify(v);
    const PAL = JSON.stringify(PALETTE);

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rules Dashboard — ${esc(fname)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"><\/script>
<style>
*{box-sizing:border-box}
:root{--bg:#061128;--panel:#0a1838;--border:#1a2d55;--primary:#00bceb;--text:#fff;--muted:#8fa4c8}
body{margin:0;padding:24px 28px;background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif;min-height:100vh}
h1{color:var(--primary);font-size:1.5rem;margin:0 0 4px;font-weight:800}
.sub{color:var(--muted);font-size:0.82rem;margin-bottom:22px}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.kpi-card{flex:1;min-width:120px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:13px 18px}
.kpi-val{font-size:1.8rem;font-weight:800;line-height:1}
.kpi-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.kpi-card.c1{border-top:4px solid #00bceb}.kpi-card.c1 .kpi-val{color:#00bceb}
.kpi-card.c2{border-top:4px solid #3070E7}.kpi-card.c2 .kpi-val{color:#60a5fa}
.kpi-card.c3{border-top:4px solid #22C55E}.kpi-card.c3 .kpi-val{color:#4ade80}
.kpi-card.c4{border-top:4px solid #FF9000}.kpi-card.c4 .kpi-val{color:#fb923c}
.kpi-card.c5{border-top:4px solid #64748B}.kpi-card.c5 .kpi-val{color:#94a3b8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.card.wide{grid-column:1/-1}
.card-title{font-size:.78rem;font-weight:700;color:var(--primary);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px}
.ch-wrap{position:relative}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th,td{border:1px solid var(--border);padding:7px 10px;text-align:left;vertical-align:top}
th{background:rgba(0,102,204,.2);color:#9bd7ff;position:sticky;top:0}
tr:nth-child(even){background:rgba(255,255,255,.02)}
.tbl-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.footer{margin-top:20px;color:var(--muted);font-size:.76rem;text-align:center;padding-top:14px;border-top:1px solid var(--border)}
@media(max-width:700px){.grid{grid-template-columns:1fr}.card.wide{grid-column:1}}
</style>
</head>
<body>
<h1>📊 Rules Dashboard</h1>
<div class="sub">File: <strong>${esc(fname)}</strong>&nbsp;·&nbsp;Generated: ${new Date().toLocaleString()}&nbsp;·&nbsp;Total: <strong>${total.toLocaleString()}</strong> rules</div>
<div class="kpi-row">
  <div class="kpi-card c1"><div class="kpi-val">${total.toLocaleString()}</div><div class="kpi-lbl">Total Rules</div></div>
  <div class="kpi-card c2"><div class="kpi-val">${uniqueSids.toLocaleString()}</div><div class="kpi-lbl">Unique SIDs</div></div>
  <div class="kpi-card c3"><div class="kpi-val">${uniqueCats}</div><div class="kpi-lbl">Categories</div></div>
  <div class="kpi-card c4"><div class="kpi-val">${uniqueProtos}</div><div class="kpi-lbl">Protocols</div></div>
  <div class="kpi-card c5"><div class="kpi-val">${uniqueActions}</div><div class="kpi-lbl">Actions</div></div>
</div>
<div class="grid">
  <div class="card"><div class="card-title">Action Distribution</div><div class="ch-wrap" style="height:${Math.max(160, actions.length*38)}px"><canvas id="cAction"></canvas></div></div>
  <div class="card"><div class="card-title">Protocol Distribution</div><div class="ch-wrap" style="height:${Math.max(160, protos.length*22+60)}px"><canvas id="cProtocol"></canvas></div></div>
  <div class="card wide"><div class="card-title">Top 20 Categories</div><div class="ch-wrap" style="height:${Math.max(280, catTop20.length*32)}px"><canvas id="cCategory"></canvas></div></div>
  <div class="card"><div class="card-title">SID Range Distribution</div><div class="ch-wrap" style="height:${Math.max(200, sids.length*32+20)}px"><canvas id="cSid"></canvas></div></div>
  <div class="card"><div class="card-title">GID Distribution</div><div class="ch-wrap" style="height:${Math.max(160, gids.length*22+60)}px"><canvas id="cGid"></canvas></div></div>
  <div class="card wide"><div class="card-title">Top 15 Classtypes</div><div class="ch-wrap" style="height:${Math.max(200, ctypes.length*32)}px"><canvas id="cClasstype"></canvas></div></div>
</div>
<div class="tbl-card">
  <div class="card-title">Category Details — Top 50</div>
  <div style="overflow:auto"><table>
    <thead><tr><th>#</th><th>Category</th><th>Count</th><th>%</th><th>Top Action</th><th>Top Protocol</th></tr></thead>
    <tbody>${tableRows}</tbody>
  </table></div>
</div>
<div class="footer">Generated by Snort Rule Converter · Rules Dashboard</div>
<script>
(function(){
const P=${PAL},T=${total},G='#1a2d55',TC='#8fa4c8',LC='#ffffff';
function bar(id,labels,data,color,vert){
  const c=document.getElementById(id);if(!c)return;
  new Chart(c,{type:'bar',data:{labels,datasets:[{data,backgroundColor:color+'bb',borderColor:color,borderWidth:1,borderRadius:4}]},
  options:{responsive:true,maintainAspectRatio:false,indexAxis:vert?'y':'x',plugins:{legend:{display:false},tooltip:{callbacks:{label:x=>` ${(+x.raw).toLocaleString()} (${T?((+x.raw/T)*100).toFixed(1):0}%)`}}},
  scales:{x:{ticks:{color:vert?TC:LC,font:{size:10}},grid:{color:G}},y:{ticks:{color:vert?LC:TC,font:{size:10}},grid:{color:G}}}}});
}
function donut(id,labels,data,colors){
  const c=document.getElementById(id);if(!c)return;
  new Chart(c,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:colors.map(x=>x+'bb'),borderColor:colors,borderWidth:1}]},
  options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:LC,font:{size:11},boxWidth:14,padding:8}},tooltip:{callbacks:{label:x=>` ${x.label}: ${(+x.raw).toLocaleString()} (${T?((+x.raw/T)*100).toFixed(1):0}%)`}}}}});
}
bar('cAction',${J(actions.map(a=>a[0].toUpperCase()))},${J(actions.map(a=>a[1]))},'#00bceb',true);
donut('cProtocol',${J(protos.map(p=>p[0].toUpperCase()))},${J(protos.map(p=>p[1]))},P.slice(0,${protos.length}));
bar('cCategory',${J(catTop20.map(c=>c[0]))},${J(catTop20.map(c=>c[1]))},'#00bceb',true);
bar('cSid',${J(sids.map(s=>s[0]))},${J(sids.map(s=>s[1]))},'#3070E7',false);
donut('cGid',${J(gids.map(g=>'GID '+g[0]))},${J(gids.map(g=>g[1]))},${ J(['#00bceb','#ff7e3f','#a855f7','#10b981','#f59e0b'].slice(0, gids.length)) });
bar('cClasstype',${J(ctypes.map(c=>c[0]))},${J(ctypes.map(c=>c[1]))},'#ec4899',true);
})();
<\/script>
</body>
</html>`;
  }

  function downloadHtml() {
    if (!state.rules.length) return;
    const html = buildDownloadHtml();
    const blob  = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url   = URL.createObjectURL(blob);
    const a     = Object.assign(document.createElement('a'), {
      href:     url,
      download: `rules-dashboard-${state.fileName.replace(/\.[^.]+$/, '')}-${new Date().toISOString().slice(0,10)}.html`,
    });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  document.addEventListener('DOMContentLoaded', () => {
    const uploadBtn = document.getElementById('dashUploadBtn');
    const fileInput = document.getElementById('dashFileInput');
    const dropZone  = document.getElementById('dashDropZone');
    const dlBtn     = document.getElementById('dashDownloadBtn');
    const resetBtn  = document.getElementById('dashResetBtn');

    if (!uploadBtn) return;

    uploadBtn.addEventListener('click', () => fileInput.click());

    dlBtn?.addEventListener('click', downloadHtml);

    resetBtn?.addEventListener('click', () => {
      state.rules = [];
      state.fileName = '';
      destroyCharts();
      const content  = document.getElementById('dashContent');
      const dz       = document.getElementById('dashDropZone');
      if (content) content.style.display = 'none';
      if (dz) {
        dz.style.display = '';
        dz.querySelector('.dash-drop-title').textContent = 'Drop your .rules file here';
        dz.querySelector('.dash-drop-sub').textContent   = 'or click "Upload .rules file" above';
      }
      if (dlBtn)    dlBtn.style.display    = 'none';
      if (fileInput) fileInput.value = '';
    });

    fileInput.addEventListener('change', e => {
      const f = e.target.files?.[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => processFile(String(r.result || ''), f.name);
      r.readAsText(f);
    });

    dropZone?.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone?.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      const f = e.dataTransfer.files?.[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => processFile(String(r.result || ''), f.name);
      r.readAsText(f);
    });
    dropZone?.addEventListener('click', () => fileInput.click());
  });
})();
