'use strict';

const SEVERITY = { OK: 'ok', INFO: 'info', WARN: 'warn', CRIT: 'crit' };

function fmtInt(n) {
  if (n === null || n === undefined || !Number.isFinite(n)) return '-';
  return Math.round(n).toLocaleString('en-US');
}
function fmtBytes(n) {
  if (!Number.isFinite(n) || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}
function fmtBps(n) {
  if (!Number.isFinite(n) || n === 0) return '0 bps';
  const bits = n * 8;
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bits) / Math.log(1000)));
  return (bits / Math.pow(1000, i)).toFixed(2) + ' ' + units[i];
}
function fmtPps(n) {
  if (!Number.isFinite(n)) return '-';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + ' Mpps';
  if (n >= 1e3) return (n / 1e3).toFixed(2) + ' Kpps';
  return Math.round(n).toLocaleString('en-US') + ' pps';
}
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function statCard(label, value, sub, sev) {
  return `<div class="stat-card ${sev || ''}">
    <div class="label">${escapeHtml(label)}</div>
    <div class="value">${escapeHtml(value)}</div>
    ${sub ? `<div class="sub">${escapeHtml(sub)}</div>` : ''}
  </div>`;
}

function findingCard(sev, title, body) {
  return `<div class="finding ${sev}">
    <div class="finding-title"><span class="sev ${sev}">${sev.toUpperCase()}</span><span class="finding-name">${escapeHtml(title)}</span></div>
    <div class="finding-detail">${body}</div>
  </div>`;
}

function table(headers, rows) {
  return `<table>
    <thead><tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c === undefined || c === null ? '-' : (typeof c === 'object' && c && c.html ? c.html : escapeHtml(c))}</td>`).join('')}</tr>`).join('')}</tbody>
  </table>`;
}

function sectionBlock(id, title, body) {
  return `<div class="section" id="sec-${id}">
    <div class="section-header">
      <h2>${escapeHtml(title)}</h2>
    </div>
    <div class="section-body">${body}</div>
  </div>`;
}

function renderDeviceSummary(data) {
  const mode = data.bundleMode || 'ftd';
  const v = data.version || {};
  const fw = data.firewall || {};
  const fo = data.failover || {};
  const fmc = data.fmcData || {};

  if (mode === 'fmc') {
    return `<div class="summary-grid">
      ${statCard('FMC Hostname', fmc.hostname || '-')}
      ${statCard('FMC Version', fmc.fmcVersion || '-')}
      ${statCard('FX-OS Version', fmc.fxosVersion || '-')}
      ${statCard('SRU', fmc.sru || '-')}
      ${statCard('VDB', fmc.vdb || '-')}
      ${statCard('Snort 2 Engine', fmc.snort2Engine || '-')}
      ${statCard('Snort 3 Engine', fmc.snort3Engine || '-')}
      ${statCard('GeoDB', fmc.geodb || '-')}
    </div>`;
  }

  if (mode === 'both') {
    return `<div class="summary-grid">
      ${statCard('FTD Hostname', v.hostname || '-')}
      ${statCard('FTD Platform', v.platform || '-')}
      ${statCard('FTD Software', v.softwareVersion || '-')}
      ${statCard('FTD Serial', v.serial || '-')}
      ${statCard('FMC Hostname', fmc.hostname || '-')}
      ${statCard('FMC Version', fmc.fmcVersion || '-')}
      ${statCard('FMC SRU', fmc.sru || '-')}
      ${statCard('FMC VDB', fmc.vdb || '-')}
      ${statCard('Failover', fo.enabled ? `${fo.unit} (${fo.state})` : 'Disabled')}
      ${statCard('Clock', data.clock || '-')}
      ${statCard('Firewall Mode', fw.mode || data.mode || '-')}
      ${statCard('Uptime', v.uptime || '-')}
    </div>`;
  }

  const cards = [
    statCard('Hostname', v.hostname || '-'),
    statCard('Platform', v.platform || '-'),
    statCard('Software', v.softwareVersion || '-'),
    statCard('Serial', v.serial || '-'),
    statCard('Uptime', v.uptime || '-'),
    statCard('Firewall Mode', fw.mode || data.mode || '-'),
    statCard('Failover', fo.enabled ? `${fo.unit} (${fo.state})` : 'Disabled'),
    statCard('Clock', data.clock || '-'),
  ].join('');
  return `<div class="summary-grid">${cards}</div>`;
}

function evaluateHealth(data) {
  const findings = [];
  const mode = data.bundleMode || 'ftd';
  if (mode === 'fmc') return '<div class="findings"></div>';

  if (data.cpu) {
    const c = data.cpu;
    let sev = SEVERITY.OK;
    if (c.min5 >= 90) sev = SEVERITY.CRIT;
    else if (c.min5 >= 70) sev = SEVERITY.WARN;
    findings.push(findingCard(sev,
      `CPU usage — 5s ${c.sec5}% / 1min ${c.min1}% / 5min ${c.min5}%`,
      sev === SEVERITY.OK ? 'Within normal range' :
        sev === SEVERITY.WARN ? 'Warning: sustained high load may delay traffic processing' :
        'Critical: traffic drop highly likely'));
  }

  if (data.memory) {
    const m = data.memory;
    let sev = SEVERITY.OK;
    if (m.usedPct >= 90) sev = SEVERITY.CRIT;
    else if (m.usedPct >= 80) sev = SEVERITY.WARN;
    findings.push(findingCard(sev,
      `Memory usage ${m.usedPct}% (${fmtBytes(m.usedBytes)} / ${fmtBytes(m.totalBytes)})`,
      `Free: ${fmtBytes(m.freeBytes)} (${m.freePct}%)`));
  }

  if (data.connCount) {
    const c = data.connCount;
    const pct = c.mostUsed ? (c.inUse / c.mostUsed * 100).toFixed(1) : 0;
    findings.push(findingCard(SEVERITY.INFO,
      `Connections — current ${fmtInt(c.inUse)} / peak ${fmtInt(c.mostUsed)}`,
      `Current vs peak: ${pct}%`));
  }

  if (data.xlateCount) {
    const x = data.xlateCount;
    findings.push(findingCard(SEVERITY.INFO,
      `NAT translations — current ${fmtInt(x.inUse)} / peak ${fmtInt(x.mostUsed)}`, ''));
  }

  if (data.blocks && data.blocks.length) {
    const failed = data.blocks.filter(b => b.failed > 0);
    if (failed.length) {
      findings.push(findingCard(SEVERITY.WARN, `Block allocation failures detected`,
        table(['Size', 'Max', 'Low', 'Cnt', 'Failed'],
          failed.map(b => [b.size, fmtInt(b.max), fmtInt(b.low), fmtInt(b.cnt), fmtInt(b.failed)]))));
    } else {
      findings.push(findingCard(SEVERITY.OK, `No block allocation failures`,
        `${data.blocks.length} pools healthy`));
    }
  }

  if (data.aspDrop) {
    const top = [...data.aspDrop.frame, ...data.aspDrop.flow].sort((a, b) => b.count - a.count).slice(0, 5);
    if (top.length && top[0].count > 0) {
      const sev = top[0].count > 1e9 ? SEVERITY.CRIT : top[0].count > 1e6 ? SEVERITY.WARN : SEVERITY.INFO;
      findings.push(findingCard(sev, `ASP Drop Top 5`,
        table(['Reason', 'Count'], top.map(d => [`${d.desc} (${d.reason})`, fmtInt(d.count)]))));
    }
  }

  if (data.interfaces && data.interfaces.length) {
    const down = data.interfaces.filter(i => !i.lineUp || !i.adminUp);
    if (down.length) {
      findings.push(findingCard(SEVERITY.WARN, `${down.length} interface(s) down`,
        table(['Interface', 'Nameif', 'Admin', 'Line'],
          down.map(i => [i.name, i.nameif, i.adminUp ? 'up' : 'down', i.lineUp ? 'up' : 'down']))));
    }
    const errs = data.interfaces.filter(i => i.inputErrors > 0 || i.outputErrors > 0 || i.overruns > 0);
    if (errs.length) {
      findings.push(findingCard(SEVERITY.WARN, `Interface errors detected (${errs.length})`,
        table(['Interface', 'In Err', 'Out Err', 'Overrun', 'Drops'],
          errs.map(i => [i.name, fmtInt(i.inputErrors), fmtInt(i.outputErrors), fmtInt(i.overruns), fmtInt(i.drops)]))));
    }
  }

  if (data.snortStats) {
    const s = data.snortStats;
    const total = s.passed + s.blocked;
    const blockPct = total ? (s.blocked / total * 100).toFixed(2) : 0;
    const bypassed = s.bypassedDown + s.bypassedBusy;
    let sev = SEVERITY.OK;
    if (s.bypassedBusy > 0) sev = SEVERITY.WARN;
    if (s.bypassedDown > 0) sev = SEVERITY.CRIT;
    findings.push(findingCard(sev,
      `Snort stats — block rate ${blockPct}%, Bypass ${fmtInt(bypassed)}`,
      `Passed ${fmtInt(s.passed)} · Blocked ${fmtInt(s.blocked)} · Bypassed Down ${fmtInt(s.bypassedDown)} · Bypassed Busy ${fmtInt(s.bypassedBusy)}`));
  }

  return `<div class="findings">${findings.join('')}</div>`;
}

function renderTrafficSection(traffic) {
  if (!traffic || (!traffic.interfaces.length && !traffic.aggregated.length)) {
    return '<p style="color:var(--text-dim)">No data</p>';
  }
  const headers = ['Interface', 'RX Pkts', 'RX Bytes', 'RX 1m PPS', 'RX 1m bps',
                   'TX Pkts', 'TX Bytes', 'TX 1m PPS', 'TX 1m bps', 'Avg Pkt'];
  const renderRows = list => list.map(t => [
    t.name,
    fmtInt(t.rxPkts), fmtBytes(t.rxBytes), fmtPps(t.m1InPps), fmtBps(t.m1InBps),
    fmtInt(t.txPkts), fmtBytes(t.txBytes), fmtPps(t.m1OutPps), fmtBps(t.m1OutBps),
    fmtInt(t.avgPktSize) + ' B',
  ]);
  let html = '';
  if (traffic.aggregated.length) {
    const agg = traffic.aggregated[0];
    html += `<div class="summary-grid" style="margin-bottom:16px">
      ${statCard('Total Avg Pkt Size', fmtInt(agg.avgPktSize) + ' B', '(RX+TX bytes) / (RX+TX pkts)')}
      ${statCard('Avg RX Pkt', fmtInt(agg.avgRxPktSize) + ' B')}
      ${statCard('Avg TX Pkt', fmtInt(agg.avgTxPktSize) + ' B')}
      ${statCard('Total Throughput (1m)', fmtBps(agg.m1InBps + agg.m1OutBps))}
      ${statCard('Total PPS (1m)', fmtPps(agg.m1InPps + agg.m1OutPps))}
    </div>`;
  }
  if (traffic.interfaces.length) {
    html += '<h3 style="margin:16px 0 8px;font-size:14px;color:var(--text-dim)">Per-Interface</h3>'
      + table(headers, renderRows(traffic.interfaces));
  }
  if (traffic.aggregated.length) {
    html += '<h3 style="margin:16px 0 8px;font-size:14px;color:var(--text-dim)">Aggregated (Physical)</h3>'
      + table(headers, renderRows(traffic.aggregated));
  }
  html += '<div class="chart-wrap"><canvas id="chart-traffic"></canvas></div>';
  return html;
}

function renderInterfacesSection(ifaces) {
  if (!ifaces || !ifaces.length) return '<p style="color:var(--text-dim)">No data</p>';
  const rows = ifaces.map(i => [
    i.name, i.nameif,
    (i.adminUp ? 'up' : 'DOWN') + '/' + (i.lineUp ? 'up' : 'DOWN'),
    i.speed, i.mtu, i.mac,
    fmtInt(i.inputPkts), fmtInt(i.outputPkts),
    fmtInt(i.inputErrors), fmtInt(i.outputErrors),
    fmtInt(i.overruns), fmtInt(i.drops),
  ]);
  return table(
    ['Name', 'Nameif', 'Admin/Line', 'Speed', 'MTU', 'MAC', 'In Pkts', 'Out Pkts', 'In Err', 'Out Err', 'Overrun', 'Drops'],
    rows
  );
}

function renderAspDropSection(asp) {
  if (!asp) return '<p style="color:var(--text-dim)">No data</p>';
  let html = '';
  if (asp.frame.length) {
    html += '<h3 style="margin:8px 0;font-size:14px;color:var(--text-dim)">Frame Drops</h3>'
      + table(['Reason', 'Code', 'Count'], asp.frame.map(d => [d.desc, d.reason, fmtInt(d.count)]));
  }
  if (asp.flow.length) {
    html += '<h3 style="margin:16px 0 8px;font-size:14px;color:var(--text-dim)">Flow Drops</h3>'
      + table(['Reason', 'Code', 'Count'], asp.flow.map(d => [d.desc, d.reason, fmtInt(d.count)]));
  }
  html += '<div class="chart-wrap"><canvas id="chart-asp"></canvas></div>';
  return html || '<p style="color:var(--text-dim)">No drops</p>';
}

function renderResourceSection(rows) {
  if (!rows || !rows.length) return '<p style="color:var(--text-dim)">No data</p>';
  return table(['Resource', 'Current', 'Peak', 'Limit', 'Denied', 'Context'],
    rows.map(r => [r.resource, r.current, r.peak, r.limit, r.denied, r.context]));
}

function renderBlocksSection(rows) {
  if (!rows || !rows.length) return '<p style="color:var(--text-dim)">No data</p>';
  return table(['Size', 'Max', 'Low', 'Cnt', 'Failed'],
    rows.map(r => [r.size, fmtInt(r.max), fmtInt(r.low), fmtInt(r.cnt), fmtInt(r.failed)]));
}

function renderSnortSection(s) {
  if (!s) return '<p style="color:var(--text-dim)">No data</p>';
  return `<div class="summary-grid">
    ${statCard('Passed', fmtInt(s.passed))}
    ${statCard('Blocked', fmtInt(s.blocked))}
    ${statCard('Injected', fmtInt(s.injected))}
    ${statCard('Bypassed (Snort Down)', fmtInt(s.bypassedDown), '', s.bypassedDown ? SEVERITY.CRIT : SEVERITY.OK)}
    ${statCard('Bypassed (Snort Busy)', fmtInt(s.bypassedBusy), '', s.bypassedBusy ? SEVERITY.WARN : SEVERITY.OK)}
    ${statCard('Fast-Forwarded', fmtInt(s.fastForwarded))}
    ${statCard('Blacklisted', fmtInt(s.blacklisted))}
    ${statCard('Start-of-Flow', fmtInt(s.startFlows))}
    ${statCard('End-of-Flow', fmtInt(s.endFlows))}
  </div>`;
}

function renderConnXlateSection(data) {
  const c = data.connCount, x = data.xlateCount;
  if (!c && !x) return '<p style="color:var(--text-dim)">No data</p>';
  return `<div class="summary-grid">
    ${c ? statCard('Connections in use', fmtInt(c.inUse)) : ''}
    ${c ? statCard('Connections most used', fmtInt(c.mostUsed)) : ''}
    ${x ? statCard('Xlate in use', fmtInt(x.inUse)) : ''}
    ${x ? statCard('Xlate most used', fmtInt(x.mostUsed)) : ''}
  </div>`;
}

function renderCpuMemSection(data) {
  const c = data.cpu, m = data.memory;
  if (!c && !m) return '<p style="color:var(--text-dim)">No data</p>';
  return `<div class="summary-grid">
    ${c ? statCard('CPU 5s', c.sec5 + '%') : ''}
    ${c ? statCard('CPU 1min', c.min1 + '%') : ''}
    ${c ? statCard('CPU 5min', c.min5 + '%') : ''}
    ${m ? statCard('Memory Used', m.usedPct + '%', fmtBytes(m.usedBytes)) : ''}
    ${m ? statCard('Memory Free', m.freePct + '%', fmtBytes(m.freeBytes)) : ''}
    ${m ? statCard('Memory Total', fmtBytes(m.totalBytes)) : ''}
  </div>`;
}

function renderCharts(data) {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = '#8aa0bd';
  Chart.defaults.borderColor = '#22426a';

  if (data.traffic && data.traffic.interfaces.length) {
    const ctx = document.getElementById('chart-traffic');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: data.traffic.interfaces.map(t => t.name),
          datasets: [
            { label: 'RX bps (1m)', data: data.traffic.interfaces.map(t => t.m1InBps * 8), backgroundColor: '#049fd9' },
            { label: 'TX bps (1m)', data: data.traffic.interfaces.map(t => t.m1OutBps * 8), backgroundColor: '#1a3a5c' },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: { y: { ticks: { callback: v => fmtBps(v / 8) } } },
        },
      });
    }
  }

  if (data.aspDrop) {
    const ctx = document.getElementById('chart-asp');
    if (ctx) {
      const top = [...data.aspDrop.frame, ...data.aspDrop.flow].sort((a, b) => b.count - a.count).slice(0, 10);
      if (top.length && top[0].count > 0) {
        new Chart(ctx, {
          type: 'bar',
          data: {
            labels: top.map(d => d.reason),
            datasets: [{ label: 'Drop count', data: top.map(d => d.count), backgroundColor: '#e74c3c' }],
          },
          options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false },
        });
      }
    }
  }
}

function renderSoftwareVersions(v) {
  if (!v) return '<p style="color:var(--text-dim)">No data</p>';
  const NA = { html: '<span style="color:var(--text-dim)">Not available in this bundle</span>' };
  const NONE = { html: '<span style="color:var(--text-dim)">Not configured</span>' };
  const cell = (val) => (val ? String(val) : NA);
  const siCell = (cat) => {
    if (!cat) return NONE;
    const lines = [];
    const push = (label, arr) => {
      if (!arr || !arr.length) return;
      const items = arr.map(n => `<li>${escapeHtml(n)}</li>`).join('');
      lines.push(`<div style="margin-bottom:4px"><strong>${label}</strong><ul style="margin:2px 0 0 18px;padding:0">${items}</ul></div>`);
    };
    if (Array.isArray(cat)) {
      push('Policy', cat);
    } else {
      push('Block', cat.block);
      push('Monitor', cat.monitor);
      push('Do-Not-Block', cat.whitelist);
    }
    return lines.length ? { html: lines.join('') } : NONE;
  };
  const si = v.siActive || null;
  const rows = [
    ['SRU (Rules update)', cell(v.sru)],
    ['VDB (Vulnerability DB)', cell(v.vdb)],
    ['Security Intelligence — IP Reputation (Network)', siCell(si && si.network)],
    ['Security Intelligence — DNS', siCell(si && si.dns)],
    ['Security Intelligence — URL', siCell(si && si.url)],
    ['LSP (Snort 3 Lightweight Security Package)', cell(v.lsp)],
    ['GeoDB', cell(v.geodb)],
    ['Snort engine version', cell(v.snortEngine)],
  ];
  return table(['Component', 'Active feeds / lists'], rows);
}

function renderFmcOverview(data) {
  const f = data.fmcData || {};
  return `<div class="summary-grid">
    ${statCard('FMC Version', f.fmcVersion || '-')}
    ${statCard('FX-OS Version', f.fxosVersion || '-')}
    ${statCard('Hostname', f.hostname || '-')}
    ${statCard('SRU', f.sru || '-')}
    ${statCard('VDB', f.vdb || '-')}
    ${statCard('Snort 2 Engine', f.snort2Engine || '-')}
    ${statCard('Snort 3 Engine', f.snort3Engine || '-')}
  </div>`;
}

function renderFmcSectionTable(rows) {
  return table(['Component', 'Value'], rows);
}

function renderFmcVersionHostname(data) {
  const f = data.fmcData || {};
  return renderFmcSectionTable([
    ['FMC Version', f.fmcVersion || '-'],
    ['FX-OS Version', f.fxosVersion || '-'],
    ['Hostname', f.hostname || '-'],
  ]);
}

function renderFmcRulePacks(data) {
  const f = data.fmcData || {};
  return renderFmcSectionTable([
    ['Intrusion Rules Update (SRU)', f.sru || '-'],
    ['Rule Pack', f.snortRulePack || '-'],
    ['Decoder Rule Pack', f.snortDecoderPack || '-'],
    ['Policy Pack', f.snortPolicyPack || '-'],
    ['Module Pack', f.snortModulePack || '-'],
  ]);
}

function renderFmcEngines(data) {
  const f = data.fmcData || {};
  return renderFmcSectionTable([
    ['Snort 2 Engine', f.snort2Engine || '-'],
    ['Snort 3 Engine', f.snort3Engine || '-'],
  ]);
}

function renderFmcVdb(data) {
  const f = data.fmcData || {};
  return renderFmcSectionTable([
    ['VDB', f.vdb || '-'],
    ['AppID Version', f.appidVer || '-'],
    ['NAVL Version', f.navlVer || '-'],
  ]);
}

function renderFmcGeodb(data) {
  const f = data.fmcData || {};
  return renderFmcSectionTable([
    ['GeoDB', f.geodb || '-'],
  ]);
}

function renderFmcSftunnel(data) {
  const f = data.fmcData || {};
  if (Array.isArray(f.sftunnelPeers) && f.sftunnelPeers.length) {
    return table(['Peer'], f.sftunnelPeers.map((p) => [p]));
  }
  if (f.sftunnelRaw) {
    return `<pre style="white-space:pre-wrap;word-break:break-word;margin:0">${escapeHtml(f.sftunnelRaw)}</pre>`;
  }
  return '<p style="color:var(--text-dim)">No data</p>';
}

function renderCPUHistory(h) {
  if (!h || !h.series) return '<p style="color:var(--text-dim)">No CPU history available (RRD files not found in bundle)</p>';
  const buckets = [
    { key: 'daily',   label: 'Daily (last 24h, 1-min avg)' },
    { key: 'weekly',  label: 'Weekly (last 7d, 5-min avg)' },
    { key: 'monthly', label: 'Monthly (last 30d, 30-min avg)' },
    { key: 'yearly',  label: 'Yearly (last 365d, hourly avg)' },
  ];
  const stats = `<div class="summary-grid" style="margin-bottom:16px">
    ${statCard('Cores parsed', String(h.cores.length))}
    ${statCard('Snort cores (heuristic)', String(h.snortCores.length))}
    ${statCard('Lina cores (heuristic)', String(h.linaCores.length))}
    ${statCard('Last sample', h.lastUpdate ? new Date(h.lastUpdate * 1000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC' : '-')}
  </div>`;
  let charts = '';
  for (const b of buckets) {
    if (!h.series[b.key]) continue;
    charts += `<h3 style="margin:16px 0 6px;font-size:14px;color:var(--text-dim)">${escapeHtml(b.label)}</h3>
      <div class="chart-wrap" style="height:240px"><canvas id="chart-cpu-${b.key}"></canvas></div>`;
  }
  charts += `<h3 style="margin:16px 0 6px;font-size:14px;color:var(--text-dim)">Per-core heatmap (Daily, 0%=blue → 100%=red)</h3>
    <div class="chart-wrap" style="height:480px;background:#0b1220;padding:8px"><canvas id="chart-cpu-heatmap" style="width:100%;height:100%"></canvas></div>`;
  return stats + charts;
}

function drawCPUHeatmap(canvas, daily, cores) {
  if (!canvas || !daily) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth, cssH = canvas.clientHeight;
  canvas.width = cssW * dpr; canvas.height = cssH * dpr;
  ctx.scale(dpr, dpr);
  const N = daily.timestamps.length;
  const C = cores.length;
  if (!N || !C) return;
  const cellW = cssW / N;
  const cellH = cssH / C;
  // Heat ramp: blue (0%) -> cyan -> green -> yellow -> red (100%)
  const heat = (v) => {
    if (!Number.isFinite(v)) return '#1a2332';
    const t = Math.max(0, Math.min(1, v / 100));
    const r = t < 0.5 ? Math.round(255 * (t * 2)) : 255;
    const g = t < 0.5 ? 255 : Math.round(255 * (1 - (t - 0.5) * 2));
    const b = t < 0.25 ? 255 : t < 0.5 ? Math.round(255 * (1 - (t - 0.25) * 4)) : 0;
    return `rgb(${r},${g},${b})`;
  };
  for (let ci = 0; ci < C; ci++) {
    const series = daily.perCore[cores[ci]];
    for (let ti = 0; ti < N; ti++) {
      ctx.fillStyle = heat(series[ti]);
      ctx.fillRect(ti * cellW, ci * cellH, Math.ceil(cellW), Math.ceil(cellH));
    }
  }
}

function renderCPUCharts(h) {
  if (!h || !h.series || typeof Chart === 'undefined') return;
  const buckets = ['daily', 'weekly', 'monthly', 'yearly'];
  for (const b of buckets) {
    const s = h.series[b];
    const ctx = document.getElementById(`chart-cpu-${b}`);
    if (!s || !ctx) continue;
    const labels = s.timestamps.map(ts => {
      const d = new Date(ts * 1000);
      if (b === 'daily')   return d.toISOString().substring(11, 16);
      if (b === 'weekly')  return d.toISOString().substring(5, 16).replace('T', ' ');
      if (b === 'monthly') return d.toISOString().substring(5, 10);
      return d.toISOString().substring(0, 10);
    });
    new Chart(ctx, {
      type: 'line',
      data: { labels, datasets: [
        { label: 'System avg', data: s.systemAvg, borderColor: '#049fd9', backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
        { label: 'Snort cores', data: s.snortAvg, borderColor: '#e74c3c', backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
        { label: 'Lina cores',  data: s.linaAvg,  borderColor: '#27ae60', backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
        { label: 'Max envelope', data: s.envMax, borderColor: 'rgba(231,76,60,0.25)', backgroundColor: 'transparent', borderWidth: 1, pointRadius: 0, borderDash: [3, 3] },
        { label: 'Min envelope', data: s.envMin, borderColor: 'rgba(39,174,96,0.25)', backgroundColor: 'transparent', borderWidth: 1, pointRadius: 0, borderDash: [3, 3] },
      ]},
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        scales: {
          y: { min: 0, max: 100, ticks: { callback: v => v + '%' } },
          x: { ticks: { maxTicksLimit: 12, autoSkip: true } }
        },
        plugins: { legend: { labels: { boxWidth: 12, font: { size: 11 } } } }
      }
    });
  }
  if (h.series.daily) {
    drawCPUHeatmap(document.getElementById('chart-cpu-heatmap'), h.series.daily, h.cores);
  }
}

// Tab grouping for the analysis report. Section IDs match sectionBlock() ids
// so that DOM IDs (sec-versions etc.) remain stable for any external anchors.
const REPORT_TABS = [
  {
    id: 'overview',
    label: 'Overview',
    sections: [
      ['versions', 'Software Versions (SRU / VDB / Security Intelligence)', d => renderSoftwareVersions(d.versions)],
    ],
  },
  {
    id: 'performance',
    label: 'Performance',
    sections: [
      ['cpuhistory', 'CPU Usage History — D/W/M/Y (per-core RRDs)', d => renderCPUHistory(d.cpuHistory)],
      ['cpumem',     'CPU & Memory (show cpu / show memory)',       d => renderCpuMemSection(d)],
      ['resource',   'Resource usage (show resource usage)',         d => renderResourceSection(d.resourceUsage)],
    ],
  },
  {
    id: 'traffic',
    label: 'Traffic',
    sections: [
      ['connxlate',  'Connections & NAT (show conn count / show xlate count)', d => renderConnXlateSection(d)],
      ['traffic',    'Traffic statistics (show traffic)',                       d => renderTrafficSection(d.traffic)],
      ['interfaces', 'Interface status (show interface)',                       d => renderInterfacesSection(d.interfaces)],
      ['asp',        'ASP Drop (show asp drop)',                                d => renderAspDropSection(d.aspDrop)],
    ],
  },
  {
    id: 'snort',
    label: 'Snort',
    sections: [
      ['snort',  'Snort statistics (show snort statistics)', d => renderSnortSection(d.snortStats)],
      ['blocks', 'Block pools (show blocks)',                d => renderBlocksSection(d.blocks)],
    ],
  },
];

function getReportTabs(data) {
  const mode = data.bundleMode || 'ftd';
  if (mode === 'ftd') return REPORT_TABS;

  const fmcTab = {
    id: 'fmc',
    label: 'FMC',
    sections: [
      ['fmc-version-hostname', 'FMC Version & Hostname', d => renderFmcVersionHostname(d)],
      ['fmc-rules', 'Snort Rule Packs (SRU)', d => renderFmcRulePacks(d)],
      ['fmc-engines', 'Snort Engines', d => renderFmcEngines(d)],
      ['fmc-vdb', 'VDB / AppID / NAVL', d => renderFmcVdb(d)],
      ['fmc-geodb', 'GeoDB', d => renderFmcGeodb(d)],
      ['fmc-sftunnel', 'Sftunnel Peers', d => renderFmcSftunnel(d)],
    ],
  };

  if (mode === 'fmc') {
    return [
      {
        id: 'overview',
        label: 'Overview',
        sections: [
          ['fmc-overview', 'FMC Summary', d => renderFmcOverview(d)],
        ],
      },
      fmcTab,
    ];
  }

  return [...REPORT_TABS, fmcTab];
}

function renderTabBar(tabs, activeId) {
  const buttons = tabs.map(t =>
    `<button type="button" class="ts-tab${t.id === activeId ? ' active' : ''}" data-tab="${t.id}" onclick="window.FPRRenderer.switchTab('${t.id}')">${t.label}</button>`
  ).join('');
  return `<div class="ts-tabbar">${buttons}</div>`;
}

function renderTabPanels(tabs, data, activeId) {
  return tabs.map(t => {
    const body = t.sections
      .map(([id, title, fn]) => sectionBlock(id, title, fn(data)))
      .join('');
    const head = t.id === 'overview'
      ? `<div class="ts-tab-findings">${evaluateHealth(data)}</div>`
      : '';
    return `<div class="ts-tab-panel${t.id === activeId ? ' active' : ''}" data-tab-panel="${t.id}">${head}${body}</div>`;
  }).join('');
}

function switchTab(tabId) {
  document.querySelectorAll('#tsAnalyzerView .ts-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tabId);
  });
  document.querySelectorAll('#tsAnalyzerView .ts-tab-panel').forEach(p => {
    p.classList.toggle('active', p.dataset.tabPanel === tabId);
  });
}

function renderReport(data) {
  document.getElementById('device-summary').innerHTML = renderDeviceSummary(data);
  document.getElementById('health-findings').innerHTML = '';

  const tabs = getReportTabs(data);
  const activeId = tabs[0].id;
  document.getElementById('sections').innerHTML =
    renderTabBar(tabs, activeId) + `<div class="ts-tab-panels">${renderTabPanels(tabs, data, activeId)}</div>`;

  // Render all charts once on load. Hidden tab panels keep their canvases in
  // the DOM (display:none ≠ removed), so tab switches need no re-render.
  setTimeout(() => { renderCharts(data); renderCPUCharts(data.cpuHistory); }, 50);
}

window.FPRRenderer = { renderReport, evaluateHealth, renderCPUCharts, switchTab };
