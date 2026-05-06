'use strict';

const SECTION_MARKER = /^------------------ (show [^\n]+?) ------------------\s*$/gm;

function splitShowTechSections(text) {
  const sections = {};
  const matches = [...text.matchAll(SECTION_MARKER)];
  // Bundle preamble (before the first "------------------ show ... ------------------" marker)
  // carries the device identity (Cisco ... Software Version, Hardware:, Serial Number:, "<host> up ...").
  // Treat it as a synthetic 'show version' section.
  if (matches.length > 0 && matches[0].index > 0) {
    sections['show version'] = text.substring(0, matches[0].index).trim();
  } else if (matches.length === 0) {
    sections['show version'] = text.trim();
  }
  for (let i = 0; i < matches.length; i++) {
    const name = matches[i][1].trim();
    const start = matches[i].index + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index : text.length;
    sections[name] = text.substring(start, end).trim();
  }
  return sections;
}

function parseInt0(s) {
  if (s === undefined || s === null || s === '') return 0;
  const n = parseInt(String(s).replace(/[, ]/g, ''), 10);
  return Number.isFinite(n) ? n : 0;
}

function parseFloat0(s) {
  if (s === undefined || s === null || s === '') return 0;
  const n = parseFloat(String(s).replace(/,/g, ''));
  return Number.isFinite(n) ? n : 0;
}

function parseShowTraffic(text) {
  if (!text) return { interfaces: [], aggregated: [] };
  const interfaces = [];
  const aggregated = [];
  let target = interfaces;

  const blockRegex = /^(\S[^\n:]*):\s*\n\treceived \(in ([\d.]+) secs\):\s*\n\t\t(\d+) packets\s+(\d+) bytes\s*\n\t\t(\d+) pkts\/sec\s+(\d+) bytes\/sec\s*\n\ttransmitted \(in ([\d.]+) secs\):\s*\n\t\t(\d+) packets\s+(\d+) bytes\s*\n\t\t(\d+) pkts\/sec\s+(\d+) bytes\/sec\s*\n\s+1 minute input rate (\d+) pkts\/sec,\s+(\d+) bytes\/sec\s*\n\s+1 minute output rate (\d+) pkts\/sec,\s+(\d+) bytes\/sec\s*\n\s+1 minute drop rate, (\d+) pkts\/sec\s*\n\s+5 minute input rate (\d+) pkts\/sec,\s+(\d+) bytes\/sec\s*\n\s+5 minute output rate (\d+) pkts\/sec,\s+(\d+) bytes\/sec\s*\n\s+5 minute drop rate, (\d+) pkts\/sec/gm;

  const aggMarker = /Aggregated Traffic on Physical Interface/;
  const aggIdx = text.search(aggMarker);

  let m;
  while ((m = blockRegex.exec(text)) !== null) {
    const isAgg = aggIdx >= 0 && m.index >= aggIdx;
    const entry = {
      name: m[1].trim(),
      uptimeSec: parseFloat0(m[2]),
      rxPkts: parseInt0(m[3]),
      rxBytes: parseInt0(m[4]),
      txPkts: parseInt0(m[8]),
      txBytes: parseInt0(m[9]),
      m1InPps: parseInt0(m[13]),
      m1InBps: parseInt0(m[14]),
      m1OutPps: parseInt0(m[15]),
      m1OutBps: parseInt0(m[16]),
      m1DropPps: parseInt0(m[17]),
      m5InPps: parseInt0(m[18]),
      m5InBps: parseInt0(m[19]),
      m5OutPps: parseInt0(m[20]),
      m5OutBps: parseInt0(m[21]),
      m5DropPps: parseInt0(m[22]),
    };
    entry.totalPkts = entry.rxPkts + entry.txPkts;
    entry.totalBytes = entry.rxBytes + entry.txBytes;
    entry.avgPktSize = entry.totalPkts ? entry.totalBytes / entry.totalPkts : 0;
    entry.avgRxPktSize = entry.rxPkts ? entry.rxBytes / entry.rxPkts : 0;
    entry.avgTxPktSize = entry.txPkts ? entry.txBytes / entry.txPkts : 0;
    (isAgg ? aggregated : interfaces).push(entry);
  }
  return { interfaces, aggregated };
}

function parseShowInterface(text) {
  if (!text) return [];
  const ifaces = [];
  const blocks = text.split(/\nInterface /);
  for (let i = 0; i < blocks.length; i++) {
    const block = i === 0 ? blocks[i] : 'Interface ' + blocks[i];
    const head = block.match(/^Interface\s+(\S+)\s+"([^"]*)",\s*is\s+(\S+),\s*line protocol is\s+(\S+)/m);
    if (!head) continue;
    const name = head[1];
    const nameif = head[2];
    const adminUp = head[3] === 'up';
    const lineUp = head[4] === 'up';

    const inputRate = block.match(/(\d+) packets input,\s+(\d+) bytes/);
    const outputRate = block.match(/(\d+) packets output,\s+(\d+) bytes/);
    const inputErrors = block.match(/(\d+) input errors/);
    const outputErrors = block.match(/(\d+) output errors/);
    const overrun = block.match(/(\d+) overrun/);
    const noBuffer = block.match(/(\d+) no buffer/);
    const drops = block.match(/Traffic Statistics for "[^"]*":[\s\S]*?(\d+) packets dropped/);
    const inputRateBps = block.match(/input rate (\d+) pkts\/sec,\s*(\d+) bytes\/sec/);
    const outputRateBps = block.match(/output rate (\d+) pkts\/sec,\s*(\d+) bytes\/sec/);
    const mac = block.match(/MAC address ([0-9a-f.]+)/i);
    const mtu = block.match(/MTU (\d+) bytes/);
    const speed = block.match(/(\d+ \w+ Full|\d+ \w+ Half|Auto-Speed[^\n]*)/);

    ifaces.push({
      name,
      nameif,
      adminUp,
      lineUp,
      mac: mac ? mac[1] : '',
      mtu: mtu ? parseInt0(mtu[1]) : 0,
      speed: speed ? speed[1].trim() : '',
      inputPkts: inputRate ? parseInt0(inputRate[1]) : 0,
      inputBytes: inputRate ? parseInt0(inputRate[2]) : 0,
      outputPkts: outputRate ? parseInt0(outputRate[1]) : 0,
      outputBytes: outputRate ? parseInt0(outputRate[2]) : 0,
      inputErrors: inputErrors ? parseInt0(inputErrors[1]) : 0,
      outputErrors: outputErrors ? parseInt0(outputErrors[1]) : 0,
      overruns: overrun ? parseInt0(overrun[1]) : 0,
      noBuffer: noBuffer ? parseInt0(noBuffer[1]) : 0,
      drops: drops ? parseInt0(drops[1]) : 0,
      inputPps: inputRateBps ? parseInt0(inputRateBps[1]) : 0,
      inputBps: inputRateBps ? parseInt0(inputRateBps[2]) : 0,
      outputPps: outputRateBps ? parseInt0(outputRateBps[1]) : 0,
      outputBps: outputRateBps ? parseInt0(outputRateBps[2]) : 0,
    });
  }
  return ifaces;
}

function parseShowAspDrop(text) {
  if (!text) return { frame: [], flow: [] };
  const result = { frame: [], flow: [] };
  let bucket = null;
  for (const line of text.split('\n')) {
    if (/^Frame drop:/.test(line)) { bucket = 'frame'; continue; }
    if (/^Flow drop:/.test(line)) { bucket = 'flow'; continue; }
    if (/^Last clearing:/.test(line)) { bucket = null; continue; }
    if (!bucket) continue;
    const m = line.match(/^\s*(.+?)\s+\((\S+?)\)\s+(\d+)\s*$/);
    if (m) {
      const count = parseInt0(m[3]);
      if (count > 0) result[bucket].push({ desc: m[1].trim(), reason: m[2], count });
    }
  }
  result.frame.sort((a, b) => b.count - a.count);
  result.flow.sort((a, b) => b.count - a.count);
  return result;
}

function parseShowCpuUsage(text) {
  if (!text) return null;
  const m = text.match(/CPU utilization for 5 seconds = (\d+)%; 1 minute: (\d+)%; 5 minutes: (\d+)%/);
  if (!m) return null;
  return { sec5: parseInt0(m[1]), min1: parseInt0(m[2]), min5: parseInt0(m[3]) };
}

function parseShowMemory(text) {
  if (!text) return null;
  const free = text.match(/Free memory:\s+(\d+) bytes\s+\((\d+)%\)/);
  const used = text.match(/Used memory:\s+(\d+) bytes\s+\((\d+)%\)/);
  const total = text.match(/Total memory:\s+(\d+) bytes/);
  if (!free || !used || !total) return null;
  return {
    freeBytes: parseInt0(free[1]),
    freePct: parseInt0(free[2]),
    usedBytes: parseInt0(used[1]),
    usedPct: parseInt0(used[2]),
    totalBytes: parseInt0(total[1]),
  };
}

function parseShowBlocks(text) {
  if (!text) return [];
  const rows = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/);
    if (m) {
      rows.push({
        size: parseInt0(m[1]),
        max: parseInt0(m[2]),
        low: parseInt0(m[3]),
        cnt: parseInt0(m[4]),
        failed: parseInt0(m[5]),
      });
    }
  }
  return rows;
}

function parseShowConnCount(text) {
  if (!text) return null;
  const m = text.match(/(\d+) in use,\s*(\d+) most used/);
  if (!m) return null;
  return { inUse: parseInt0(m[1]), mostUsed: parseInt0(m[2]) };
}

function parseShowXlateCount(text) {
  if (!text) return null;
  const m = text.match(/(\d+) in use,\s*(\d+) most used/);
  if (!m) return null;
  return { inUse: parseInt0(m[1]), mostUsed: parseInt0(m[2]) };
}

function parseShowFirewall(text) {
  if (!text) return null;
  const m = text.match(/Firewall mode:\s*(\S+)/);
  return m ? { mode: m[1] } : null;
}

function parseShowFailover(text) {
  if (!text) return null;
  const onMatch = text.match(/Failover (On|Off)/);
  const unitMatch = text.match(/Failover unit (\S+)/);
  const stateMatch = text.match(/This host:\s*\S+\s*-\s*(\S+)/);
  return {
    enabled: onMatch ? onMatch[1] === 'On' : false,
    unit: unitMatch ? unitMatch[1] : '',
    state: stateMatch ? stateMatch[1] : '',
  };
}

function parseShowVersion(text) {
  if (!text) return {};
  const out = {};
  const grab = (re) => { const m = text.match(re); return m ? m[1].trim() : ''; };
  out.platform = grab(/Hardware:\s*([^,\n]+)/);
  out.serial = grab(/Serial Number:\s*(\S+)/);
  out.softwareVersion = grab(/Cisco (?:Adaptive Security Appliance|Firepower Threat Defense) Software Version\s+(\S+)/i)
    || grab(/Software Version\s+(\S+)/);
  out.uptime = grab(/^\S+ up\s+(.+)$/m);
  out.hostname = grab(/^(\S+) up\s+/m);
  out.model = grab(/Model\s*:\s*(.+?)\s*$/m);
  return out;
}

function parseShowSnortStatistics(text) {
  if (!text) return null;
  const grab = (re) => { const m = text.match(re); return m ? parseInt0(m[1]) : 0; };
  return {
    passed: grab(/Passed Packets\s+(\d+)/),
    blocked: grab(/Blocked Packets\s+(\d+)/),
    injected: grab(/Injected Packets\s+(\d+)/),
    bypassedDown: grab(/Packets bypassed \(Snort Down\)\s+(\d+)/),
    bypassedBusy: grab(/Packets bypassed \(Snort Busy\)\s+(\d+)/),
    fastForwarded: grab(/Fast-Forwarded Flows\s+(\d+)/),
    blacklisted: grab(/Blacklisted Flows\s+(\d+)/),
    startFlows: grab(/Start-of-Flow events\s+(\d+)/),
    endFlows: grab(/End-of-Flow events\s+(\d+)/),
  };
}

function parseShowResourceUsage(text) {
  if (!text) return [];
  const rows = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^(\S+(?:\s\[\S+\])?)\s+(\d+|\S+)\s+(\d+|\S+)\s+(\d+|\S+|unlimited|N\/A)\s+(\d+)\s+(\S+)\s*$/);
    if (m && m[1] !== 'Resource') {
      rows.push({
        resource: m[1].trim(),
        current: m[2],
        peak: m[3],
        limit: m[4],
        denied: m[5],
        context: m[6],
      });
    }
  }
  return rows;
}

function parseShowClock(text) {
  if (!text) return '';
  return text.split('\n')[0].trim();
}

function parseShowMode(text) {
  if (!text) return '';
  const m = text.match(/Security context mode:\s*(\S+)/);
  return m ? m[1] : text.trim();
}

/* parseSoftwareVersions: extracts SRU/VDB from show-tech text and merges
 * Security Intelligence versions captured opportunistically from
 * IPRVersion.dat files (passed via `extras`). LSP/GeoDB/Snort engine are not
 * exposed in standard FTD troubleshoot bundles -> reported as null. */
function parseSoftwareVersions(text, extras) {
  extras = extras || {};
  const grab = (re) => { const m = (text || '').match(re); return m ? m[1].trim() : null; };
  return {
    sru:         grab(/^Rules update version\s*:\s*(\S+)/m),
    vdb:         grab(/^VDB version\s*:\s*(\S+)/m),
    iprep:       extras.iprep || null,
    sidns:       extras.sidns || null,
    siurl:       extras.siurl || null,
    lsp:         null,
    geodb:       null,
    snortEngine: null,
  };
}

function parseCPUHistory(extras) {
  if (!extras || !extras.cpuRrds) return null;
  const cores = Object.keys(extras.cpuRrds).map(n => parseInt(n, 10)).sort((a, b) => a - b);
  if (!cores.length || typeof window === 'undefined' || !window.RRDParser) return null;

  const RRD = window.RRDParser;
  const perCore = {};
  let lastUpdate = 0;
  for (const c of cores) {
    try {
      const rrd = RRD.parseRRD(extras.cpuRrds[c]);
      perCore[c] = rrd;
      if (rrd.lastUpdate > lastUpdate) lastUpdate = rrd.lastUpdate;
    } catch (e) {
      console.warn(`[cpuHistory] core ${c} parse failed:`, e.message);
    }
  }
  const validCores = Object.keys(perCore).map(n => parseInt(n, 10));
  if (!validCores.length) return null;

  const ref = perCore[validCores[0]];
  const rraIdx = RRD.classifyRRAs(ref);
  const buckets = ['daily', 'weekly', 'monthly', 'yearly'];

  const series = {};
  for (const bucket of buckets) {
    const bInfo = rraIdx[bucket];
    if (!bInfo || bInfo.avg == null) { series[bucket] = null; continue; }
    const idx = bInfo.avg;
    const refRows = RRD.rraToSeries(ref, idx);
    const timestamps = refRows.map(r => r.ts);
    const N = timestamps.length;
    const refStep = ref.rras[idx].step;

    const perCoreData = {};
    for (const c of validCores) {
      const rows = RRD.rraToSeries(perCore[c], idx);
      const vals = rows.map(r => r.val);
      perCoreData[c] = vals.length === N ? vals
        : vals.length > N ? vals.slice(vals.length - N)
        : Array(N - vals.length).fill(NaN).concat(vals);
    }

    const systemAvg = new Array(N), envMin = new Array(N), envMax = new Array(N);
    for (let t = 0; t < N; t++) {
      let sum = 0, n = 0, mn = Infinity, mx = -Infinity;
      for (const c of validCores) {
        const v = perCoreData[c][t];
        if (Number.isFinite(v)) { sum += v; n++; if (v < mn) mn = v; if (v > mx) mx = v; }
      }
      systemAvg[t] = n ? sum / n : NaN;
      envMin[t] = n ? mn : NaN;
      envMax[t] = n ? mx : NaN;
    }

    series[bucket] = { timestamps, systemAvg, envMin, envMax, perCore: perCoreData, step: refStep };
  }

  // Heuristic split: cores whose long-term (yearly or monthly) avg sits in the
  // upper tertile are "Snort" (heavy DPI workers); rest are "Lina/system".
  // Falls back to no-split if reference RRA absent.
  const refKey = series.yearly ? 'yearly' : (series.monthly ? 'monthly' : 'daily');
  const refData = series[refKey];
  const coreAvg = {};
  for (const c of validCores) {
    let sum = 0, n = 0;
    for (const v of refData.perCore[c]) { if (Number.isFinite(v)) { sum += v; n++; } }
    coreAvg[c] = n ? sum / n : 0;
  }
  const sortedAvgs = validCores.map(c => coreAvg[c]).sort((a, b) => a - b);
  const cutoff = sortedAvgs[Math.floor(sortedAvgs.length * 0.5)] || 0;
  const snortCores = validCores.filter(c => coreAvg[c] > cutoff);
  const linaCores = validCores.filter(c => coreAvg[c] <= cutoff);

  for (const bucket of buckets) {
    const s = series[bucket];
    if (!s) continue;
    const N = s.timestamps.length;
    const snortAvg = new Array(N), linaAvg = new Array(N);
    for (let t = 0; t < N; t++) {
      let ss = 0, sn = 0, ls = 0, ln = 0;
      for (const c of snortCores) { const v = s.perCore[c][t]; if (Number.isFinite(v)) { ss += v; sn++; } }
      for (const c of linaCores)  { const v = s.perCore[c][t]; if (Number.isFinite(v)) { ls += v; ln++; } }
      snortAvg[t] = sn ? ss / sn : NaN;
      linaAvg[t]  = ln ? ls / ln : NaN;
    }
    s.snortAvg = snortAvg;
    s.linaAvg  = linaAvg;
  }

  return {
    lastUpdate,
    cores: validCores,
    snortCores,
    linaCores,
    series,
  };
}

function parseAll(showTechText, extras) {
  const sections = splitShowTechSections(showTechText);
  return {
    cpuHistory: parseCPUHistory(extras),
    raw: sections,
    clock: parseShowClock(sections['show clock']),
    version: parseShowVersion(sections['show version'] || sections['show inventory']),
    firewall: parseShowFirewall(sections['show firewall']),
    failover: parseShowFailover(sections['show failover']),
    mode: parseShowMode(sections['show mode']),
    cpu: parseShowCpuUsage(sections['show cpu usage']),
    memory: parseShowMemory(sections['show memory']),
    blocks: parseShowBlocks(sections['show blocks']),
    connCount: parseShowConnCount(sections['show conn count']),
    xlateCount: parseShowXlateCount(sections['show xlate count']),
    traffic: parseShowTraffic(sections['show traffic']),
    interfaces: parseShowInterface(sections['show interface']),
    aspDrop: parseShowAspDrop(sections['show asp drop']),
    snortStats: parseShowSnortStatistics(sections['show snort statistics']),
    resourceUsage: parseShowResourceUsage(sections['show resource usage counter all 1']),
  };
}

function findShowTechFile(files) {
  const candidates = files
    .filter(f => /show.tech.*\.txt$/i.test(f.name) || /show_tech_output\.txt$/i.test(f.name))
    .sort((a, b) => b.size - a.size);
  return candidates[0] || null;
}

window.FPRParser = {
  splitShowTechSections,
  parseAll,
  parseSoftwareVersions,
  parseCPUHistory,
  findShowTechFile,
};
