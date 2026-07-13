(function () {
  'use strict';

  const PALETTE = [
    '#00bceb','#3070E7','#00d68f','#ff7e3f','#ec4899',
    '#a855f7','#f59e0b','#10b981','#6366f1','#f43f5e',
    '#0ea5e9','#84cc16','#14b8a6','#fb923c','#8b5cf6',
    '#22d3ee','#a3e635','#fb7185','#fbbf24','#34d399',
  ];

  let state = {
    mode: null,
    rules: [],
    localRules: [],
    v7Stats: null,
    v7LocalRules: [],
    v7Filter: 'all',
    v7Page: 0,
    v7ActiveTab: 'overview',
    table: { headers: [], rows: [], colMeta: [], selectedCols: [] },
    fileName: '',
    charts: {},
  };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  }

  function fileExt(name) { return (name.split('.').pop() || '').toLowerCase(); }
  function isExcelExt(e) { return ['xlsx','xls','xlsm','ods'].includes(e); }

  function destroyCharts() {
    Object.values(state.charts).forEach(c => { try { c.destroy(); } catch (_) {} });
    state.charts = {};
  }

  function tally(arr, keyFn) {
    const m = new Map();
    for (const x of arr) { const k = keyFn(x); m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }

  function parseSnortRules(text) {
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
        msg:       (opts.match(/\bmsg\s*:\s*"([^"]+)"/)        || [])[1] || '',
        gid:       parseInt((opts.match(/\bgid\s*:\s*(\d+)/)   || [])[1] || '1', 10),
        sid:       parseInt((opts.match(/\bsid\s*:\s*(\d+)/)   || [])[1] || '0', 10),
        rev:       parseInt((opts.match(/\brev\s*:\s*(\d+)/)   || [])[1] || '0', 10),
        classtype: ((opts.match(/\bclasstype\s*:\s*([^;,)]+)/) || [])[1] || '').trim() || '(none)',
      });
    }
    return rules;
  }

  function snortCategory(msg) {
    if (!msg) return '(Unknown)';
    const w = msg.split(' ')[0] || '';
    const p = w.split('-');
    if (p.length >= 2 && /^[A-Z]+$/.test(p[0]) && /^[A-Z0-9]+$/.test(p[1])) return p[0]+'-'+p[1];
    if (/^[A-Z]{3,}$/.test(p[0])) return p[0];
    return '(Other)';
  }

  function sidBucket(sid) {
    if (!sid) return '(Unknown)';
    const b = Math.floor(sid / 10000) * 10000;
    return b.toLocaleString()+'~'+(b+9999).toLocaleString();
  }

  function detectDelimiter(line) {
    const s = {',':0,'\t':0,';':0,'|':0};
    for (const c of line) if (s[c]!==undefined) s[c]++;
    return Object.entries(s).sort((a,b)=>b[1]-a[1])[0][0];
  }

  function parseCsvLine(line, delim) {
    const fields = []; let i=0, field='';
    while (i <= line.length) {
      if (i === line.length) { fields.push(field.trim()); break; }
      if (line[i] === '"') {
        i++;
        while (i < line.length) {
          if (line[i]==='"'&&line[i+1]==='"') { field+='"'; i+=2; }
          else if (line[i]==='"') { i++; break; }
          else field+=line[i++];
        }
        while (i<line.length&&line[i]!==delim) i++;
        fields.push(field.trim()); field=''; i++;
      } else {
        const end = line.indexOf(delim, i);
        if (end===-1) { fields.push(line.slice(i).trim()); break; }
        fields.push(line.slice(i,end).trim()); field=''; i=end+delim.length;
      }
    }
    return fields;
  }

  function parseCsv(text) {
    const lines = text.split(/\r?\n/).filter(l=>l.trim());
    if (lines.length < 2) return { headers:[], rows:[] };
    const delim = detectDelimiter(lines[0]);
    const headers = parseCsvLine(lines[0], delim);
    if (headers.length < 2) return { headers:[], rows:[] };
    return { headers, rows: lines.slice(1).map(l=>parseCsvLine(l,delim)) };
  }

  function parseExcel(buffer) {
    if (typeof XLSX === 'undefined') throw new Error('SheetJS not loaded');
    const wb = XLSX.read(new Uint8Array(buffer), { type:'array' });

    // Smart sheet selection:
    // 1) Prefer a sheet whose first row has 5+ non-empty cells
    // 2) Among those, prefer 'All Rules' (our extractor output)
    // 3) Fall back to first sheet
    let targetSheet = wb.SheetNames[0];
    let bestScore = -1;
    for (const name of wb.SheetNames) {
      const ws = wb.Sheets[name];
      const first = XLSX.utils.sheet_to_json(ws, { header:1, defval:'', range:{ s:{r:0,c:0}, e:{r:0,c:30} } });
      const hdrCount = first.length ? first[0].filter(v => v !== '').length : 0;
      const score = hdrCount + (name === 'All Rules' ? 1000 : 0);
      if (score > bestScore) { bestScore = score; targetSheet = name; }
    }

    const ws   = wb.Sheets[targetSheet];
    const data = XLSX.utils.sheet_to_json(ws, { header:1, defval:'' });
    if (!data.length) return { headers:[], rows:[], sheetName: targetSheet };
    const headers = data[0].map(String);
    const rows = data.slice(1)
      .filter(r => r.some(v => v !== ''))
      .map(row => {
        const r = row.map(String).slice(0, headers.length);
        while (r.length < headers.length) r.push('');
        return r;
      });
    return { headers, rows, sheetName: targetSheet };
  }

  // ── Snort Excel Export detection & parsing ─────────────────────────────

  function isSnortXlsxExport(headers) {
    const h = new Set(headers.map(String));
    return ['GID','SID','Message','Rule Details','Rule Action','Status'].every(k => h.has(k));
  }

  function parseSnortXlsx(headers, rows) {
    const col = {};
    headers.forEach((h, i) => { col[String(h)] = i; });
    const get = (r, k) => String(r[col[k]] ?? '').trim();

    return rows
      .filter(r => get(r,'SID') && get(r,'SID') !== '0')
      .map(r => {
        const ruleData = get(r, 'Rule Details');
        const opts     = ruleData.includes('(') ? ruleData.slice(ruleData.lastIndexOf('(') + 1).replace(/\)\s*$/, '') : '';
        const protoM   = ruleData.match(/^\s*\w+\s+(\w+)\s+/);
        const ctM      = opts.match(/\bclasstype\s*:\s*([^;,)]+)/);
        return {
          type:      get(r, 'Type') || 'B',
          gid:       parseInt(get(r, 'GID'))  || 1,
          sid:       parseInt(get(r, 'SID'))  || 0,
          msg:       get(r, 'Message'),
          ruleData,
          action:    get(r, 'Rule Action').toUpperCase(),
          status:    get(r, 'Status'),
          groups:    get(r, 'Assigned Groups') || '—',
          protocol:  protoM ? protoM[1].toUpperCase() : '(Unknown)',
          classtype: ctM    ? ctM[1].trim()            : '(none)',
        };
      });
  }

  // ── v7 Multi-sheet Excel detection ────────────────────────────────────

  function isSnortV7Format(wb) {
    const n = new Set(wb.SheetNames);
    return n.has('All Rules') && n.has('Local') && n.has('Built-in');
  }

  function detectUnnecessaryJS(rule) {
    const reasons = [];
    const rd = rule.ruleData || '';
    if (rule.status === 'Disabled') reasons.push('비활성화 상태 룰');
    const detPtns = [/content\s*:/i,/pcre\s*:/i,/byte_test\s*:/i,/byte_jump\s*:/i,
      /byte_extract\s*:/i,/isdataat\s*:/i,/dsize\s*:/i,/file_data\s*[;:]/i];
    const hasDet = detPtns.some(p => p.test(rd));
    if (!hasDet) reasons.push('탐지 내용 없음 (content/pcre 등 미사용)');
    if (hasDet) {
      const cts = [...rd.matchAll(/content\s*:\s*"([^"]*)"/gi)].map(m => m[1]);
      const hexStripped = cts.length === 1 ? cts[0].replace(/\|[0-9a-f\s]+\|/gi,'').replace(/\s+/g,'') : '';
      if (hexStripped.length <= 6 && cts.length === 1 && !/pcre\s*:/i.test(rd))
        reasons.push('단일 탐지 content 너무 짧음 (오탐 위험)');
    }
    const sidM = rd.match(/\bsid\s*:\s*(\d+)/i);
    if (sidM && [0,999999,1234567,9999998,9999999].includes(+sidM[1]))
      reasons.push('테스트/임시 SID: ' + sidM[1]);
    const m = rule.msg || '';
    if (!m || ['','-','n/a','test','test rule','unknown'].includes(m.toLowerCase()))
      reasons.push('메시지 없음/임시값');
    return reasons;
  }

  function parseLocalV7Xlsx(headers, rows) {
    const col = {};
    headers.forEach((h, i) => { col[String(h).trim()] = i; });
    const get = (r, k) => String(r[col[k]] ?? '').trim();
    return rows
      .filter(r => get(r,'SID') && get(r,'SID') !== '0')
      .map(r => {
        const ruleData = get(r,'Rule Details');
        const opts = ruleData.includes('(') ? ruleData.slice(ruleData.lastIndexOf('(') + 1).replace(/\)\s*$/, '') : '';
        const protoM = ruleData.match(/^\s*\w+\s+(\w+)\s+/);
        const ctM    = opts.match(/\bclasstype\s*:\s*([^;,)]+)/);
        const dupCell = get(r,'중복 여부');
        const synCell = get(r,'문법 오류');
        const delCell = get(r,'삭제 권고');
        const rule = {
          type:'L', gid:parseInt(get(r,'GID'))||1, sid:parseInt(get(r,'SID'))||0,
          msg:get(r,'Message'), ruleData,
          action:get(r,'Rule Action').toUpperCase(), status:get(r,'Status'),
          groups:get(r,'Assigned Groups')||'—',
          protocol:protoM?protoM[1].toUpperCase():'(Unknown)',
          classtype:ctM?ctM[1].trim():'(none)',
          isDuplicate:dupCell.includes('중복'),
          dupBuiltinSid:get(r,'중복 Built-in SID'),
          syntaxErrors:synCell?synCell.split('\n').map(s=>s.trim()).filter(Boolean):[],
          deleteRecommended:delCell.includes('권고'),
          deleteReason:get(r,'삭제/검토 근거'),
        };
        const unR = detectUnnecessaryJS(rule);
        rule.unnecessaryReasons = unR;
        rule.isReviewNeeded = unR.length > 0 && !rule.deleteRecommended
          && !rule.isDuplicate && rule.syntaxErrors.length === 0;
        return rule;
      });
  }

  function extractV7ReviewCount(data) {
    for (const row of data) {
      const c0 = String(row[0] || '');
      if (c0.includes('검토 필요') && !isNaN(Number(row[1])) && Number(row[1]) > 0)
        return Number(row[1]);
    }
    return 0;
  }

  function parseSnortV7Excel(buffer) {
    const wb = XLSX.read(new Uint8Array(buffer), { type:'array' });
    const allData = XLSX.utils.sheet_to_json(wb.Sheets['All Rules'], { header:1, defval:'' });
    const allH   = allData[0].map(String);
    const allRows = allData.slice(1).filter(r=>r.some(v=>v!=='')).map(r=>r.map(String));
    const allRules = parseSnortXlsx(allH, allRows);

    const locData  = XLSX.utils.sheet_to_json(wb.Sheets['Local'], { header:1, defval:'' });
    const locH     = locData[0].map(String);
    const locRows  = locData.slice(1).filter(r=>r.some(v=>v!=='')).map(r=>r.map(String));
    const localRules = parseLocalV7Xlsx(locH, locRows);

    let reviewCount = localRules.filter(r=>r.isReviewNeeded).length;
    if (wb.SheetNames.includes('로컬 룰 분석')) {
      const aData = XLSX.utils.sheet_to_json(wb.Sheets['로컬 룰 분석'], { header:1, defval:'' });
      const ext = extractV7ReviewCount(aData);
      if (ext > 0) reviewCount = ext;
    }
    return { allRules, localRules, v7Stats:{ reviewCount } };
  }

  // ── v7 Local Rules tab ─────────────────────────────────────────────────

  function renderV7LocalPanel(localRules, filter, page) {
    filter = filter || state.v7Filter || 'all';
    page   = (page !== undefined) ? page : (state.v7Page || 0);
    state.v7Filter = filter; state.v7Page = page;

    const dupC = localRules.filter(r=>r.isDuplicate).length;
    const synC = localRules.filter(r=>r.syntaxErrors.length>0).length;
    const delC = localRules.filter(r=>r.deleteRecommended).length;
    const revC = localRules.filter(r=>r.isReviewNeeded).length;
    const okC  = localRules.filter(r=>!r.isDuplicate&&r.syntaxErrors.length===0&&!r.deleteRecommended&&!r.isReviewNeeded).length;
    const fMap = {
      all:r=>true, dup:r=>r.isDuplicate, syn:r=>r.syntaxErrors.length>0,
      del:r=>r.deleteRecommended, rev:r=>r.isReviewNeeded,
      ok: r=>!r.isDuplicate&&r.syntaxErrors.length===0&&!r.deleteRecommended&&!r.isReviewNeeded,
    };
    const filtered  = localRules.filter(fMap[filter]||fMap.all);
    const PER_PAGE  = 50;
    const maxPage   = Math.max(0, Math.ceil(filtered.length/PER_PAGE)-1);
    page = Math.min(page, maxPage);
    const pageRules = filtered.slice(page*PER_PAGE, (page+1)*PER_PAGE);

    const rowCls = r => r.deleteRecommended?'v7-row-del':r.syntaxErrors.length>0?'v7-row-syn':r.isDuplicate?'v7-row-dup':r.isReviewNeeded?'v7-row-rev':'';
    const badges  = r => {
      const b=[];
      if(r.isDuplicate)              b.push('<span class="v7-badge dup">중복</span>');
      if(r.syntaxErrors.length>0)    b.push('<span class="v7-badge syn">문법오류</span>');
      if(r.deleteRecommended)        b.push('<span class="v7-badge del">삭제권고</span>');
      if(r.isReviewNeeded)           b.push('<span class="v7-badge rev">검토필요</span>');
      if(!b.length)                  b.push('<span class="v7-badge ok">OK</span>');
      return b.join(' ');
    };
    const pgCount = Math.ceil(filtered.length/PER_PAGE);
    const pgNums  = pgCount<=1?'':(() => {
      const start = Math.max(0, Math.min(page-3, pgCount-7));
      const end   = Math.min(pgCount, start+7);
      return [...Array(end-start)].map((_,i)=>{
        const p=start+i;
        return `<button class="v7-pg-btn${p===page?' active':''}" onclick="window.__v7pg(${p})">${p+1}</button>`;
      }).join('');
    })();
    const pgHtml = pgCount<=1?'': `
      <div class="v7-pg-bar">
        <span>${filtered.length.toLocaleString()} 건 · ${page+1}/${pgCount} 페이지</span>
        ${page>0?`<button class="v7-pg-btn" onclick="window.__v7pg(${page-1})">‹ 이전</button>`:''}
        ${pgNums}
        ${page<pgCount-1?`<button class="v7-pg-btn" onclick="window.__v7pg(${page+1})">다음 ›</button>`:''}
      </div>`;

    document.getElementById('v7TabLocal').innerHTML = `
      <div class="v7-filter-bar">
        <button class="v7-filter-btn${filter==='all'?' active':''}" onclick="window.__v7flt('all')">전체 (${localRules.length})</button>
        <button class="v7-filter-btn f-dup${filter==='dup'?' active':''}" onclick="window.__v7flt('dup')">✔ 중복 (${dupC})</button>
        <button class="v7-filter-btn f-syn${filter==='syn'?' active':''}" onclick="window.__v7flt('syn')">⚠ 문법오류 (${synC})</button>
        <button class="v7-filter-btn f-del${filter==='del'?' active':''}" onclick="window.__v7flt('del')">🗑 삭제권고 (${delC})</button>
        <button class="v7-filter-btn f-rev${filter==='rev'?' active':''}" onclick="window.__v7flt('rev')">👁 검토필요 (${revC})</button>
        <button class="v7-filter-btn f-ok${filter==='ok'?' active':''}" onclick="window.__v7flt('ok')">✅ 이상없음 (${okC})</button>
      </div>
      <div class="table-scroll">
        <table class="v7-local-tbl">
          <thead><tr>
            <th>#</th><th>SID</th><th>Message</th><th>Action</th><th>Status</th>
            <th>분석</th><th>근거 / 오류</th><th>Rule Details</th>
          </tr></thead>
          <tbody>
            ${pageRules.map((r,i)=>`<tr class="${rowCls(r)}">
              <td style="text-align:center">${page*PER_PAGE+i+1}</td>
              <td style="font-family:Consolas;font-weight:700;color:#0369a1;white-space:nowrap">${r.sid}</td>
              <td style="max-width:200px;font-size:.78rem">${esc(r.msg)}</td>
              <td style="text-align:center;white-space:nowrap">${esc(r.action)}</td>
              <td style="text-align:center;font-size:.75rem;white-space:nowrap">${esc(r.status)}</td>
              <td style="white-space:nowrap">${badges(r)}</td>
              <td style="font-size:.74rem;color:#7c3aed;max-width:220px">
                ${r.syntaxErrors.length>0
                  ? r.syntaxErrors.slice(0,3).map(e=>esc(e.slice(0,80))).join('<br>')
                  : r.deleteReason
                    ? esc(r.deleteReason.slice(0,120))
                    : r.unnecessaryReasons.slice(0,2).map(x=>esc(x.slice(0,80))).join('<br>')}
              </td>
              <td class="rd-cell">${esc((r.ruleData||'').slice(0,200))}${(r.ruleData||'').length>200?'…':''}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      ${pgHtml}`;

    window.__v7pg  = p => renderV7LocalPanel(state.v7LocalRules, state.v7Filter, p);
    window.__v7flt = f => renderV7LocalPanel(state.v7LocalRules, f, 0);
  }

  // ── v7 Issues tab ──────────────────────────────────────────────────────

  function renderV7IssuesPanel(localRules) {
    const delRules = localRules.filter(r=>r.deleteRecommended);
    const dupRules = localRules.filter(r=>r.isDuplicate);
    const synRules = localRules.filter(r=>r.syntaxErrors.length>0);
    const revRules = localRules.filter(r=>r.isReviewNeeded);

    const issueItem = (r, bodyHtml) => `
      <div class="v7-issue-item">
        <div>
          <span class="v7-issue-sid">SID ${r.sid}</span>
          <span class="v7-issue-msg">${esc(r.msg.slice(0,100))}</span>
        </div>
        <div class="v7-issue-rd">${esc((r.ruleData||'').slice(0,320))}${(r.ruleData||'').length>320?'…':''}</div>
        <div class="v7-issue-reason">${bodyHtml}</div>
      </div>`;

    const section = (title, bgColor, textColor, items, bodyFn) => {
      if (!items.length) return '';
      return `
        <div class="v7-issue-group">
          <div class="v7-issue-hdr" style="background:${bgColor};color:${textColor}"
            onclick="const b=this.nextElementSibling;const open=b.style.display!=='none';b.style.display=open?'none':'';this.querySelector('.v7-chev').textContent=open?'▼':'▲'">
            <span>${title} &nbsp;<strong>(${items.length}건)</strong></span>
            <span class="v7-chev">▼</span>
          </div>
          <div class="v7-issue-body" style="display:none">
            ${items.map(r=>issueItem(r, bodyFn(r))).join('')}
          </div>
        </div>`;
    };

    document.getElementById('v7TabIssues').innerHTML = `
      <p style="font-size:.85rem;color:#64748b;margin:0 0 12px;">총 <strong>${delRules.length+revRules.length}</strong>건의 조치 필요 룰이 있습니다. 항목 클릭 시 상세 목록이 펼쳐집니다.</p>
      ${section('🗑 삭제 권고 룰','#fff5f5','#b91c1c', delRules,
        r=>`<span style="color:#b91c1c">${esc(r.deleteReason.slice(0,200))}</span>`)}
      ${section('✔ Built-in 중복 룰 (삭제 권고 포함)','#fefce8','#a16207', dupRules,
        r=>`중복 Built-in SID: <strong>${esc(r.dupBuiltinSid)}</strong>`)}
      ${section('⚠ 문법 오류 룰','#f5f3ff','#7e22ce', synRules,
        r=>r.syntaxErrors.map((e,i)=>`[${i+1}] ${esc(e)}`).join('<br>'))}
      ${section('👁 검토 필요 룰 (불필요 의심)','#eff6ff','#1d4ed8', revRules,
        r=>r.unnecessaryReasons.map((e,i)=>`[${i+1}] ${esc(e)}`).join('<br>'))}`;
  }

  // ── v7 Overview charts ─────────────────────────────────────────────────

  function renderSnortV7Overview(allRules, localRules, dupC, synC, delC, revC) {
    const total    = allRules.length;
    const locTotal = localRules.length;
    const actions  = tally(allRules, r=>r.action);
    const statuses = tally(allRules, r=>r.status);
    const typeDist = tally(allRules, r=>r.type==='B'?'Built-in':'Local');
    const cats     = tally(allRules, r=>snortCategory(r.msg)).slice(0,20);
    const protos   = tally(allRules, r=>r.protocol).slice(0,10);
    const sidBkts  = tally(allRules, r=>sidBucket(r.sid));
    const ctypes   = tally(allRules, r=>r.classtype).slice(0,15);
    const groups   = tally(allRules, r=>r.groups).filter(g=>g[0]!=='—').slice(0,15);
    const gids     = tally(allRules, r=>String(r.gid));
    const cleanC   = Math.max(0, locTotal - delC - revC);
    const localAna = [['이상 없음',cleanC],['삭제 권고',delC],['검토 필요',revC],['Built-in 중복',dupC],['문법 오류',synC]].filter(x=>x[1]>0);

    document.getElementById('dashChartsGrid').innerHTML = `
      <div class="dash-card"><div class="dash-card-title">Rule Action</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXA"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Status</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXS"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Built-in vs Local</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXT"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Protocol</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXP"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">🔬 로컬 룰 분석 현황</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXLA"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">GID Distribution</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXG"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 20 Categories</div>
        <div class="dash-ch-wrap" style="height:520px"><canvas id="dXCat"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 15 Classtypes</div>
        <div class="dash-ch-wrap" style="height:420px"><canvas id="dXCT"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">SID Range Distribution</div>
        <div class="dash-ch-wrap" style="height:300px"><canvas id="dXSid"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 15 Assigned Groups</div>
        <div class="dash-ch-wrap" style="height:420px"><canvas id="dXGrp"></canvas></div></div>`;

    const anaColors = ['#22c55e','#ef4444','#3b82f6','#f59e0b','#a855f7'];
    requestAnimationFrame(()=>{
      state.charts.xa  = makeDoughnut('dXA',  actions.map(a=>a[0]),   actions.map(a=>a[1]),  ['#3070E7','#00bceb','#9ca3af'].slice(0,actions.length));
      state.charts.xs  = makeDoughnut('dXS',  statuses.map(s=>s[0]),  statuses.map(s=>s[1]), ['#22c55e','#94a3b8','#ff7e3f'].slice(0,statuses.length));
      state.charts.xt  = makeDoughnut('dXT',  typeDist.map(t=>t[0]),  typeDist.map(t=>t[1]), ['#00bceb','#f59e0b']);
      state.charts.xp  = makeDoughnut('dXP',  protos.map(p=>p[0]),    protos.map(p=>p[1]),   PALETTE.slice(0,protos.length));
      state.charts.xla = makeDoughnut('dXLA', localAna.map(x=>x[0]),  localAna.map(x=>x[1]), anaColors.slice(0,localAna.length));
      state.charts.xg  = makeDoughnut('dXG',  gids.map(g=>'GID '+g[0]),gids.map(g=>g[1]),    PALETTE.slice(0,gids.length));
      state.charts.xc  = makeBar('dXCat', cats.map(c=>c[0]),    cats.map(c=>c[1]),   '#00bceb', true);
      state.charts.xct = makeBar('dXCT',  ctypes.map(c=>c[0]),  ctypes.map(c=>c[1]), '#ec4899', true);
      state.charts.xsi = makeBar('dXSid', sidBkts.map(s=>s[0]),sidBkts.map(s=>s[1]),'#3070E7', false);
      state.charts.xgr = makeBar('dXGrp', groups.map(g=>g[0]), groups.map(g=>g[1]),  '#a855f7', true);
    });

    const catList = tally(allRules, r=>snortCategory(r.msg));
    document.querySelector('#dashDataTable thead').innerHTML =
      `<tr><th>#</th><th>Category</th><th>Total</th><th>%</th><th>BLOCK</th><th>ALERT</th><th>Built-in</th><th>Local</th></tr>`;
    document.querySelector('#dashDataTable tbody').innerHTML = catList.slice(0,50).map((c,i)=>{
      const sub=allRules.filter(r=>snortCategory(r.msg)===c[0]);
      const bl=sub.filter(r=>r.action==='BLOCK').length;
      const al=sub.filter(r=>r.action==='ALERT').length;
      const bi=sub.filter(r=>r.type==='B').length;
      const lo=sub.filter(r=>r.type==='L').length;
      return `<tr><td>${i+1}</td>
        <td style="font-weight:600;color:var(--primary)">${esc(c[0])}</td>
        <td>${c[1].toLocaleString()}</td><td>${((c[1]/total)*100).toFixed(1)}%</td>
        <td>${bl.toLocaleString()}</td><td>${al.toLocaleString()}</td>
        <td>${bi.toLocaleString()}</td><td>${lo.toLocaleString()}</td></tr>`;
    }).join('');
    document.getElementById('dashTableTitle').textContent = 'Category Details — Top 50';
    const tblPnl = document.querySelector('#dashContent > .panel');
    if (tblPnl) tblPnl.style.display = '';
  }

  // ── v7 Main Dashboard ─────────────────────────────────────────────────

  function renderSnortV7Dashboard(allRules, localRules, v7Stats) {
    const total    = allRules.length;
    const builtins = allRules.filter(r=>r.type==='B').length;
    const locTotal = localRules.length;
    const active   = allRules.filter(r=>r.status==='Active').length;
    const disabled = allRules.filter(r=>r.status==='Disabled').length;
    const dupC     = localRules.filter(r=>r.isDuplicate).length;
    const synC     = localRules.filter(r=>r.syntaxErrors.length>0).length;
    const delC     = localRules.filter(r=>r.deleteRecommended).length;
    const revC     = v7Stats.reviewCount || localRules.filter(r=>r.isReviewNeeded).length;
    const cleanC   = Math.max(0, locTotal - delC - revC);

    renderKpis([
      {v:total.toLocaleString(),    l:'Total Rules', cls:'cyan'},
      {v:builtins.toLocaleString(), l:'Built-in',    cls:'blue'},
      {v:locTotal.toLocaleString(), l:'Local',       cls:'green'},
      {v:active.toLocaleString(),   l:'Active',      cls:'orange'},
      {v:disabled.toLocaleString(), l:'Disabled',    cls:'gray'},
    ]);

    const pDel = locTotal?(delC/locTotal*100).toFixed(1):'0';
    const pRev = locTotal?(revC/locTotal*100).toFixed(1):'0';
    const pDup = locTotal?Math.max(0,(dupC-delC)/locTotal*100).toFixed(1):'0';
    const pSyn = locTotal?Math.max(0,(synC-delC)/locTotal*100).toFixed(1):'0';
    const pOk  = Math.max(0, 100 - +pDel - +pRev - +pDup - +pSyn).toFixed(1);

    const kpiBar = document.getElementById('dashKpiBar');
    const banner = document.createElement('div');
    banner.id = 'v7AnalysisBanner';
    banner.className = 'v7-analysis-banner';
    banner.innerHTML = `
      <div class="v7-analysis-title">🔬 로컬 룰 분석 (v7) — ${locTotal.toLocaleString()}개 로컬 룰</div>
      <div class="mig-kpi-bar" style="margin-bottom:12px;">
        <div class="mig-kpi-card" style="border-top:4px solid #f59e0b;flex:1;min-width:100px;background:#fffbeb">
          <div class="kpi-val" style="color:#f59e0b">${dupC}</div><div class="kpi-lbl">✔ Built-in 중복</div>
        </div>
        <div class="mig-kpi-card purple" style="flex:1;min-width:100px">
          <div class="kpi-val">${synC}</div><div class="kpi-lbl">⚠ 문법 오류</div>
        </div>
        <div class="mig-kpi-card red" style="flex:1;min-width:100px">
          <div class="kpi-val">${delC}</div><div class="kpi-lbl">🗑 삭제 권고</div>
        </div>
        <div class="mig-kpi-card blue" style="flex:1;min-width:100px">
          <div class="kpi-val">${revC}</div><div class="kpi-lbl">👁 검토 필요</div>
        </div>
        <div class="mig-kpi-card teal" style="flex:1;min-width:100px">
          <div class="kpi-val">${cleanC}</div><div class="kpi-lbl">✅ 이상 없음</div>
        </div>
      </div>
      <div class="v7-bar-wrap">
        ${+pDel>0?`<div class="v7-seg del" style="flex:${pDel}">${pDel}%</div>`:''}
        ${+pRev>0?`<div class="v7-seg rev" style="flex:${pRev}">${pRev}%</div>`:''}
        ${+pDup>0?`<div class="v7-seg dup" style="flex:${pDup}">${pDup}%</div>`:''}
        ${+pSyn>0?`<div class="v7-seg syn" style="flex:${pSyn}">${pSyn}%</div>`:''}
        <div class="v7-seg clean" style="flex:${pOk}">${pOk}%</div>
      </div>
      <div class="v7-legend">
        <div class="v7-leg-item"><div class="v7-leg-dot" style="background:#ef4444"></div>삭제 권고</div>
        <div class="v7-leg-item"><div class="v7-leg-dot" style="background:#3b82f6"></div>검토 필요</div>
        <div class="v7-leg-item"><div class="v7-leg-dot" style="background:#f59e0b"></div>Built-in 중복</div>
        <div class="v7-leg-item"><div class="v7-leg-dot" style="background:#a855f7"></div>문법 오류</div>
        <div class="v7-leg-item"><div class="v7-leg-dot" style="background:#22c55e"></div>이상 없음</div>
      </div>`;
    kpiBar.parentNode.insertBefore(banner, kpiBar.nextSibling);

    const grid = document.getElementById('dashChartsGrid');
    const tabBarDiv = document.createElement('div');
    tabBarDiv.className = 'v7-tab-bar'; tabBarDiv.id = 'v7TabBar';
    tabBarDiv.innerHTML = `
      <button class="v7-tab-btn active" data-tab="overview">📊 Overview</button>
      <button class="v7-tab-btn" data-tab="local">🔍 Local Analysis <span style="background:#e2e8f0;border-radius:10px;padding:1px 7px;font-size:.7rem;margin-left:4px">${locTotal}</span></button>
      <button class="v7-tab-btn" data-tab="issues">⚠ Issues <span style="background:#fee2e2;color:#b91c1c;border-radius:10px;padding:1px 7px;font-size:.7rem;margin-left:4px">${delC+revC}</span></button>`;
    grid.parentNode.insertBefore(tabBarDiv, grid);

    grid.className = 'v7-tab-panel dash-grid'; grid.dataset.tab = 'overview';
    grid.insertAdjacentHTML('afterend',
      '<div id="v7TabLocal" class="v7-tab-panel" data-tab="local" style="display:none;"></div>' +
      '<div id="v7TabIssues" class="v7-tab-panel" data-tab="issues" style="display:none;"></div>');

    tabBarDiv.addEventListener('click', e => {
      const btn = e.target.closest('.v7-tab-btn');
      if (!btn) return;
      const tab = btn.dataset.tab;
      tabBarDiv.querySelectorAll('.v7-tab-btn').forEach(b=>b.classList.toggle('active',b===btn));
      document.querySelectorAll('.v7-tab-panel').forEach(p=>p.style.display=p.dataset.tab===tab?'':'none');
      const tblPnl = document.querySelector('#dashContent > .panel');
      if (tblPnl) tblPnl.style.display = tab==='overview'?'':'none';
      state.v7ActiveTab = tab;
      if (tab==='local'  && !document.querySelector('#v7TabLocal .v7-filter-bar'))
        renderV7LocalPanel(state.v7LocalRules);
      if (tab==='issues' && !document.querySelector('#v7TabIssues .v7-issue-group'))
        renderV7IssuesPanel(state.v7LocalRules);
    });

    state.v7LocalRules = localRules;
    const tblPnl = document.querySelector('#dashContent > .panel');
    if (tblPnl) tblPnl.style.display = '';
    renderSnortV7Overview(allRules, localRules, dupC, synC, delC, revC);
  }

  // ── Snort Excel Export dashboard ───────────────────────────────────────

  function renderSnortXlsxDashboard(rules) {
    const total    = rules.length;
    const builtins = rules.filter(r => r.type === 'B').length;
    const locals   = rules.filter(r => r.type === 'L').length;
    const active   = rules.filter(r => r.status === 'Active').length;
    const disabled = rules.filter(r => r.status === 'Disabled').length;

    renderKpis([
      { v: total.toLocaleString(),    l: 'Total Rules'  },
      { v: builtins.toLocaleString(), l: 'Built-in'     },
      { v: locals.toLocaleString(),   l: 'Local'        },
      { v: active.toLocaleString(),   l: 'Active'       },
      { v: disabled.toLocaleString(), l: 'Disabled'     },
    ]);

    const actions   = tally(rules, r => r.action);
    const statuses  = tally(rules, r => r.status);
    const typeDist  = tally(rules, r => r.type === 'B' ? 'Built-in' : 'Local');
    const cats      = tally(rules, r => snortCategory(r.msg)).slice(0, 20);
    const protos    = tally(rules, r => r.protocol).slice(0, 10);
    const sidBkts   = tally(rules, r => sidBucket(r.sid));
    const ctypes    = tally(rules, r => r.classtype).slice(0, 15);
    const groups    = tally(rules, r => r.groups).filter(g => g[0] !== '—').slice(0, 15);

    document.getElementById('dashChartsGrid').innerHTML = `
      <div class="dash-card"><div class="dash-card-title">Rule Action</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXA"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Status</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXS"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Built-in vs Local</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXT"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Protocol Distribution</div>
        <div class="dash-ch-wrap" style="height:180px"><canvas id="dXP"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 20 Categories (from Message)</div>
        <div class="dash-ch-wrap" style="height:520px"><canvas id="dXCat"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 15 Classtypes (from Rule Details)</div>
        <div class="dash-ch-wrap" style="height:420px"><canvas id="dXCT"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">SID Range Distribution</div>
        <div class="dash-ch-wrap" style="height:300px"><canvas id="dXSid"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">GID Distribution</div>
        <div class="dash-ch-wrap" style="height:300px"><canvas id="dXG"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 15 Assigned Groups</div>
        <div class="dash-ch-wrap" style="height:420px"><canvas id="dXGrp"></canvas></div></div>`;

    const gids = tally(rules, r => String(r.gid));

    requestAnimationFrame(() => {
      state.charts.xa  = makeDoughnut('dXA',  actions.map(a=>a[0]),    actions.map(a=>a[1]),   ['#3070E7','#00bceb','#9ca3af'].slice(0,actions.length));
      state.charts.xs  = makeDoughnut('dXS',  statuses.map(s=>s[0]),   statuses.map(s=>s[1]),  ['#22c55e','#94a3b8','#ff7e3f'].slice(0,statuses.length));
      state.charts.xt  = makeDoughnut('dXT',  typeDist.map(t=>t[0]),   typeDist.map(t=>t[1]),  ['#00bceb','#f59e0b'].slice(0,typeDist.length));
      state.charts.xp  = makeDoughnut('dXP',  protos.map(p=>p[0]),     protos.map(p=>p[1]),    PALETTE.slice(0,protos.length));
      state.charts.xc  = makeBar('dXCat', cats.map(c=>c[0]),    cats.map(c=>c[1]),    '#00bceb', true);
      state.charts.xct = makeBar('dXCT',  ctypes.map(c=>c[0]),  ctypes.map(c=>c[1]),  '#ec4899', true);
      state.charts.xsi = makeBar('dXSid', sidBkts.map(s=>s[0]), sidBkts.map(s=>s[1]),'#3070E7', false);
      state.charts.xg  = makeDoughnut('dXG', gids.map(g=>'GID '+g[0]), gids.map(g=>g[1]), PALETTE.slice(0,gids.length));
      state.charts.xgr = makeBar('dXGrp', groups.map(g=>g[0]), groups.map(g=>g[1]), '#a855f7', true);
    });

    const catList = tally(rules, r => snortCategory(r.msg));
    document.querySelector('#dashDataTable thead').innerHTML =
      `<tr><th>#</th><th>Category</th><th>Count</th><th>%</th><th>BLOCK</th><th>ALERT</th><th>DISABLE</th><th>Active</th><th>Disabled</th></tr>`;
    document.querySelector('#dashDataTable tbody').innerHTML = catList.slice(0, 50).map((c, i) => {
      const sub   = rules.filter(r => snortCategory(r.msg) === c[0]);
      const block = sub.filter(r => r.action === 'BLOCK').length;
      const alert = sub.filter(r => r.action === 'ALERT').length;
      const dis   = sub.filter(r => r.action === 'DISABLE').length;
      const act   = sub.filter(r => r.status === 'Active').length;
      const dstat = sub.filter(r => r.status === 'Disabled').length;
      return `<tr><td>${i+1}</td>
        <td style="font-weight:600;color:var(--primary)">${esc(c[0])}</td>
        <td>${c[1].toLocaleString()}</td>
        <td>${((c[1]/total)*100).toFixed(1)}%</td>
        <td>${block.toLocaleString()}</td><td>${alert.toLocaleString()}</td><td>${dis.toLocaleString()}</td>
        <td>${act.toLocaleString()}</td><td>${dstat.toLocaleString()}</td></tr>`;
    }).join('');
  }

  function analyzeColumns(headers, rows) {
    return headers.map((name, ci) => {
      const vals     = rows.map(r => (r[ci]??'').toString().trim());
      const nonEmpty = vals.filter(v => v!==''&&v!=='null'&&v!=='N/A'&&v!=='-');
      const nullCount = vals.length - nonEmpty.length;
      const numParsed = nonEmpty.map(v=>parseFloat(v)).filter(n=>!isNaN(n));
      const isNumeric = nonEmpty.length>0 && numParsed.length/nonEmpty.length>0.8;
      const uniqueSet = new Set(nonEmpty);
      const base = {
        name, type: isNumeric?'numeric':'categorical',
        total:vals.length, nullCount,
        nullPct: vals.length?(nullCount/vals.length*100).toFixed(1):'0',
        unique:uniqueSet.size, sample:[...uniqueSet].slice(0,5),
      };
      if (isNumeric) {
        const min=Math.min(...numParsed), max=Math.max(...numParsed);
        const avg=numParsed.reduce((a,b)=>a+b,0)/numParsed.length;
        return {...base, min, max, avg, histogram:buildHistogram(numParsed,15)};
      }
      return {...base, distribution: tally(nonEmpty,v=>v).slice(0,25)};
    });
  }

  function buildHistogram(nums, buckets) {
    if (!nums.length) return [];
    const min=Math.min(...nums), max=Math.max(...nums);
    if (min===max) return [{label:String(min),count:nums.length}];
    const size=(max-min)/buckets;
    const bins=Array.from({length:buckets},(_,i)=>({label:(min+i*size).toFixed(1),count:0}));
    for (const n of nums) { const idx=Math.min(Math.floor((n-min)/size),buckets-1); bins[idx].count++; }
    return bins.filter(b=>b.count>0);
  }

  const GRID='#d1d5db', TICK='#374151', LABEL='#1e293b';

  function makeBar(id, labels, data, color, horiz=false) {
    const el=document.getElementById(id);
    if (!el||typeof Chart==='undefined') return null;
    return new Chart(el,{type:'bar',
      data:{labels,datasets:[{data,backgroundColor:color+'bb',borderColor:color,borderWidth:1,borderRadius:4}]},
      options:{responsive:true,maintainAspectRatio:false,indexAxis:horiz?'y':'x',
        plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${(+c.raw).toLocaleString()}`}}},
        scales:{
          x:{ticks:{color:horiz?TICK:LABEL,font:{size:10}},grid:{color:GRID}},
          y:{ticks:{color:horiz?LABEL:TICK,font:{size:10}},grid:{color:GRID}},
        },
      },
    });
  }

  function makeDoughnut(id, labels, data, colors) {
    const el=document.getElementById(id);
    if (!el||typeof Chart==='undefined') return null;
    return new Chart(el,{type:'doughnut',
      data:{labels,datasets:[{data,backgroundColor:colors.map(c=>c+'bb'),borderColor:colors,borderWidth:1}]},
      options:{responsive:true,maintainAspectRatio:false,
        plugins:{legend:{position:'right',labels:{color:LABEL,font:{size:11},boxWidth:14,padding:8}},
          tooltip:{callbacks:{label:c=>` ${c.label}: ${(+c.raw).toLocaleString()}`}}},
      },
    });
  }

  function renderKpis(kpis) {
    const el=document.getElementById('dashKpiBar');
    if (!el) return;
    const cls=['cyan','blue','green','orange','gray'];
    el.innerHTML=kpis.map((k,i)=>`
      <div class="mig-kpi-card ${k.cls||cls[i%cls.length]}">
        <div class="kpi-val">${k.v}</div><div class="kpi-lbl">${k.l}</div>
      </div>`).join('');
  }

  function renderSnortDashboard(rules) {
    const total=rules.length;
    renderKpis([
      {v:total.toLocaleString(),l:'Total Rules'},
      {v:new Set(rules.map(r=>r.sid)).size.toLocaleString(),l:'Unique SIDs'},
      {v:new Set(rules.map(r=>snortCategory(r.msg))).size,l:'Categories'},
      {v:new Set(rules.map(r=>r.protocol)).size,l:'Protocols'},
      {v:new Set(rules.map(r=>r.action)).size,l:'Actions'},
    ]);
    document.getElementById('dashChartsGrid').innerHTML=`
      <div class="dash-card"><div class="dash-card-title">Action Distribution</div>
        <div class="dash-ch-wrap" style="height:220px"><canvas id="dCA"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">Protocol Distribution</div>
        <div class="dash-ch-wrap" style="height:220px"><canvas id="dCP"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 20 Categories</div>
        <div class="dash-ch-wrap" style="height:520px"><canvas id="dCCat"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">SID Range Distribution</div>
        <div class="dash-ch-wrap" style="height:260px"><canvas id="dCS"></canvas></div></div>
      <div class="dash-card"><div class="dash-card-title">GID Distribution</div>
        <div class="dash-ch-wrap" style="height:260px"><canvas id="dCG"></canvas></div></div>
      <div class="dash-card dash-card-wide"><div class="dash-card-title">Top 15 Classtypes</div>
        <div class="dash-ch-wrap" style="height:420px"><canvas id="dCCT"></canvas></div></div>`;

    const actions=tally(rules,r=>r.action);
    const protos=tally(rules,r=>r.protocol).slice(0,10);
    const cats=tally(rules,r=>snortCategory(r.msg)).slice(0,20);
    const sidBkts=tally(rules,r=>sidBucket(r.sid));
    const ctypes=tally(rules,r=>r.classtype).slice(0,15);
    const gids=tally(rules,r=>String(r.gid));
    requestAnimationFrame(()=>{
      state.charts.a =makeBar('dCA',actions.map(a=>a[0].toUpperCase()),actions.map(a=>a[1]),'#00bceb',true);
      state.charts.p =makeDoughnut('dCP',protos.map(p=>p[0].toUpperCase()),protos.map(p=>p[1]),PALETTE.slice(0,protos.length));
      state.charts.c =makeBar('dCCat',cats.map(c=>c[0]),cats.map(c=>c[1]),'#00bceb',true);
      state.charts.s =makeBar('dCS',sidBkts.map(s=>s[0]),sidBkts.map(s=>s[1]),'#3070E7',false);
      state.charts.g =makeDoughnut('dCG',gids.map(g=>'GID '+g[0]),gids.map(g=>g[1]),['#00bceb','#ff7e3f','#a855f7'].slice(0,gids.length));
      state.charts.ct=makeBar('dCCT',ctypes.map(c=>c[0]),ctypes.map(c=>c[1]),'#ec4899',true);
    });

    const catList=tally(rules,r=>snortCategory(r.msg));
    document.querySelector('#dashDataTable thead').innerHTML=
      `<tr><th>#</th><th>Category</th><th>Count</th><th>%</th><th>Top Action</th><th>Top Protocol</th></tr>`;
    document.querySelector('#dashDataTable tbody').innerHTML=catList.slice(0,50).map((c,i)=>{
      const sub=rules.filter(r=>snortCategory(r.msg)===c[0]);
      const tA=tally(sub,r=>r.action)[0]?.[0]?.toUpperCase()||'—';
      const tP=tally(sub,r=>r.protocol)[0]?.[0]?.toUpperCase()||'—';
      return `<tr><td>${i+1}</td><td style="font-weight:600;color:var(--primary)">${esc(c[0])}</td>
        <td>${c[1].toLocaleString()}</td><td>${((c[1]/total)*100).toFixed(1)}%</td>
        <td>${esc(tA)}</td><td>${esc(tP)}</td></tr>`;
    }).join('');
  }

  function selectInterestingCols(colMeta) {
    return colMeta
      .map((c,i)=>({...c,_i:i}))
      .filter(c=>c.type==='categorical'?c.unique>=2&&c.unique<=50:c.histogram?.length>1)
      .sort((a,b)=>{
        if (a.type==='categorical'&&b.type!=='categorical') return -1;
        if (b.type==='categorical'&&a.type!=='categorical') return  1;
        return 0;
      }).slice(0,6);
  }

  function renderTableDashboard(colMeta, rows) {
    const total=rows.length;
    const numCols=colMeta.filter(c=>c.type==='numeric').length;
    const catCols=colMeta.filter(c=>c.type==='categorical').length;
    const emptyCells=colMeta.reduce((s,c)=>s+c.nullCount,0);
    const totalCells=colMeta.length*total;
    renderKpis([
      {v:total.toLocaleString(),l:'Rows'},
      {v:colMeta.length,l:'Columns'},
      {v:numCols,l:'Numeric Cols'},
      {v:catCols,l:'Categorical Cols'},
      {v:totalCells?(emptyCells/totalCells*100).toFixed(1)+'%':'0%',l:'Empty Cells'},
    ]);

    const selected=selectInterestingCols(colMeta);
    state.table.selectedCols=selected;

    document.getElementById('dashChartsGrid').innerHTML=selected.map((col,i)=>{
      const wide=i===2||i===5;
      const h=col.type==='numeric'?'220px':`${Math.max(180,Math.min(col.unique,25)*28)}px`;
      return `
        <div class="dash-card${wide?' dash-card-wide':''}">
          <div class="dash-card-title">${esc(col.name)}</div>
          <div style="font-size:.74rem;color:var(--muted);margin-bottom:8px;">${col.type} · ${col.unique.toLocaleString()} unique · ${col.nullPct}% empty</div>
          <div class="dash-ch-wrap" style="height:${h}"><canvas id="dTC${i}"></canvas></div>
        </div>`;
    }).join('');

    requestAnimationFrame(()=>{
      selected.forEach((col,i)=>{
        const color=PALETTE[i%PALETTE.length];
        if (col.type==='categorical') {
          const dist=col.distribution||[];
          state.charts['tc'+i]=makeBar('dTC'+i,dist.map(d=>String(d[0])),dist.map(d=>d[1]),color,true);
        } else {
          const hist=col.histogram||[];
          state.charts['tc'+i]=makeBar('dTC'+i,hist.map(h=>h.label),hist.map(h=>h.count),color,false);
        }
      });
    });

    document.querySelector('#dashDataTable thead').innerHTML=
      `<tr><th>#</th><th>Column</th><th>Type</th><th>Unique</th><th>Empty %</th><th>Min / Max / Avg</th><th>Samples</th></tr>`;
    document.querySelector('#dashDataTable tbody').innerHTML=colMeta.map((c,i)=>`
      <tr><td>${i+1}</td><td style="font-weight:600;color:var(--primary)">${esc(c.name)}</td>
      <td>${c.type}</td><td>${c.unique.toLocaleString()}</td><td>${c.nullPct}%</td>
      <td style="font-size:.8rem;color:var(--muted)">${c.type==='numeric'?`${c.min?.toLocaleString()} / ${c.max?.toLocaleString()} / ${c.avg?.toFixed(2)}`:'—'}</td>
      <td style="font-size:.78rem;color:var(--muted)">${c.sample.map(v=>esc(String(v))).join(', ')}</td></tr>`).join('');
  }

  function activateDashboard(fileName, description) {
    state.fileName=fileName;
    ['dashDropZone'].forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='none';});
    ['dashContent'].forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='block';});
    ['dashDownloadBtn','dashResetBtn'].forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='inline-flex';});
    const fi=document.getElementById('dashFileInfo');
    if (fi){fi.textContent=description;fi.style.display='block';}
  }

  function showError(msg) {
    const dz=document.getElementById('dashDropZone');
    if (!dz) return;
    dz.style.display='';
    dz.querySelector('.dash-drop-title').textContent='⚠ '+msg;
    dz.querySelector('.dash-drop-sub').textContent='Try a different file';
  }

  function processText(text, name) {
    const ext=fileExt(name);
    if (['rules','conf'].includes(ext)) {
      const rules=parseSnortRules(text);
      if (rules.length) { state.mode='rules'; state.rules=rules; destroyCharts(); activateDashboard(name,name+' — '+rules.length.toLocaleString()+' rules'); renderSnortDashboard(rules); return; }
    }
    const {headers,rows}=parseCsv(text);
    if (headers.length>=2&&rows.length>=1) {
      const colMeta=analyzeColumns(headers,rows);
      state.mode='table'; state.table={headers,rows,colMeta,selectedCols:[]}; destroyCharts();
      activateDashboard(name,name+' — '+rows.length.toLocaleString()+' rows × '+headers.length+' columns'); renderTableDashboard(colMeta,rows); return;
    }
    const rules=parseSnortRules(text);
    if (rules.length) { state.mode='rules'; state.rules=rules; destroyCharts(); activateDashboard(name,name+' — '+rules.length.toLocaleString()+' rules'); renderSnortDashboard(rules); return; }
    showError('No recognizable data found in this file');
  }

  function processBuffer(buffer, name) {
    try {
      if (typeof XLSX === 'undefined') throw new Error('SheetJS not loaded');
      const wb = XLSX.read(new Uint8Array(buffer), { type:'array' });

      if (isSnortV7Format(wb)) {
        const { allRules, localRules, v7Stats } = parseSnortV7Excel(buffer);
        if (!allRules.length) { showError('No rules found in v7 Excel'); return; }
        state.mode='snort-v7'; state.rules=allRules; state.localRules=localRules; state.v7Stats=v7Stats;
        destroyCharts();
        activateDashboard(name, name+' — v7 · '+allRules.length.toLocaleString()+' rules · Local '+localRules.length.toLocaleString());
        renderSnortV7Dashboard(allRules, localRules, v7Stats);
        return;
      }

      const {headers,rows,sheetName}=parseExcel(buffer);
      if (!headers.length){showError('Excel file appears empty');return;}

      if (isSnortXlsxExport(headers)) {
        const rules = parseSnortXlsx(headers, rows);
        if (!rules.length){showError('No rule rows found in this Excel file');return;}
        state.mode='snort-xlsx'; state.rules=rules; destroyCharts();
        activateDashboard(name, name+' — '+rules.length.toLocaleString()+' rules (sheet: '+sheetName+')');
        renderSnortXlsxDashboard(rules);
        return;
      }

      const colMeta=analyzeColumns(headers,rows);
      state.mode='table'; state.table={headers,rows,colMeta,selectedCols:[]}; destroyCharts();
      activateDashboard(name,name+' — '+rows.length.toLocaleString()+' rows × '+headers.length+' columns (sheet: '+sheetName+')');
      renderTableDashboard(colMeta,rows);
    } catch(e){showError('Excel parse error: '+e.message);}
  }

  function handleFile(file) {
    if (!file) return;
    const reader=new FileReader();
    if (isExcelExt(fileExt(file.name))) {
      reader.onload=e=>processBuffer(e.target.result,file.name);
      reader.readAsArrayBuffer(file);
    } else {
      reader.onload=e=>processText(String(e.target.result||''),file.name);
      reader.readAsText(file);
    }
  }

  function htmlShell(title, body, script) {
    const P=JSON.stringify(PALETTE);
    return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"><\/script>
<style>
*{box-sizing:border-box}:root{--bg:#061128;--panel:#0a1838;--border:#1a2d55;--primary:#00bceb;--text:#fff;--muted:#8fa4c8}
body{margin:0;padding:24px 28px;background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
h1{color:var(--primary);font-size:1.5rem;margin:0 0 4px;font-weight:800}.sub{color:var(--muted);font-size:.82rem;margin-bottom:22px}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.kpi-card{flex:1;min-width:120px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:13px 18px}
.kpi-val{font-size:1.8rem;font-weight:800;line-height:1}.kpi-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.kpi-card.c1{border-top:4px solid #00bceb}.kpi-card.c1 .kpi-val{color:#00bceb}
.kpi-card.c2{border-top:4px solid #3070E7}.kpi-card.c2 .kpi-val{color:#60a5fa}
.kpi-card.c3{border-top:4px solid #22C55E}.kpi-card.c3 .kpi-val{color:#4ade80}
.kpi-card.c4{border-top:4px solid #FF9000}.kpi-card.c4 .kpi-val{color:#fb923c}
.kpi-card.c5{border-top:4px solid #64748B}.kpi-card.c5 .kpi-val{color:#94a3b8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}.card.wide{grid-column:1/-1}
.ct{font-size:.78rem;font-weight:700;color:var(--primary);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.cs{font-size:.74rem;color:var(--muted);margin-bottom:8px}.ch{position:relative}
table{width:100%;border-collapse:collapse;font-size:.84rem}th,td{border:1px solid var(--border);padding:7px 10px;text-align:left;vertical-align:top}
th{background:rgba(0,102,204,.2);color:#9bd7ff;position:sticky;top:0}tr:nth-child(even){background:rgba(255,255,255,.02)}
.tbl{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:20px}
.footer{margin-top:20px;color:var(--muted);font-size:.76rem;text-align:center;padding-top:14px;border-top:1px solid var(--border)}
@media(max-width:700px){.grid{grid-template-columns:1fr}.card.wide{grid-column:1}}
</style></head><body>${body}
<div class="footer">Generated by Snort Rule Converter · Dashboard</div>
<script>(function(){
const P=${P},G='#1a2d55',TC='#8fa4c8',LC='#ffffff';
function bar(id,lbl,dat,col,h){const c=document.getElementById(id);if(!c)return;new Chart(c,{type:'bar',data:{labels:lbl,datasets:[{data:dat,backgroundColor:col+'bb',borderColor:col,borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,indexAxis:h?'y':'x',plugins:{legend:{display:false}},scales:{x:{ticks:{color:h?TC:LC,font:{size:10}},grid:{color:G}},y:{ticks:{color:h?LC:TC,font:{size:10}},grid:{color:G}}}}});}
function donut(id,lbl,dat,cols){const c=document.getElementById(id);if(!c)return;new Chart(c,{type:'doughnut',data:{labels:lbl,datasets:[{data:dat,backgroundColor:cols.map(x=>x+'bb'),borderColor:cols,borderWidth:1}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:LC,font:{size:11},boxWidth:14,padding:8}}}}});}
${script}
})();<\/script></body></html>`;
  }

  function buildSnortHtml() {
    const rules=state.rules, total=rules.length, fname=state.fileName;
    const actions=tally(rules,r=>r.action);
    const protos=tally(rules,r=>r.protocol).slice(0,10);
    const cats=tally(rules,r=>snortCategory(r.msg));
    const cat20=cats.slice(0,20);
    const sids=tally(rules,r=>sidBucket(r.sid));
    const ctypes=tally(rules,r=>r.classtype).slice(0,15);
    const gids=tally(rules,r=>String(r.gid));
    const J=JSON.stringify;
    const tableRows=cats.slice(0,50).map((c,i)=>{
      const sub=rules.filter(r=>snortCategory(r.msg)===c[0]);
      const tA=tally(sub,r=>r.action)[0]?.[0]?.toUpperCase()||'—';
      const tP=tally(sub,r=>r.protocol)[0]?.[0]?.toUpperCase()||'—';
      return `<tr><td>${i+1}</td><td>${esc(c[0])}</td><td>${c[1].toLocaleString()}</td><td>${((c[1]/total)*100).toFixed(1)}%</td><td>${esc(tA)}</td><td>${esc(tP)}</td></tr>`;
    }).join('');
    const kpis=[
      {v:total.toLocaleString(),l:'Total Rules',cls:'c1'},
      {v:new Set(rules.map(r=>r.sid)).size.toLocaleString(),l:'Unique SIDs',cls:'c2'},
      {v:new Set(rules.map(r=>snortCategory(r.msg))).size,l:'Categories',cls:'c3'},
      {v:new Set(rules.map(r=>r.protocol)).size,l:'Protocols',cls:'c4'},
      {v:new Set(rules.map(r=>r.action)).size,l:'Actions',cls:'c5'},
    ];
    const body=`<h1>📊 Rules Dashboard</h1>
<div class="sub">File: <strong>${esc(fname)}</strong> · Generated: ${new Date().toLocaleString()}</div>
<div class="kpi-row">${kpis.map(k=>`<div class="kpi-card ${k.cls}"><div class="kpi-val">${k.v}</div><div class="kpi-lbl">${k.l}</div></div>`).join('')}</div>
<div class="grid">
  <div class="card"><div class="ct">Action</div><div class="ch" style="height:${Math.max(160,actions.length*38)}px"><canvas id="cA"></canvas></div></div>
  <div class="card"><div class="ct">Protocol</div><div class="ch" style="height:${Math.max(160,protos.length*22+60)}px"><canvas id="cP"></canvas></div></div>
  <div class="card wide"><div class="ct">Top 20 Categories</div><div class="ch" style="height:${Math.max(280,cat20.length*32)}px"><canvas id="cC"></canvas></div></div>
  <div class="card"><div class="ct">SID Range</div><div class="ch" style="height:${Math.max(200,sids.length*28)}px"><canvas id="cS"></canvas></div></div>
  <div class="card"><div class="ct">GID</div><div class="ch" style="height:${Math.max(160,gids.length*22+60)}px"><canvas id="cG"></canvas></div></div>
  <div class="card wide"><div class="ct">Top 15 Classtypes</div><div class="ch" style="height:${Math.max(200,ctypes.length*32)}px"><canvas id="cCT"></canvas></div></div>
</div>
<div class="tbl"><div class="ct" style="margin-bottom:10px">Category Details — Top 50</div><div style="overflow:auto"><table>
  <thead><tr><th>#</th><th>Category</th><th>Count</th><th>%</th><th>Top Action</th><th>Top Protocol</th></tr></thead>
  <tbody>${tableRows}</tbody></table></div></div>`;
    const script=`
bar('cA',${J(actions.map(a=>a[0].toUpperCase()))},${J(actions.map(a=>a[1]))},'#00bceb',true);
donut('cP',${J(protos.map(p=>p[0].toUpperCase()))},${J(protos.map(p=>p[1]))},P.slice(0,${protos.length}));
bar('cC',${J(cat20.map(c=>c[0]))},${J(cat20.map(c=>c[1]))},'#00bceb',true);
bar('cS',${J(sids.map(s=>s[0]))},${J(sids.map(s=>s[1]))},'#3070E7',false);
donut('cG',${J(gids.map(g=>'GID '+g[0]))},${J(gids.map(g=>g[1]))},${ JSON.stringify(['#00bceb','#ff7e3f','#a855f7'].slice(0,gids.length)) });
bar('cCT',${J(ctypes.map(c=>c[0]))},${J(ctypes.map(c=>c[1]))},'#ec4899',true);`;
    return htmlShell('Rules Dashboard — '+fname, body, script);
  }

  function buildTableHtml() {
    const {colMeta,selectedCols}=state.table, fname=state.fileName, rows=state.table.rows;
    const J=JSON.stringify;
    const kpis=[
      {v:rows.length.toLocaleString(),l:'Rows',cls:'c1'},
      {v:colMeta.length,l:'Columns',cls:'c2'},
      {v:colMeta.filter(c=>c.type==='numeric').length,l:'Numeric Cols',cls:'c3'},
      {v:colMeta.filter(c=>c.type==='categorical').length,l:'Categorical Cols',cls:'c4'},
    ];
    const chartDivs=selectedCols.map((col,i)=>{
      const wide=i===2||i===5;
      const h=col.type==='numeric'?'220px':`${Math.max(180,Math.min(col.unique,25)*28)}px`;
      return `<div class="card${wide?' wide':''}"><div class="ct">${esc(col.name)}</div>
        <div class="cs">${col.type} · ${col.unique.toLocaleString()} unique · ${col.nullPct}% empty</div>
        <div class="ch" style="height:${h}"><canvas id="cTC${i}"></canvas></div></div>`;
    }).join('');
    const chartScript=selectedCols.map((col,i)=>{
      const color=PALETTE[i%PALETTE.length];
      if (col.type==='categorical'){
        const dist=col.distribution||[];
        return `bar('cTC${i}',${J(dist.map(d=>String(d[0])))},${J(dist.map(d=>d[1]))},'${color}',true);`;
      }
      const hist=col.histogram||[];
      return `bar('cTC${i}',${J(hist.map(h=>h.label))},${J(hist.map(h=>h.count))},'${color}',false);`;
    }).join('\n');
    const tableRows=colMeta.map((c,i)=>`
      <tr><td>${i+1}</td><td>${esc(c.name)}</td><td>${c.type}</td><td>${c.unique.toLocaleString()}</td>
      <td>${c.nullPct}%</td><td style="font-size:.8rem">${c.type==='numeric'?`${c.min?.toLocaleString()} / ${c.max?.toLocaleString()} / ${c.avg?.toFixed(2)}`:'—'}</td>
      <td style="font-size:.78rem">${c.sample.map(v=>esc(String(v))).join(', ')}</td></tr>`).join('');
    const body=`<h1>📊 Data Dashboard</h1>
<div class="sub">File: <strong>${esc(fname)}</strong> · Generated: ${new Date().toLocaleString()}</div>
<div class="kpi-row">${kpis.map(k=>`<div class="kpi-card ${k.cls}"><div class="kpi-val">${k.v}</div><div class="kpi-lbl">${k.l}</div></div>`).join('')}</div>
<div class="grid">${chartDivs}</div>
<div class="tbl"><div class="ct" style="margin-bottom:10px">Column Summary</div><div style="overflow:auto"><table>
  <thead><tr><th>#</th><th>Column</th><th>Type</th><th>Unique</th><th>Empty %</th><th>Min/Max/Avg</th><th>Samples</th></tr></thead>
  <tbody>${tableRows}</tbody></table></div></div>`;
    return htmlShell('Data Dashboard — '+fname, body, chartScript);
  }

  function buildV7Html() {
    const allRules  = state.rules;
    const localRules = state.v7LocalRules;
    const fname  = state.fileName;
    const J      = JSON.stringify;
    const total  = allRules.length;
    const locTotal = localRules.length;

    // ── Pre-compute chart data ──────────────────────────────────
    const actions  = tally(allRules, r=>r.action);
    const statuses = tally(allRules, r=>r.status);
    const typeDist = tally(allRules, r=>r.type==='B'?'Built-in':'Local');
    const protos   = tally(allRules, r=>r.protocol).slice(0,10);
    const cats     = tally(allRules, r=>snortCategory(r.msg));
    const cat20    = cats.slice(0,20);
    const sidBkts  = tally(allRules, r=>sidBucket(r.sid));
    const ctypes   = tally(allRules, r=>r.classtype).slice(0,15);
    const groups   = tally(allRules, r=>r.groups).filter(g=>g[0]!=='—').slice(0,15);
    const gids     = tally(allRules, r=>String(r.gid));

    const dupC   = localRules.filter(r=>r.isDuplicate).length;
    const synC   = localRules.filter(r=>r.syntaxErrors.length>0).length;
    const delC   = localRules.filter(r=>r.deleteRecommended).length;
    const revC   = state.v7Stats?.reviewCount || localRules.filter(r=>r.isReviewNeeded).length;
    const cleanC = Math.max(0, locTotal - delC - revC);
    const builtins = allRules.filter(r=>r.type==='B').length;
    const active   = allRules.filter(r=>r.status==='Active').length;
    const disabled = allRules.filter(r=>r.status==='Disabled').length;
    const localAna = [['이상 없음',cleanC],['삭제 권고',delC],['검토 필요',revC],['Built-in 중복',dupC],['문법 오류',synC]].filter(x=>x[1]>0);
    const anaColors = ['#22c55e','#ef4444','#3b82f6','#f59e0b','#a855f7'];

    const pDel = locTotal?(delC/locTotal*100).toFixed(1):'0';
    const pRev = locTotal?(revC/locTotal*100).toFixed(1):'0';
    const pDup = locTotal?Math.max(0,(dupC-delC)/locTotal*100).toFixed(1):'0';
    const pSyn = locTotal?Math.max(0,(synC-delC)/locTotal*100).toFixed(1):'0';
    const pOk  = Math.max(0,100-+pDel-+pRev-+pDup-+pSyn).toFixed(1);

    // ── Category table rows ─────────────────────────────────────
    const catTableRows = cats.slice(0,50).map((c,i)=>{
      const sub = allRules.filter(r=>snortCategory(r.msg)===c[0]);
      const bl  = sub.filter(r=>r.action==='BLOCK').length;
      const al  = sub.filter(r=>r.action==='ALERT').length;
      const bi  = sub.filter(r=>r.type==='B').length;
      const lo  = sub.filter(r=>r.type==='L').length;
      return `<tr><td>${i+1}</td><td class="hl">${esc(c[0])}</td><td>${c[1].toLocaleString()}</td><td>${((c[1]/total)*100).toFixed(1)}%</td><td>${bl}</td><td>${al}</td><td>${bi}</td><td>${lo}</td></tr>`;
    }).join('');

    // ── Issues accordion HTML (static, no JS needed) ────────────
    const delRules = localRules.filter(r=>r.deleteRecommended);
    const dupRules = localRules.filter(r=>r.isDuplicate);
    const synRules = localRules.filter(r=>r.syntaxErrors.length>0);
    const revRules = localRules.filter(r=>r.isReviewNeeded);

    const issueItem = (r, bodyHtml) => `
      <div class="iitem">
        <div><span class="isid">SID ${r.sid}</span><span class="imsg">${esc((r.msg||'').slice(0,100))}</span></div>
        <div class="ird">${esc((r.ruleData||'').slice(0,320))}${(r.ruleData||'').length>320?'…':''}</div>
        <div class="ireason">${bodyHtml}</div>
      </div>`;

    const issueSection = (title, bgColor, textColor, items, bodyFn) => {
      if (!items.length) return '';
      return `<div class="isec">
        <div class="ihdr" style="background:${bgColor};color:${textColor}" onclick="const b=this.nextElementSibling;const o=b.style.display!=='none';b.style.display=o?'none':'';this.querySelector('.chev').textContent=o?'▼':'▲'">
          <span>${title} <strong>(${items.length}건)</strong></span><span class="chev">▼</span>
        </div>
        <div class="ibody" style="display:none">${items.map(r=>issueItem(r,bodyFn(r))).join('')}</div>
      </div>`;
    };

    const issuesHtml = `
      <p class="isub">총 <strong>${delC+revC}</strong>건의 조치 필요 룰이 있습니다.</p>
      ${issueSection('🗑 삭제 권고 룰','#fff5f5','#b91c1c',delRules,r=>`<span style="color:#b91c1c">${esc(r.deleteReason.slice(0,200))}</span>`)}
      ${issueSection('✔ Built-in 중복 룰','#fefce8','#a16207',dupRules,r=>`중복 Built-in SID: <strong>${esc(r.dupBuiltinSid)}</strong>`)}
      ${issueSection('⚠ 문법 오류 룰','#f5f3ff','#7e22ce',synRules,r=>r.syntaxErrors.map((e,i)=>`[${i+1}] ${esc(e)}`).join('<br>'))}
      ${issueSection('👁 검토 필요 룰','#eff6ff','#1d4ed8',revRules,r=>r.unnecessaryReasons.map((e,i)=>`[${i+1}] ${esc(e)}`).join('<br>'))}`;

    // ── Embed only needed fields of localRules (trim size) ───────
    const localEmbed = localRules.map(r=>({
      sid:r.sid, msg:r.msg, action:r.action, status:r.status,
      ruleData:r.ruleData||'',
      isDuplicate:r.isDuplicate, dupBuiltinSid:r.dupBuiltinSid||'',
      syntaxErrors:r.syntaxErrors,
      deleteRecommended:r.deleteRecommended, deleteReason:r.deleteReason||'',
      isReviewNeeded:r.isReviewNeeded,
      unnecessaryReasons:r.unnecessaryReasons||[],
    }));

    const P = JSON.stringify(PALETTE);

    return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>v7 Rules Dashboard — ${esc(fname)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"><\/script>
<style>
*{box-sizing:border-box}
:root{--bg:#061128;--panel:#0a1838;--border:#1a2d55;--primary:#00bceb;--text:#fff;--muted:#8fa4c8}
body{margin:0;padding:20px 24px;background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif;font-size:14px}
h1{color:var(--primary);font-size:1.4rem;margin:0 0 4px;font-weight:800}
.sub{color:var(--muted);font-size:.82rem;margin-bottom:16px}
/* KPIs */
.krow{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.kcard{flex:1;min-width:110px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 16px}
.kval{font-size:1.7rem;font-weight:800;line-height:1}.klbl{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.kcard.c1{border-top:4px solid #00bceb}.kcard.c1 .kval{color:#00bceb}
.kcard.c2{border-top:4px solid #3070E7}.kcard.c2 .kval{color:#60a5fa}
.kcard.c3{border-top:4px solid #22C55E}.kcard.c3 .kval{color:#4ade80}
.kcard.c4{border-top:4px solid #FF9000}.kcard.c4 .kval{color:#fb923c}
.kcard.c5{border-top:4px solid #64748B}.kcard.c5 .kval{color:#94a3b8}
.kcard.cv1{border-top:4px solid #f59e0b}.kcard.cv1 .kval{color:#f59e0b}
.kcard.cv2{border-top:4px solid #a855f7}.kcard.cv2 .kval{color:#a855f7}
.kcard.cv3{border-top:4px solid #ef4444}.kcard.cv3 .kval{color:#ef4444}
.kcard.cv4{border-top:4px solid #3b82f6}.kcard.cv4 .kval{color:#3b82f6}
.kcard.cv5{border-top:4px solid #14b8a6}.kcard.cv5 .kval{color:#14b8a6}
/* Analysis Banner */
.abanner{background:rgba(20,184,166,.09);border:1px solid rgba(20,184,166,.25);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.atitle{font-size:.78rem;font-weight:700;color:#5eead4;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
.barwrap{height:20px;border-radius:5px;overflow:hidden;display:flex;background:#1a2d55}
.bseg{height:100%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden}
.bseg.del{background:#ef4444}.bseg.rev{background:#3b82f6}.bseg.dup{background:#f59e0b}.bseg.syn{background:#a855f7}.bseg.ok{background:#22c55e}
.aleg{display:flex;flex-wrap:wrap;gap:8px;margin-top:7px}
.aleg-i{display:flex;align-items:center;gap:4px;font-size:.73rem;color:var(--muted)}
.aleg-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
/* Tabs */
.tabbar{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:14px;flex-wrap:wrap}
.tabbtn{padding:8px 16px;font-size:.82rem;font-weight:600;border:none;background:transparent;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-2px;transition:color .15s,border-color .15s}
.tabbtn.active{color:var(--primary);border-bottom-color:var(--primary)}
.tabpanel{display:none}.tabpanel.active{display:block}
/* Charts grid */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.card.wide{grid-column:1/-1}
.ct{font-size:.75rem;font-weight:700;color:var(--primary);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.ch{position:relative}
/* Table */
.tblwrap{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:14px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th,td{border:1px solid var(--border);padding:6px 9px;text-align:left;vertical-align:top}
th{background:rgba(0,102,204,.2);color:#9bd7ff;position:sticky;top:0}
tr:nth-child(even){background:rgba(255,255,255,.02)}
.hl{font-weight:600;color:var(--primary)}
/* Filter bar */
.fbar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.fbtn{padding:4px 12px;border-radius:20px;font-size:.76rem;font-weight:600;border:1px solid var(--border);background:var(--panel);cursor:pointer;color:var(--muted);transition:all .15s}
.fbtn:hover{border-color:#8fa4c8;color:#fff}
.fbtn.active{background:#00bceb;color:#000;border-color:#00bceb}
.fbtn.fa.active{background:#f59e0b;border-color:#f59e0b;color:#000}
.fbtn.fb.active{background:#a855f7;border-color:#a855f7}
.fbtn.fc.active{background:#ef4444;border-color:#ef4444}
.fbtn.fd.active{background:#3b82f6;border-color:#3b82f6}
.fbtn.fe.active{background:#22c55e;border-color:#22c55e;color:#000}
/* Local table */
.ltbl{font-size:.78rem;width:100%;border-collapse:collapse}
.ltbl td,.ltbl th{padding:5px 7px;border:1px solid var(--border)}
.ltbl th{background:rgba(0,102,204,.2);color:#9bd7ff;position:sticky;top:0}
.rd{font-family:Consolas,monospace;font-size:.68rem;max-width:260px;word-break:break-all}
.rd-del td{background:rgba(239,68,68,.08)!important}
.rd-syn td{background:rgba(168,85,247,.08)!important}
.rd-dup td{background:rgba(245,158,11,.07)!important}
.rd-rev td{background:rgba(59,130,246,.07)!important}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.7rem;font-weight:700;margin:1px}
.bd{background:rgba(239,68,68,.2);color:#fca5a5}.bs{background:rgba(168,85,247,.2);color:#d8b4fe}
.bu{background:rgba(245,158,11,.2);color:#fcd34d}.br{background:rgba(59,130,246,.2);color:#93c5fd}.bo{background:rgba(34,197,94,.2);color:#86efac}
/* Pagination */
.pgbar{display:flex;gap:4px;align-items:center;justify-content:flex-end;padding:8px 0 0;font-size:.78rem;color:var(--muted);flex-wrap:wrap}
.pgbtn{padding:3px 9px;border-radius:6px;border:1px solid var(--border);background:var(--panel);cursor:pointer;font-size:.76rem;color:var(--muted)}
.pgbtn:hover{border-color:var(--primary);color:var(--primary)}
.pgbtn.active{background:var(--primary);color:#000;border-color:var(--primary)}
/* Issues */
.isub{font-size:.83rem;color:var(--muted);margin:0 0 12px}
.isec{margin-bottom:10px;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.ihdr{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;cursor:pointer;font-weight:700;font-size:.82rem;user-select:none}
.ihdr:hover{opacity:.9}.chev{flex-shrink:0;margin-left:8px}
.ibody{padding:0 12px 12px}
.iitem{margin-top:8px;border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:.78rem}
.isid{font-weight:700;color:var(--primary);margin-right:8px;font-family:Consolas,monospace}
.imsg{color:#e2e8f0;font-weight:600}
.ird{font-family:Consolas,monospace;font-size:.68rem;color:var(--muted);word-break:break-all;margin-top:4px;line-height:1.5}
.ireason{margin-top:5px;font-size:.74rem;font-weight:600}
/* Footer */
.footer{margin-top:20px;color:var(--muted);font-size:.74rem;text-align:center;padding-top:12px;border-top:1px solid var(--border)}
@media(max-width:700px){.grid{grid-template-columns:1fr}.card.wide{grid-column:1}}
</style>
</head>
<body>
<h1>📊 Rules Dashboard — v7 Analysis</h1>
<div class="sub">File: <strong>${esc(fname)}</strong> · Generated: ${new Date().toLocaleString()}</div>

<!-- KPI Row 1: Overall -->
<div class="krow">
  <div class="kcard c1"><div class="kval">${total.toLocaleString()}</div><div class="klbl">Total Rules</div></div>
  <div class="kcard c2"><div class="kval">${builtins.toLocaleString()}</div><div class="klbl">Built-in</div></div>
  <div class="kcard c3"><div class="kval">${locTotal.toLocaleString()}</div><div class="klbl">Local</div></div>
  <div class="kcard c4"><div class="kval">${active.toLocaleString()}</div><div class="klbl">Active</div></div>
  <div class="kcard c5"><div class="kval">${disabled.toLocaleString()}</div><div class="klbl">Disabled</div></div>
</div>

<!-- Analysis Banner -->
<div class="abanner">
  <div class="atitle">🔬 로컬 룰 분석 (v7) — ${locTotal.toLocaleString()}개 로컬 룰</div>
  <div class="krow" style="margin-bottom:10px">
    <div class="kcard cv1"><div class="kval">${dupC}</div><div class="klbl">✔ Built-in 중복</div></div>
    <div class="kcard cv2"><div class="kval">${synC}</div><div class="klbl">⚠ 문법 오류</div></div>
    <div class="kcard cv3"><div class="kval">${delC}</div><div class="klbl">🗑 삭제 권고</div></div>
    <div class="kcard cv4"><div class="kval">${revC}</div><div class="klbl">👁 검토 필요</div></div>
    <div class="kcard cv5"><div class="kval">${cleanC}</div><div class="klbl">✅ 이상 없음</div></div>
  </div>
  <div class="barwrap">
    ${+pDel>0?`<div class="bseg del" style="flex:${pDel}">${pDel}%</div>`:''}
    ${+pRev>0?`<div class="bseg rev" style="flex:${pRev}">${pRev}%</div>`:''}
    ${+pDup>0?`<div class="bseg dup" style="flex:${pDup}">${pDup}%</div>`:''}
    ${+pSyn>0?`<div class="bseg syn" style="flex:${pSyn}">${pSyn}%</div>`:''}
    <div class="bseg ok" style="flex:${pOk}">${pOk}%</div>
  </div>
  <div class="aleg">
    <div class="aleg-i"><div class="aleg-dot" style="background:#ef4444"></div>삭제 권고</div>
    <div class="aleg-i"><div class="aleg-dot" style="background:#3b82f6"></div>검토 필요</div>
    <div class="aleg-i"><div class="aleg-dot" style="background:#f59e0b"></div>Built-in 중복</div>
    <div class="aleg-i"><div class="aleg-dot" style="background:#a855f7"></div>문법 오류</div>
    <div class="aleg-i"><div class="aleg-dot" style="background:#22c55e"></div>이상 없음</div>
  </div>
</div>

<!-- Tab Bar -->
<div class="tabbar">
  <button class="tabbtn active" onclick="switchTab('ov',this)">📊 Overview</button>
  <button class="tabbtn" onclick="switchTab('lo',this)">🔍 Local Analysis <span style="background:rgba(255,255,255,.1);border-radius:10px;padding:1px 7px;font-size:.7rem;margin-left:4px">${locTotal}</span></button>
  <button class="tabbtn" onclick="switchTab('is',this)">⚠ Issues <span style="background:rgba(239,68,68,.25);color:#fca5a5;border-radius:10px;padding:1px 7px;font-size:.7rem;margin-left:4px">${delC+revC}</span></button>
</div>

<!-- Tab: Overview -->
<div id="tab-ov" class="tabpanel active">
  <div class="grid">
    <div class="card"><div class="ct">Rule Action</div><div class="ch" style="height:180px"><canvas id="cA"></canvas></div></div>
    <div class="card"><div class="ct">Status</div><div class="ch" style="height:180px"><canvas id="cS"></canvas></div></div>
    <div class="card"><div class="ct">Built-in vs Local</div><div class="ch" style="height:180px"><canvas id="cT"></canvas></div></div>
    <div class="card"><div class="ct">Protocol</div><div class="ch" style="height:180px"><canvas id="cP"></canvas></div></div>
    <div class="card"><div class="ct">🔬 로컬 룰 분석 현황</div><div class="ch" style="height:180px"><canvas id="cLA"></canvas></div></div>
    <div class="card"><div class="ct">GID</div><div class="ch" style="height:180px"><canvas id="cG"></canvas></div></div>
    <div class="card wide"><div class="ct">Top 20 Categories</div><div class="ch" style="height:520px"><canvas id="cCat"></canvas></div></div>
    <div class="card wide"><div class="ct">Top 15 Classtypes</div><div class="ch" style="height:420px"><canvas id="cCT"></canvas></div></div>
    <div class="card"><div class="ct">SID Range</div><div class="ch" style="height:300px"><canvas id="cSid"></canvas></div></div>
    <div class="card wide"><div class="ct">Top 15 Assigned Groups</div><div class="ch" style="height:420px"><canvas id="cGrp"></canvas></div></div>
  </div>
  <div class="tblwrap">
    <div class="ct" style="margin-bottom:8px">Category Details — Top 50</div>
    <table><thead><tr><th>#</th><th>Category</th><th>Total</th><th>%</th><th>BLOCK</th><th>ALERT</th><th>Built-in</th><th>Local</th></tr></thead>
    <tbody>${catTableRows}</tbody></table>
  </div>
</div>

<!-- Tab: Local Analysis (interactive) -->
<div id="tab-lo" class="tabpanel">
  <div class="fbar" id="fbar"></div>
  <div class="tblwrap" id="ltbl-wrap"></div>
</div>

<!-- Tab: Issues (static) -->
<div id="tab-is" class="tabpanel">
  ${issuesHtml}
</div>

<div class="footer">Generated by Snort Rule Converter · v7 Dashboard · ${new Date().toLocaleString()}</div>

<script>(function(){
const P=${P};
const G='#1a2d55',TC='#8fa4c8',LC='#e2e8f0';
function bar(id,lbl,dat,col,h){const c=document.getElementById(id);if(!c||typeof Chart==='undefined')return;new Chart(c,{type:'bar',data:{labels:lbl,datasets:[{data:dat,backgroundColor:col+'bb',borderColor:col,borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,indexAxis:h?'y':'x',plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+Number(ctx.raw).toLocaleString()}}},scales:{x:{ticks:{color:h?TC:LC,font:{size:10}},grid:{color:G}},y:{ticks:{color:h?LC:TC,font:{size:10}},grid:{color:G}}}}});}
function donut(id,lbl,dat,cols){const c=document.getElementById(id);if(!c||typeof Chart==='undefined')return;new Chart(c,{type:'doughnut',data:{labels:lbl,datasets:[{data:dat,backgroundColor:cols.map(x=>x+'bb'),borderColor:cols,borderWidth:1}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:LC,font:{size:11},boxWidth:14,padding:8}},tooltip:{callbacks:{label:ctx=>' '+ctx.label+': '+Number(ctx.raw).toLocaleString()}}}}});}

bar('cA',${J(actions.map(a=>a[0]))},${J(actions.map(a=>a[1]))},'#00bceb',true);
donut('cS',${J(statuses.map(s=>s[0]))},${J(statuses.map(s=>s[1]))},['#22c55e','#94a3b8','#ff7e3f'].slice(0,${statuses.length}));
donut('cT',${J(typeDist.map(t=>t[0]))},${J(typeDist.map(t=>t[1]))},['#00bceb','#f59e0b']);
donut('cP',${J(protos.map(p=>p[0]))},${J(protos.map(p=>p[1]))},P.slice(0,${protos.length}));
donut('cLA',${J(localAna.map(x=>x[0]))},${J(localAna.map(x=>x[1]))},${J(anaColors.slice(0,localAna.length))});
donut('cG',${J(gids.map(g=>'GID '+g[0]))},${J(gids.map(g=>g[1]))},P.slice(0,${gids.length}));
bar('cCat',${J(cat20.map(c=>c[0]))},${J(cat20.map(c=>c[1]))},'#00bceb',true);
bar('cCT',${J(ctypes.map(c=>c[0]))},${J(ctypes.map(c=>c[1]))},'#ec4899',true);
bar('cSid',${J(sidBkts.map(s=>s[0]))},${J(sidBkts.map(s=>s[1]))},'#3070E7',false);
bar('cGrp',${J(groups.map(g=>g[0]))},${J(groups.map(g=>g[1]))},'#a855f7',true);
})();

// Global helpers for inline onclick handlers
var LR=${J(localEmbed)};
var _curFilter='all', _curPage=0;
function switchTab(id,btn){
  document.querySelectorAll('.tabpanel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tabbtn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
  if(id==='lo'&&!document.querySelector('#fbar .fbtn'))renderLocalTab(LR,'all',0);
}
function renderLocalTab(lr,filter,page){
  _curFilter=filter; _curPage=page;
  var PER=50;
  var fmap={all:function(){return true},a:function(r){return r.isDuplicate},b:function(r){return r.syntaxErrors.length>0},c:function(r){return r.deleteRecommended},d:function(r){return r.isReviewNeeded},e:function(r){return !r.isDuplicate&&!r.syntaxErrors.length&&!r.deleteRecommended&&!r.isReviewNeeded}};
  var fil=lr.filter(fmap[filter]||fmap.all);
  var maxP=Math.max(0,Math.ceil(fil.length/PER)-1);
  page=Math.min(page,maxP);
  var pg=fil.slice(page*PER,(page+1)*PER);
  var dupN=lr.filter(function(r){return r.isDuplicate}).length;
  var synN=lr.filter(function(r){return r.syntaxErrors.length>0}).length;
  var delN=lr.filter(function(r){return r.deleteRecommended}).length;
  var revN=lr.filter(function(r){return r.isReviewNeeded}).length;
  var okN=lr.filter(function(r){return !r.isDuplicate&&!r.syntaxErrors.length&&!r.deleteRecommended&&!r.isReviewNeeded}).length;
  var filters=[['all','전체 ('+lr.length+')',''],['a','✔ 중복 ('+dupN+')','fa'],['b','⚠ 문법오류 ('+synN+')','fb'],['c','🗑 삭제권고 ('+delN+')','fc'],['d','👁 검토필요 ('+revN+')','fd'],['e','✅ 이상없음 ('+okN+')','fe']];
  document.getElementById('fbar').innerHTML=filters.map(function(x){var f=x[0],l=x[1],c=x[2];return '<button class="fbtn '+c+(filter===f?' active':'')+'" onclick="renderLocalTab(LR,\''+f+'\',0)">'+l+'</button>';}).join('');
  function rc(r){return r.deleteRecommended?'rd-del':r.syntaxErrors.length?'rd-syn':r.isDuplicate?'rd-dup':r.isReviewNeeded?'rd-rev':'';}
  function bdg(r){var b=[];if(r.isDuplicate)b.push('<span class="badge bu">중복</span>');if(r.syntaxErrors.length)b.push('<span class="badge bs">문법오류</span>');if(r.deleteRecommended)b.push('<span class="badge bd">삭제권고</span>');if(r.isReviewNeeded)b.push('<span class="badge br">검토필요</span>');if(!b.length)b.push('<span class="badge bo">OK</span>');return b.join('');}
  function esc2(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  var rows=pg.map(function(r,i){return '<tr class="'+rc(r)+'"><td style="text-align:center">'+(page*PER+i+1)+'</td><td style="font-family:Consolas;font-weight:700;color:#00bceb;white-space:nowrap">'+r.sid+'</td><td style="max-width:200px;font-size:.75rem">'+esc2(r.msg)+'</td><td style="white-space:nowrap">'+esc2(r.action)+'</td><td style="white-space:nowrap;font-size:.75rem">'+esc2(r.status)+'</td><td style="white-space:nowrap">'+bdg(r)+'</td><td style="font-size:.7rem;color:#d8b4fe;max-width:220px">'+(r.syntaxErrors.length?r.syntaxErrors.slice(0,3).map(function(e){return esc2(e.slice(0,80));}).join('<br>'):r.deleteReason?esc2(r.deleteReason.slice(0,120)):r.unnecessaryReasons.slice(0,2).map(function(x){return esc2(x.slice(0,80));}).join('<br>'))+'</td><td class="rd">'+esc2((r.ruleData||'').slice(0,200))+((r.ruleData||'').length>200?'…':'')+'</td></tr>';}).join('');
  var pgCount=Math.ceil(fil.length/PER);
  var pgH='';
  if(pgCount>1){
    var pgNums='';var s=Math.max(0,Math.min(page-3,pgCount-7));var e=Math.min(pgCount,s+7);
    for(var i=s;i<e;i++){pgNums+='<button class="pgbtn'+(i===page?' active':'')+'" onclick="renderLocalTab(LR,\''+filter+'\','+i+')">'+(i+1)+'</button>';}
    pgH='<div class="pgbar"><span>'+fil.length.toLocaleString()+' 건 · '+(page+1)+'/'+pgCount+' 페이지</span>'+(page>0?'<button class="pgbtn" onclick="renderLocalTab(LR,\''+filter+'\','+(page-1)+')">‹</button>':'')+pgNums+(page<pgCount-1?'<button class="pgbtn" onclick="renderLocalTab(LR,\''+filter+'\','+(page+1)+')">›</button>':'')+'</div>';
  }
  document.getElementById('ltbl-wrap').innerHTML='<div style="overflow:auto"><table class="ltbl"><thead><tr><th>#</th><th>SID</th><th>Message</th><th>Action</th><th>Status</th><th>분석</th><th>근거/오류</th><th>Rule Details</th></tr></thead><tbody>'+rows+'</tbody></table></div>'+pgH;
}
</body></html>`;
  }

  function downloadHtml() {
    if (!state.mode) return;
    let html;
    if (state.mode === 'snort-v7') html = buildV7Html();
    else if (state.mode === 'table') html = buildTableHtml();
    else html = buildSnortHtml();
    const blob=new Blob([html],{type:'text/html;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const a=Object.assign(document.createElement('a'),{href:url,download:'dashboard-'+state.fileName.replace(/\.[^.]+$/,'')+'-'+new Date().toISOString().slice(0,10)+'.html'});
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }

  document.addEventListener('DOMContentLoaded', () => {
    const fileInput=document.getElementById('dashFileInput');
    const dropZone=document.getElementById('dashDropZone');
    const dlBtn=document.getElementById('dashDownloadBtn');
    const resetBtn=document.getElementById('dashResetBtn');
    if (!fileInput) return;

    dlBtn?.addEventListener('click', downloadHtml);

    resetBtn?.addEventListener('click', () => {
      state.mode=null; state.rules=[]; state.localRules=[]; state.v7Stats=null;
      state.v7LocalRules=[]; state.v7Filter='all'; state.v7Page=0; state.v7ActiveTab='overview';
      state.fileName='';
      state.table={headers:[],rows:[],colMeta:[],selectedCols:[]};
      destroyCharts();
      ['dashContent','dashFileInfo'].forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='none';});
      ['dashDownloadBtn','dashResetBtn'].forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='none';});
      const dz=document.getElementById('dashDropZone');
      if (dz){dz.style.display='';dz.querySelector('.dash-drop-title').textContent='Drop your file here';dz.querySelector('.dash-drop-sub').textContent='or click Upload file above';}
      fileInput.value='';
      ['v7AnalysisBanner','v7TabBar','v7TabLocal','v7TabIssues'].forEach(id=>{const e=document.getElementById(id);if(e)e.remove();});
      const grid=document.getElementById('dashChartsGrid');
      if(grid){grid.className='dash-grid';grid.removeAttribute('data-tab');grid.style.display='';}
      const tblPnl=document.querySelector('#dashContent > .panel');
      if(tblPnl)tblPnl.style.display='';
      if(typeof window.__v7pg!=='undefined')delete window.__v7pg;
      if(typeof window.__v7flt!=='undefined')delete window.__v7flt;
    });

    fileInput.addEventListener('change', e=>{const f=e.target.files?.[0];if(f)handleFile(f);});

    dropZone?.addEventListener('dragover',  e=>{e.preventDefault();dropZone.classList.add('drag-over');});
    dropZone?.addEventListener('dragleave', ()=>dropZone.classList.remove('drag-over'));
    dropZone?.addEventListener('drop', e=>{
      e.preventDefault();dropZone.classList.remove('drag-over');
      const f=e.dataTransfer.files?.[0];if(f)handleFile(f);
    });
    dropZone?.addEventListener('click', ()=>fileInput.click());
  });

  const dualState = {
    builtinText: '', localText: '', builtinName: '', localName: '',
    builtinRules: [], localRules: [], duplicates: [], syntaxErrors: [],
    dupFilter: 'all', synFilter: 'all', dualCharts: {}
  };

  function parseSnortRulesFull(text) {
    const rules = [];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i].trim();
      if (!raw || raw.startsWith('#')) continue;
      const ACTIONS = /^(alert|block|drop|log|pass|react|reject|rewrite|activate|dynamic|sdrop)\s/i;
      if (!ACTIONS.test(raw)) continue;
      const parenIdx = raw.indexOf('(');
      const headerStr = parenIdx >= 0 ? raw.slice(0, parenIdx).trim() : raw;
      const optStr    = parenIdx >= 0 ? raw.slice(parenIdx + 1).replace(/\)\s*$/, '') : '';
      const hParts    = headerStr.split(/\s+/);
      const getOpt = (key) => (optStr.match(new RegExp('\\b' + key + '\\s*:\\s*"([^"]*)"','i')) || [])[1] ?? null;
      const getOptN = (key) => parseInt((optStr.match(new RegExp('\\b' + key + '\\s*:\\s*(\\d+)','i')) || [])[1] || '0', 10);
      const getOptRaw = (key) => ((optStr.match(new RegExp('\\b' + key + '\\s*:\\s*([^;]+)','i')) || [])[1] || '').trim();
      const contents = [...optStr.matchAll(/\bcontent\s*:\s*"((?:[^"\\]|\\.)*)"/gi)].map(m => m[1]);
      const pcres    = [...optStr.matchAll(/\bpcre\s*:\s*"([^"]+)"/gi)].map(m => m[1]);
      const buffers  = [];
      ['http_uri','http_raw_uri','http_header','http_raw_header','http_cookie','http_client_body','http_raw_body','http_method','file_data','base64_data'].forEach(b => {
        if (new RegExp('\\b' + b + '\\s*[;:]').test(optStr)) buffers.push(b);
      });
      rules.push({
        raw, lineNum: i + 1,
        action:    (hParts[0] || '').toLowerCase(),
        protocol:  (hParts[1] || '').toLowerCase(),
        srcIp:     hParts[2] || '', srcPort: hParts[3] || '',
        direction: hParts[4] || '', dstIp: hParts[5] || '', dstPort: hParts[6] || '',
        msg:       getOpt('msg') || '',
        sid:       getOptN('sid'),
        rev:       getOptN('rev'),
        gid:       getOptN('gid') || 1,
        classtype: getOptRaw('classtype') || '(none)',
        contents, pcres, buffers, optStr
      });
    }
    return rules;
  }

  function computeFingerprint(r) {
    const c = r.contents.slice().sort().join('|').toLowerCase();
    const p = r.pcres.slice().sort().join('|').toLowerCase();
    const b = r.buffers.slice().sort().join(',');
    const key = [r.protocol, r.direction, c, p, b].join('__');
    return (c || p) ? key : '';
  }

  function analyzeDuplicates(builtinRules, localRules) {
    const bySid  = new Map(builtinRules.filter(r => r.sid > 0).map(r => [r.sid, r]));
    const byMsg  = new Map(builtinRules.filter(r => r.msg).map(r => [r.msg.toLowerCase().trim(), r]));
    const byFP   = new Map();
    for (const r of builtinRules) {
      const fp = computeFingerprint(r);
      if (!fp) continue;
      if (!byFP.has(fp)) byFP.set(fp, []);
      byFP.get(fp).push(r);
    }
    const byContent = new Map();
    for (const r of builtinRules) {
      if (!r.contents.length) continue;
      const k = r.contents.slice().sort().join('|').toLowerCase();
      if (!byContent.has(k)) byContent.set(k, []);
      byContent.get(k).push(r);
    }
    const results = [];
    for (const loc of localRules) {
      const reasons = []; let matched = null;
      if (loc.sid > 0 && bySid.has(loc.sid)) {
        matched = bySid.get(loc.sid);
        reasons.push({ type:'SID', cls:'sid', label:`SID ${loc.sid} 완전 일치`, detail:`Built-in "${matched.msg}" (SID ${matched.sid})와 동일 SID`, sev:'exact', icon:'🔴' });
      }
      if (loc.msg) {
        const mk = loc.msg.toLowerCase().trim();
        if (byMsg.has(mk)) { const b = byMsg.get(mk); if (!matched) matched = b;
          reasons.push({ type:'MSG', cls:'msg', label:'msg 메시지 완전 일치', detail:`"${loc.msg.slice(0,60)}"`, sev:'high', icon:'🟠' }); }
      }
      const fp = computeFingerprint(loc);
      if (fp && byFP.has(fp)) { const arr = byFP.get(fp); if (!matched) matched = arr[0];
        reasons.push({ type:'FP', cls:'fp', label:'탐지 패턴(시그니처) 동일', detail:`Built-in ${arr.map(b=>'SID '+b.sid).join(', ')}와 동일 패턴`, sev:'high', icon:'🟡' }); }
      if (loc.contents.length) {
        const ck = loc.contents.slice().sort().join('|').toLowerCase();
        if (byContent.has(ck) && !reasons.find(r=>r.type==='FP')) { const arr = byContent.get(ck); if (!matched) matched = arr[0];
          reasons.push({ type:'CONTENT', cls:'content', label:'content 패턴 일치', detail:`"${loc.contents.slice(0,2).join('", "')}"`, sev:'medium', icon:'🟡' }); }
      }
      if (reasons.length && matched) {
        results.push({ localRule: loc, builtinRule: matched, reasons, severity: reasons.some(r=>r.sev==='exact')?'exact':'likely' });
      }
    }
    return results;
  }

  function splitOptTokens(optStr) {
    const tokens = []; let cur = '', depth = 0, inQ = false;
    for (let i = 0; i < optStr.length; i++) {
      const ch = optStr[i];
      if (ch === '\\' && inQ) { cur += ch + (optStr[++i]||''); continue; }
      if (ch === '"') { inQ = !inQ; cur += ch; continue; }
      if (!inQ && ch === '(') { depth++; cur += ch; continue; }
      if (!inQ && ch === ')') { depth--; cur += ch; continue; }
      if (!inQ && depth === 0 && ch === ';') { tokens.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    if (cur.trim()) tokens.push(cur.trim());
    return tokens;
  }

  function validateLocalRuleSyntax(rules) {
    const VALID_ACTIONS   = ['alert','block','drop','log','pass','react','reject','rewrite','activate','dynamic','sdrop'];
    const VALID_PROTOS    = ['tcp','udp','icmp','ip','http','ftp','smtp','ssh','telnet','dns','tls','ssl','dcerpc','smb','gre','pkthdr','file'];
    const LEGACY_OPTS     = ['uricontent','threshold','logto','session','rawbytes','http_encode','sameip'];
    const PORT_RE         = /^(!?)(\[.*\]|any|\d+|\d+:\d*|\d*:\d+|\d+:\d+|\$\w+)$/;
    const errors = [];
    for (const rule of rules) {
      const errs = []; const { raw, lineNum, action, protocol, direction, srcPort, dstPort, optStr, sid, msg, rev, contents } = rule;
      if (!VALID_ACTIONS.includes(action))
        errs.push({ code:'H001', sev:'critical', msg:`잘못된 action: '${action}'`, fix:`유효 action: ${VALID_ACTIONS.slice(0,6).join(', ')} 등` });
      if (!VALID_PROTOS.includes(protocol))
        errs.push({ code:'H004', sev:'warning', msg:`알 수 없는 프로토콜: '${protocol}'`, fix:'tcp, udp, icmp, ip 등 사용' });
      if (direction !== '->' && direction !== '<>')
        errs.push({ code:'H007', sev:'critical', msg:`잘못된 방향 연산자: '${direction||"없음"}'`, fix:"'->' 또는 '<>' 사용" });
      if (!PORT_RE.test(srcPort))
        errs.push({ code:'H006', sev:'warning', msg:`소스 포트 의심: '${srcPort}'`, fix:'80 / 1024:65535 / any 형식' });
      if (!PORT_RE.test(dstPort))
        errs.push({ code:'H009', sev:'warning', msg:`목적지 포트 의심: '${dstPort}'`, fix:'80 / 1024:65535 / any 형식' });
      if (!raw.includes('(') || !raw.includes(')'))
        errs.push({ code:'O001', sev:'critical', msg:'옵션 블록 괄호 () 없음', fix:'룰 끝에 (msg:".."; sid:N; rev:1;) 형식 추가' });
      if (sid === 0 || !optStr.match(/\bsid\s*:\s*\d+\s*;/))
        errs.push({ code:'O003a', sev:'critical', msg:'sid 옵션 없음 (필수)', fix:'sid:1000001; 추가 (로컬 룰 1,000,000 이상 권장)' });
      else if (sid < 1000000)
        errs.push({ code:'S001', sev:'warning', msg:`로컬 룰 SID ${sid} < 1,000,000`, fix:`sid:${sid + 1000000}; 로 변경 권장` });
      if (!msg || !optStr.match(/\bmsg\s*:\s*"[^"]+"\s*;/))
        errs.push({ code:'O003b', sev:'critical', msg:'msg 옵션 없음 또는 따옴표 오류', fix:'msg:"Rule Description Here"; 추가' });
      if (rev === 0 || !optStr.match(/\brev\s*:\s*\d+\s*;/))
        errs.push({ code:'O003c', sev:'warning', msg:'rev 옵션 없음 (권장)', fix:'rev:1; 추가' });
      for (const opt of LEGACY_OPTS) {
        if (new RegExp('\\b' + opt + '\\s*[;:]').test(optStr))
          errs.push({ code:'S004', sev:'warning', msg:`Snort 2 전용 옵션 '${opt}' 사용`, fix:`'${opt}'은 Snort 3 미지원. 마이그레이션 필요.` });
      }
      const pcreM = optStr.match(/\bpcre\s*:\s*"([^"]+)"/);
      if (pcreM && !/^\/.*\/[imscABCDEGHIMOPQRSUVWYZ]*$/i.test(pcreM[1]))
        errs.push({ code:'O010', sev:'critical', msg:`PCRE 패턴 구문 오류: ${pcreM[1].slice(0,40)}`, fix:'/pattern/flags 형식 필요: pcre:"/abc/i";' });
      const tokens = splitOptTokens(optStr);
      for (const tok of tokens) {
        if (!tok) continue;
        const ci = tok.indexOf(':');
        if (ci >= 0) {
          const val = tok.slice(ci + 1);
          const qCount = (val.match(/(?<!\\)"/g) || []).length;
          if (qCount % 2 !== 0)
            errs.push({ code:'O002', sev:'critical', msg:`따옴표 불균형: ...${tok.slice(0, 30)}...`, fix:'문자열 값 닫기: key:"value";' });
        }
      }
      if (contents.length === 1 && contents[0].replace(/\|[0-9a-fA-F ]+\|/g,'').replace(/\s/g,'').length <= 4)
        errs.push({ code:'O005', sev:'warning', msg:'단일 content 패턴이 너무 짧음 (오탐 위험)', fix:'더 구체적인 패턴 추가 또는 다른 옵션과 조합' });
      if (errs.length) {
        const fixedRule = buildFixedRule(rule, errs);
        errors.push({ lineNum, raw, errors: errs, fixedRule });
      }
    }
    return errors;
  }

  function buildFixedRule(rule, errs) {
    let fixed = rule.raw;
    let optStr = rule.optStr;
    let modified = false;
    if (errs.find(e => e.code === 'O003a') && rule.sid === 0) {
      optStr += ' sid:1000001; rev:1;'; modified = true;
    } else if (errs.find(e => e.code === 'S001') && rule.sid > 0 && rule.sid < 1000000) {
      optStr = optStr.replace(/\bsid\s*:\s*\d+\s*;/, `sid:${rule.sid + 1000000};`); modified = true;
    }
    if (errs.find(e => e.code === 'O003b') && !rule.msg) {
      optStr = 'msg:"Local Rule Description"; ' + optStr; modified = true;
    }
    if (errs.find(e => e.code === 'O003c') && rule.rev === 0) {
      if (!optStr.match(/\brev\s*:\s*\d+\s*;/)) { optStr += ' rev:1;'; modified = true; }
    }
    if (errs.find(e => e.code === 'H007') && rule.direction !== '->' && rule.direction !== '<>') {
      fixed = fixed.replace(/\s+[^\s(]+\s+(?=\S+\s+\S+\s*\()/, ' -> '); modified = true;
    }
    if (modified) {
      const pi = fixed.indexOf('(');
      if (pi >= 0) fixed = fixed.slice(0, pi + 1) + optStr + ')';
    }
    return modified ? fixed : null;
  }

  function renderDualKpis(builtinRules, localRules, duplicates, syntaxErrors) {
    const el = document.getElementById('dualKpiRow');
    if (!el) return;
    const exactDup = duplicates.filter(d => d.severity === 'exact').length;
    const likelyDup = duplicates.filter(d => d.severity === 'likely').length;
    const critErr = syntaxErrors.filter(e => e.errors.some(x => x.sev === 'critical')).length;
    const warnErr = syntaxErrors.filter(e => !e.errors.some(x => x.sev === 'critical') && e.errors.some(x => x.sev === 'warning')).length;
    const cleanLocal = Math.max(0, localRules.length - duplicates.length - syntaxErrors.length);
    el.innerHTML = [
      { v: builtinRules.length.toLocaleString(), l: 'Built-in 룰', c: 'c-blue' },
      { v: localRules.length.toLocaleString(),   l: 'Local 룰',    c: 'c-cyan' },
      { v: exactDup + likelyDup,                  l: '중복 룰',     c: 'c-amber' },
      { v: critErr,                                l: '문법 오류 (Critical)', c: 'c-red' },
      { v: warnErr,                                l: '문법 경고',  c: 'c-purple' },
      { v: cleanLocal,                             l: '이상 없음',  c: 'c-green' }
    ].map(k => `<div class="dual-kpi-card ${k.c}"><div class="dual-kpi-val">${k.v}</div><div class="dual-kpi-lbl">${k.l}</div></div>`).join('');

    const total = localRules.length || 1;
    const pDup  = ((duplicates.length / total) * 100).toFixed(1);
    const pErr  = ((syntaxErrors.length / total) * 100).toFixed(1);
    const pOk   = Math.max(0, 100 - +pDup - +pErr).toFixed(1);
    document.getElementById('dualProgWrap').innerHTML = `
      <div style="margin-bottom:6px;font-size:.8rem;color:var(--muted);">Local 룰 분석 현황</div>
      <div class="dual-prog-bar">
        ${+pDup > 0 ? `<div class="dual-prog-seg s-dup" style="flex:${pDup}">${pDup}%</div>` : ''}
        ${+pErr > 0 ? `<div class="dual-prog-seg s-err" style="flex:${pErr}">${pErr}%</div>` : ''}
        <div class="dual-prog-seg s-ok" style="flex:${pOk}">${pOk}%</div>
      </div>
      <div class="dual-legend">
        <div class="dual-leg-item"><div class="dual-leg-dot" style="background:#f59e0b"></div>중복 (${pDup}%)</div>
        <div class="dual-leg-item"><div class="dual-leg-dot" style="background:#ef4444"></div>문법 오류 (${pErr}%)</div>
        <div class="dual-leg-item"><div class="dual-leg-dot" style="background:#22c55e"></div>이상 없음 (${pOk}%)</div>
      </div>`;
  }

  function destroyDualCharts() {
    Object.values(dualState.dualCharts).forEach(c => { try { c.destroy(); } catch(_){} });
    dualState.dualCharts = {};
  }

  function renderDualCharts(builtinRules, localRules, duplicates, syntaxErrors) {
    const grid = document.getElementById('dualChartsGrid');
    if (!grid || typeof Chart === 'undefined') return;
    destroyDualCharts();

    const tally = (arr, fn) => { const m = new Map(); arr.forEach(x => { const k=fn(x); m.set(k,(m.get(k)||0)+1); }); return [...m.entries()].sort((a,b)=>b[1]-a[1]); };
    const bActions   = tally(builtinRules, r => r.action.toUpperCase());
    const lActions   = tally(localRules,   r => r.action.toUpperCase());
    const bProtos    = tally(builtinRules, r => r.protocol.toUpperCase()).slice(0,8);
    const lProtos    = tally(localRules,   r => r.protocol.toUpperCase()).slice(0,8);
    const dupTypes   = tally(duplicates.flatMap(d => d.reasons), r => r.type);
    const errTypes   = tally(syntaxErrors.flatMap(e => e.errors), e => e.code);
    const classtypes = tally(localRules, r => r.classtype).slice(0,10);
    const dupSev     = [['완전 일치(SID)', duplicates.filter(d=>d.severity==='exact').length], ['유사 일치', duplicates.filter(d=>d.severity==='likely').length]].filter(x=>x[1]>0);
    const errSev     = [
      ['Critical', syntaxErrors.filter(e=>e.errors.some(x=>x.sev==='critical')).length],
      ['Warning',  syntaxErrors.filter(e=>!e.errors.some(x=>x.sev==='critical')&&e.errors.some(x=>x.sev==='warning')).length]
    ].filter(x=>x[1]>0);
    const cleanL = Math.max(0, localRules.length - duplicates.length - syntaxErrors.length);
    const overallData = [['이상 없음', cleanL], ['중복', duplicates.length], ['문법 오류', syntaxErrors.length]].filter(x=>x[1]>0);

    const LIGHT = document.getElementById('dashboardView')?.querySelector('#dualChartsGrid');
    const GR = '#d1d5db', TK = '#374151', LB = '#1e293b';

    const mkDot = (id, labels, data, colors) => {
      const el = document.getElementById(id); if (!el) return null;
      return new Chart(el, { type:'doughnut', data:{labels,datasets:[{data,backgroundColor:colors.map(c=>c+'bb'),borderColor:colors,borderWidth:1}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:LB,font:{size:11},boxWidth:14,padding:8}},tooltip:{callbacks:{label:c=>` ${c.label}: ${c.raw}`}}}} });
    };
    const mkBar = (id, labels, data, color, horiz=false) => {
      const el = document.getElementById(id); if (!el) return null;
      return new Chart(el, { type:'bar', data:{labels,datasets:[{data,backgroundColor:color+'bb',borderColor:color,borderWidth:1,borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:horiz?'y':'x',plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.raw}`}}},
          scales:{x:{ticks:{color:horiz?TK:LB,font:{size:10}},grid:{color:GR}},y:{ticks:{color:horiz?LB:TK,font:{size:10}},grid:{color:GR}}}} });
    };
    const mkGroupBar = (id, labels, datasets) => {
      const el = document.getElementById(id); if (!el) return null;
      return new Chart(el, { type:'bar', data:{labels,datasets},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'top',labels:{color:LB,font:{size:11}}}},
          scales:{x:{ticks:{color:LB,font:{size:10}},grid:{color:GR}},y:{ticks:{color:TK,font:{size:10}},grid:{color:GR}}}} });
    };

    grid.innerHTML = `
      <div class="dual-chart-card"><div class="dual-chart-title">📊 Local 룰 전체 분석 현황</div>
        <div style="height:200px"><canvas id="dcOverall"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">🔴 중복 유형 분포</div>
        <div style="height:200px"><canvas id="dcDupType"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">⚠️ 문법 오류 심각도</div>
        <div style="height:200px"><canvas id="dcErrSev"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">🔴 중복 심각도</div>
        <div style="height:200px"><canvas id="dcDupSev"></canvas></div></div>
      <div class="dual-chart-card wide"><div class="dual-chart-title">⚡ Built-in vs Local — Action 분포 비교</div>
        <div style="height:200px"><canvas id="dcActionCmp"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">📡 Built-in 프로토콜 분포</div>
        <div style="height:220px"><canvas id="dcBProto"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">📡 Local 프로토콜 분포</div>
        <div style="height:220px"><canvas id="dcLProto"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">🏷️ Local Classtype 분포</div>
        <div style="height:260px"><canvas id="dcClasstype"></canvas></div></div>
      <div class="dual-chart-card"><div class="dual-chart-title">🔑 문법 오류 코드별</div>
        <div style="height:260px"><canvas id="dcErrCode"></canvas></div></div>
      <div class="dual-chart-card wide"><div class="dual-chart-title">📋 Local 룰 SID 분포</div>
        <div style="height:200px"><canvas id="dcSidDist"></canvas></div></div>`;

    const allActions = [...new Set([...bActions.map(a=>a[0]), ...lActions.map(a=>a[0])])];
    const bActMap = Object.fromEntries(bActions); const lActMap = Object.fromEntries(lActions);
    const sidBkts = (() => { const m = new Map(); localRules.forEach(r => { const b = Math.floor(r.sid/100000)*100000; const k = b.toLocaleString()+'~'+(b+99999).toLocaleString(); m.set(k,(m.get(k)||0)+1); }); return [...m.entries()].sort((a,b)=>a[0].localeCompare(b[0])); })();

    requestAnimationFrame(() => {
      dualState.dualCharts.overall    = mkDot('dcOverall',   overallData.map(x=>x[0]),  overallData.map(x=>x[1]),  ['#22c55e','#f59e0b','#ef4444']);
      dualState.dualCharts.dupType    = mkDot('dcDupType',   dupTypes.map(x=>x[0]),     dupTypes.map(x=>x[1]),     ['#ef4444','#f59e0b','#3b82f6','#a855f7']);
      dualState.dualCharts.errSev     = mkDot('dcErrSev',    errSev.map(x=>x[0]),       errSev.map(x=>x[1]),       ['#ef4444','#f59e0b']);
      dualState.dualCharts.dupSev     = mkDot('dcDupSev',    dupSev.map(x=>x[0]),       dupSev.map(x=>x[1]),       ['#ef4444','#f59e0b']);
      dualState.dualCharts.actionCmp  = mkGroupBar('dcActionCmp', allActions, [
        { label:'Built-in', data:allActions.map(a=>bActMap[a]||0), backgroundColor:'#00bcebbb', borderColor:'#00bceb', borderWidth:1, borderRadius:4 },
        { label:'Local',    data:allActions.map(a=>lActMap[a]||0), backgroundColor:'#f59e0bbb', borderColor:'#f59e0b', borderWidth:1, borderRadius:4 }
      ]);
      dualState.dualCharts.bProto     = mkDot('dcBProto',    bProtos.map(p=>p[0]),      bProtos.map(p=>p[1]),      PALETTE.slice(0,bProtos.length));
      dualState.dualCharts.lProto     = mkDot('dcLProto',    lProtos.map(p=>p[0]),      lProtos.map(p=>p[1]),      PALETTE.slice(0,lProtos.length));
      dualState.dualCharts.classtype  = mkBar('dcClasstype',  classtypes.map(c=>c[0]),   classtypes.map(c=>c[1]),   '#00bceb', true);
      dualState.dualCharts.errCode    = mkBar('dcErrCode',    errTypes.map(e=>e[0]),     errTypes.map(e=>e[1]),     '#ef4444', true);
      dualState.dualCharts.sidDist    = mkBar('dcSidDist',    sidBkts.map(s=>s[0]),      sidBkts.map(s=>s[1]),      '#3b82f6', false);
    });
  }

  function renderDuplicates(duplicates, filter) {
    filter = filter || 'all';
    dualState.dupFilter = filter;
    const filtered = filter === 'all' ? duplicates : filter === 'exact' ? duplicates.filter(d=>d.severity==='exact') : duplicates.filter(d=>d.severity==='likely');
    const exactC  = duplicates.filter(d=>d.severity==='exact').length;
    const likelyC = duplicates.filter(d=>d.severity==='likely').length;
    const fb = document.getElementById('dupFilterBar');
    if (fb) fb.innerHTML = [
      { f:'all',    l:`전체 (${duplicates.length})` },
      { f:'exact',  l:`🔴 완전 일치 (${exactC})` },
      { f:'likely', l:`🟡 유사 일치 (${likelyC})` }
    ].map(b=>`<button class="filter-btn${filter===b.f?' active':''}" onclick="window.__dupFlt('${b.f}')">${b.l}</button>`).join('');

    const thead = document.querySelector('#dupTable thead');
    const tbody = document.querySelector('#dupTable tbody');
    if (!thead || !tbody) return;
    thead.innerHTML = '<tr><th>#</th><th>심각도</th><th>Local SID</th><th>Local msg</th><th>중복 이유</th><th>Built-in SID</th><th>Built-in msg</th><th>Local 룰</th></tr>';
    tbody.innerHTML = filtered.map((d,i) => `
      <tr>
        <td style="text-align:center;font-size:.78rem">${i+1}</td>
        <td><span class="sev-badge ${d.severity}">${d.severity==='exact'?'완전 일치':'유사 일치'}</span></td>
        <td style="font-family:Consolas;font-weight:700;color:#0369a1">${d.localRule.sid||'없음'}</td>
        <td style="font-size:.78rem;max-width:160px">${esc(d.localRule.msg.slice(0,80))}</td>
        <td>${d.reasons.map(r=>`<span class="dup-tag ${r.cls}" title="${esc(r.detail)}">${r.icon} ${r.label}</span>`).join('')}</td>
        <td style="font-family:Consolas;font-weight:700;color:#0369a1">${d.builtinRule.sid}</td>
        <td style="font-size:.78rem;max-width:160px">${esc(d.builtinRule.msg.slice(0,80))}</td>
        <td class="rule-code-cell">${esc(d.localRule.raw.slice(0,120))}${d.localRule.raw.length>120?'…':''}</td>
      </tr>`).join('');
    window.__dupFlt = f => renderDuplicates(dualState.duplicates, f);
  }

  function renderSyntaxErrors(syntaxErrors, filter) {
    filter = filter || 'all';
    dualState.synFilter = filter;
    const critC = syntaxErrors.filter(e=>e.errors.some(x=>x.sev==='critical')).length;
    const warnC = syntaxErrors.filter(e=>!e.errors.some(x=>x.sev==='critical')&&e.errors.some(x=>x.sev==='warning')).length;
    const filtered = filter === 'all' ? syntaxErrors : filter === 'critical' ? syntaxErrors.filter(e=>e.errors.some(x=>x.sev==='critical')) : syntaxErrors.filter(e=>!e.errors.some(x=>x.sev==='critical'));
    const fb = document.getElementById('synFilterBar');
    if (fb) fb.innerHTML = [
      { f:'all',      l:`전체 (${syntaxErrors.length})` },
      { f:'critical', l:`🔴 Critical (${critC})` },
      { f:'warning',  l:`🟡 Warning only (${warnC})` }
    ].map(b=>`<button class="filter-btn${filter===b.f?' active':''}" onclick="window.__synFlt('${b.f}')">${b.l}</button>`).join('');

    const list = document.getElementById('synErrorList');
    if (!list) return;
    list.innerHTML = filtered.map((e,idx) => {
      const hasCrit = e.errors.some(x=>x.sev==='critical');
      const errLabel = hasCrit ? `🔴 Critical (${e.errors.filter(x=>x.sev==='critical').length})` : `🟡 Warning (${e.errors.length})`;
      return `
      <div class="syn-card" id="synCard${idx}">
        <div class="syn-card-hdr" onclick="toggleSynCard(${idx})">
          <span class="syn-line-badge">Line ${e.lineNum}</span>
          <span style="font-size:.82rem;color:var(--text);font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(e.raw)}">${esc(e.raw.slice(0,60))}${e.raw.length>60?'…':''}</span>
          <span class="syn-err-count">${errLabel}</span>
          <span class="syn-card-chev">▼</span>
        </div>
        <div class="syn-raw">${esc(e.raw)}</div>
        <div class="syn-card-body">
          ${e.errors.map(err => `
            <div class="syn-err-item">
              <div class="syn-err-icon ${err.sev}">${err.sev==='critical'?'!':err.sev==='warning'?'⚠':'i'}</div>
              <div class="syn-err-text">
                <span class="syn-err-code ${err.sev}">${err.code}</span>
                <span class="syn-err-msg">${esc(err.msg)}</span>
                <div class="syn-fix-box"><span class="syn-fix-label">💡 수정 방법</span>${esc(err.fix)}</div>
              </div>
            </div>`).join('')}
          ${e.fixedRule ? `
            <div style="margin-top:10px;">
              <div class="syn-fix-label" style="margin-bottom:4px;">✅ 자동 수정 룰 (제안)</div>
              <div class="syn-fix-box" style="font-size:.75rem;">${esc(e.fixedRule)}</div>
            </div>` : ''}
        </div>
      </div>`;
    }).join('');
    if (!filtered.length) list.innerHTML = '<div style="text-align:center;padding:32px;color:var(--muted);">해당 조건의 문법 오류가 없습니다 ✅</div>';
    window.__synFlt = f => renderSyntaxErrors(dualState.syntaxErrors, f);
    window.toggleSynCard = idx => {
      const card = document.getElementById('synCard' + idx);
      if (card) card.classList.toggle('open');
    };
  }

  function generateDualReportHTML(builtinRules, localRules, duplicates, syntaxErrors, builtinName, localName) {
    const ts = new Date().toLocaleString('ko-KR');
    const cleanL = Math.max(0, localRules.length - duplicates.length - syntaxErrors.length);
    const exactDup = duplicates.filter(d=>d.severity==='exact').length;
    const critErr  = syntaxErrors.filter(e=>e.errors.some(x=>x.sev==='critical')).length;
    const dupRows  = duplicates.map((d,i) => `<tr>
      <td>${i+1}</td>
      <td><span style="padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:800;${d.severity==='exact'?'background:#fee2e2;color:#b91c1c;':'background:#fef9c3;color:#854d0e;'}">${d.severity==='exact'?'완전일치':'유사일치'}</span></td>
      <td style="font-family:monospace">${d.localRule.sid}</td>
      <td>${d.localRule.msg.replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}</td>
      <td>${d.reasons.map(r=>r.label).join('<br>')}</td>
      <td style="font-family:monospace">${d.builtinRule.sid}</td>
      <td>${d.builtinRule.msg.replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}</td>
    </tr>`).join('');
    const synRows = syntaxErrors.map((e,i) => `<tr>
      <td>${i+1}</td><td>${e.lineNum}</td>
      <td>${e.errors.some(x=>x.sev==='critical')?'<span style="color:#b91c1c;font-weight:700">🔴 Critical</span>':'<span style="color:#854d0e;font-weight:700">🟡 Warning</span>'}</td>
      <td style="font-family:monospace;font-size:.75rem;max-width:300px;overflow:hidden">${e.raw.replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c])).slice(0,120)}${e.raw.length>120?'…':''}</td>
      <td>${e.errors.map(x=>`<b>[${x.code}]</b> ${x.msg.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}`).join('<br>')}</td>
      <td style="font-family:monospace;font-size:.73rem;color:#166534;background:#f0fdf4;padding:4px 6px;border-radius:4px">${e.fixedRule ? e.fixedRule.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c])).slice(0,120) : '—'}</td>
    </tr>`).join('');
    return `<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Snort Rules Analysis Report — ${ts}</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:0;font-family:Inter,'Segoe UI',system-ui,sans-serif;background:#f1f5f9;color:#0f172a}
.wrap{max-width:1300px;margin:0 auto;padding:24px 20px}
.report-hdr{background:linear-gradient(135deg,#0369a1,#0ea5e9);color:#fff;border-radius:14px;padding:28px 32px;margin-bottom:24px}
.report-hdr h1{margin:0 0 6px;font-size:1.6rem;font-weight:800}
.report-hdr p{margin:0;opacity:.85;font-size:.9rem}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.kpi{flex:1;min-width:120px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;text-align:center}
.kpi-v{font-size:2.2rem;font-weight:800;line-height:1}
.kpi-l{font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;color:#64748b;margin-top:5px}
.kpi.blue{border-top:4px solid #3b82f6}.kpi.blue .kpi-v{color:#3b82f6}
.kpi.cyan{border-top:4px solid #0284c7}.kpi.cyan .kpi-v{color:#0284c7}
.kpi.amber{border-top:4px solid #d97706}.kpi.amber .kpi-v{color:#d97706}
.kpi.red{border-top:4px solid #dc2626}.kpi.red .kpi-v{color:#dc2626}
.kpi.green{border-top:4px solid #16a34a}.kpi.green .kpi-v{color:#16a34a}
.section{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin-bottom:20px}
.section h2{margin:0 0 14px;font-size:1.1rem;color:#0369a1;border-bottom:2px solid #e2e8f0;padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:.83rem}
th{background:#eff6ff;color:#1e40af;border:1px solid #c7d2fe;padding:9px 10px;text-align:left;font-weight:700;white-space:nowrap}
td{border:1px solid #e2e8f0;padding:8px 10px;vertical-align:top}
tr:nth-child(even) td{background:#f8fafc}
tr:hover td{background:#eff6ff}
.badge-exact{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:800;background:#fee2e2;color:#b91c1c}
.badge-likely{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:800;background:#fef9c3;color:#854d0e}
.footer{text-align:center;color:#94a3b8;font-size:.78rem;margin-top:28px;padding-top:16px;border-top:1px solid #e2e8f0}
</style></head><body><div class="wrap">
<div class="report-hdr">
  <h1>📊 Snort Rules Analysis Report</h1>
  <p>생성: ${ts} · Built-in: ${builtinName} · Local: ${localName}</p>
</div>
<div class="kpi-row">
  <div class="kpi blue"><div class="kpi-v">${builtinRules.length.toLocaleString()}</div><div class="kpi-l">Built-in 룰</div></div>
  <div class="kpi cyan"><div class="kpi-v">${localRules.length.toLocaleString()}</div><div class="kpi-l">Local 룰</div></div>
  <div class="kpi amber"><div class="kpi-v">${duplicates.length}</div><div class="kpi-l">중복 룰 (${exactDup} 완전)</div></div>
  <div class="kpi red"><div class="kpi-v">${syntaxErrors.length}</div><div class="kpi-l">문법 오류 (${critErr} Critical)</div></div>
  <div class="kpi green"><div class="kpi-v">${cleanL}</div><div class="kpi-l">이상 없음</div></div>
</div>
<div class="section">
  <h2>🔴 중복 룰 분석 (총 ${duplicates.length}건 — Built-in 기준)</h2>
  ${duplicates.length ? `<div style="overflow:auto"><table><thead><tr><th>#</th><th>심각도</th><th>Local SID</th><th>Local msg</th><th>중복 이유</th><th>Built-in SID</th><th>Built-in msg</th></tr></thead><tbody>${dupRows}</tbody></table></div>` : '<p style="color:#64748b">중복 룰 없음 ✅</p>'}
</div>
<div class="section">
  <h2>⚠️ 문법 오류 분석 (총 ${syntaxErrors.length}건)</h2>
  ${syntaxErrors.length ? `<div style="overflow:auto"><table><thead><tr><th>#</th><th>Line</th><th>심각도</th><th>룰 (요약)</th><th>오류 내용</th><th>수정 제안</th></tr></thead><tbody>${synRows}</tbody></table></div>` : '<p style="color:#64748b">문법 오류 없음 ✅</p>'}
</div>
<div class="footer">Snort Rules Analyzer — https://maxias13.github.io/snort-rule-converter-site/ — Not official Cisco information</div>
</div></body></html>`;
  }

  function runDualAnalysis() {
    const { builtinText, localText, builtinName, localName } = dualState;
    const statusTxt = document.getElementById('dualStatusTxt');
    if (statusTxt) statusTxt.textContent = '분석 중...';
    setTimeout(() => {
      const builtinRules = parseSnortRulesFull(builtinText);
      const localRules   = parseSnortRulesFull(localText);
      const duplicates   = analyzeDuplicates(builtinRules, localRules);
      const syntaxErrors = validateLocalRuleSyntax(localRules);
      dualState.builtinRules = builtinRules; dualState.localRules = localRules;
      dualState.duplicates = duplicates; dualState.syntaxErrors = syntaxErrors;

      document.getElementById('tbDuplicates').textContent = duplicates.length;
      document.getElementById('tbSyntax').textContent = syntaxErrors.length;

      const results = document.getElementById('dualResults');
      if (results) results.style.display = '';
      renderDualKpis(builtinRules, localRules, duplicates, syntaxErrors);
      renderDualCharts(builtinRules, localRules, duplicates, syntaxErrors);
      renderDuplicates(duplicates, 'all');
      renderSyntaxErrors(syntaxErrors, 'all');

      ['dualDownloadBtn','dualResetBtn'].forEach(id => { const e = document.getElementById(id); if(e) e.style.display = 'inline-flex'; });
      if (statusTxt) statusTxt.textContent = `완료 — Built-in ${builtinRules.length}개, Local ${localRules.length}개 분석`;
    }, 50);
  }

  function initDualMode() {
    const builtinBox   = document.getElementById('builtinDropBox');
    const localBox     = document.getElementById('localDropBox');
    const builtinInput = document.getElementById('builtinFileInput');
    const localInput   = document.getElementById('localFileInput');
    const analyzeBtn   = document.getElementById('dualAnalyzeBtn');
    const stdBtn       = document.getElementById('dashModeStdBtn');
    const dualBtn      = document.getElementById('dashModeDualBtn');
    if (!builtinBox || !localBox) return;

    const loadFile = (file, type) => {
      const reader = new FileReader();
      reader.onload = e => {
        const text = String(e.target.result || '');
        if (type === 'builtin') {
          dualState.builtinText = text; dualState.builtinName = file.name;
          builtinBox.classList.add('has-file');
          const st = document.getElementById('builtinStatus');
          if (st) { st.textContent = `✅ ${file.name} (${parseSnortRulesFull(text).length}개 룰)`; st.className = 'dual-box-status ready'; }
        } else {
          dualState.localText = text; dualState.localName = file.name;
          localBox.classList.add('has-file');
          const st = document.getElementById('localStatus');
          if (st) { st.textContent = `✅ ${file.name} (${parseSnortRulesFull(text).length}개 룰)`; st.className = 'dual-box-status ready'; }
        }
        if (dualState.builtinText && dualState.localText) {
          if (analyzeBtn) analyzeBtn.disabled = false;
          const st = document.getElementById('dualStatusTxt');
          if (st) st.textContent = '두 파일 준비 완료 — 분석 시작 버튼을 눌러주세요';
        }
      };
      reader.readAsText(file);
    };

    const setupBox = (box, input, type) => {
      box.addEventListener('click', () => input.click());
      input.addEventListener('change', e => { const f = e.target.files?.[0]; if(f) loadFile(f, type); });
      box.addEventListener('dragover',  e => { e.preventDefault(); box.classList.add('drag-over'); });
      box.addEventListener('dragleave', () => box.classList.remove('drag-over'));
      box.addEventListener('drop', e => { e.preventDefault(); box.classList.remove('drag-over'); const f = e.dataTransfer.files?.[0]; if(f) loadFile(f, type); });
    };
    setupBox(builtinBox, builtinInput, 'builtin');
    setupBox(localBox,   localInput,   'local');

    if (analyzeBtn) analyzeBtn.addEventListener('click', runDualAnalysis);

    const tabBar = document.getElementById('dualTabBar');
    if (tabBar) tabBar.addEventListener('click', e => {
      const btn = e.target.closest('.anal-tab-btn');
      if (!btn) return;
      const tab = btn.dataset.tab;
      tabBar.querySelectorAll('.anal-tab-btn').forEach(b => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.anal-tab-panel').forEach(p => p.classList.toggle('active', p.dataset.tab === tab));
    });

    const dlBtn = document.getElementById('dualDownloadBtn');
    if (dlBtn) dlBtn.addEventListener('click', () => {
      const html = generateDualReportHTML(dualState.builtinRules, dualState.localRules, dualState.duplicates, dualState.syntaxErrors, dualState.builtinName, dualState.localName);
      const a = document.createElement('a'); a.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
      a.download = `snort_analysis_${new Date().toISOString().slice(0,10)}.html`; a.click();
    });

    const resetDual = () => {
      dualState.builtinText=''; dualState.localText=''; dualState.builtinName=''; dualState.localName='';
      dualState.builtinRules=[]; dualState.localRules=[]; dualState.duplicates=[]; dualState.syntaxErrors=[];
      destroyDualCharts();
      [builtinBox, localBox].forEach(b => b.classList.remove('has-file'));
      ['builtinStatus','localStatus'].forEach(id => { const e = document.getElementById(id); if(e){e.textContent='파일 없음';e.className='dual-box-status';} });
      if (analyzeBtn) analyzeBtn.disabled = true;
      const st = document.getElementById('dualStatusTxt'); if(st) st.textContent = '두 파일을 모두 업로드 후 분석하세요';
      const res = document.getElementById('dualResults'); if(res) res.style.display = 'none';
      ['dualDownloadBtn','dualResetBtn'].forEach(id => { const e = document.getElementById(id); if(e) e.style.display='none'; });
      [builtinInput, localInput].forEach(i => { i.value=''; });
    };
    const resetBtn = document.getElementById('dualResetBtn');
    if (resetBtn) resetBtn.addEventListener('click', resetDual);

    const switchMode = mode => {
      const isDual = mode === 'dual';
      document.getElementById('dashStdSection').style.display  = isDual ? 'none' : '';
      document.getElementById('dashDualSection').style.display = isDual ? '' : 'none';
      document.getElementById('dashUploadLbl').style.display   = isDual ? 'none' : '';
      document.getElementById('dashDownloadBtn').style.display = isDual ? 'none' : (isDual ? 'none' : (document.getElementById('dashDownloadBtn').dataset.vis||'none'));
      document.getElementById('dashResetBtn').style.display    = isDual ? 'none' : (isDual ? 'none' : (document.getElementById('dashResetBtn').dataset.vis||'none'));
      stdBtn.classList.toggle('active',  !isDual);
      dualBtn.classList.toggle('active',  isDual);
    };
    if (stdBtn)  stdBtn.addEventListener('click',  () => switchMode('standard'));
    if (dualBtn) dualBtn.addEventListener('click',  () => switchMode('dual'));
  }

  document.addEventListener('DOMContentLoaded', () => { initDualMode(); });

})();
