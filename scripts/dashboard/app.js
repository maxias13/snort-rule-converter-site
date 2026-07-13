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

  function downloadHtml() {
    if (!state.mode) return;
    const html = state.mode === 'table' ? buildTableHtml() : buildSnortHtml();
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

})();
