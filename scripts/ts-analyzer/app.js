/* FPR Troubleshoot Analyzer - app.js
 * Streaming pipeline:
 *   File -> Blob.slice chunks -> pako.Inflate (chunked gunzip)
 *        -> StreamingTarScanner (captures only show_tech_output.txt)
 *        -> TextDecoder -> FPRParser.parseAll -> FPRRenderer.renderReport
 * Memory profile: ~1-4 MB peak (only the target file's bytes are retained).
 */

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const uploadZone   = $('upload-zone');
  const uploadZone2  = $('upload-zone-2');
  const fileInput    = $('file-input');
  const fileInput2   = $('file-input-2');
  const uploadZoneLabel = $('upload-zone-label');
  const fileNamePrimary = $('file-name-primary');
  const fileNameSecondary = $('file-name-secondary');
  const modePicker = $('ts-mode-picker');
  const progressBox  = $('progress');
  const progressMsg  = $('progress-msg');
  const progressFill = $('progress-fill');
  const errorBox     = $('error-box');
  const reportBox    = $('report');

  let currentMode = 'ftd';
  let isProcessing = false;
  const selectedFiles = { primary: null, secondary: null };

  bindUploadZone(uploadZone, fileInput, 'primary');
  if (uploadZone2 && fileInput2) bindUploadZone(uploadZone2, fileInput2, 'secondary');
  bindModePicker();
  applyMode('ftd', { resetFiles: false });

  function bindUploadZone(zone, input, role) {
    zone.addEventListener('click', (e) => {
      if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT') input.click();
    });
    zone.querySelector('button')?.addEventListener('click', () => input.click());
    input.addEventListener('change', (e) => {
      const f = e.target.files?.[0];
      if (f) onFileSelected(f, role);
    });
    ['dragenter', 'dragover'].forEach(ev =>
      zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('dragging'); })
    );
    ['dragleave', 'drop'].forEach(ev =>
      zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('dragging'); })
    );
    zone.addEventListener('drop', (e) => {
      const f = e.dataTransfer?.files?.[0];
      if (!f) return;
      onFileSelected(f, role);
    });
  }

  function bindModePicker() {
    if (!modePicker) return;
    const cards = modePicker.querySelectorAll('.ts-mode-card');
    cards.forEach((card) => {
      card.addEventListener('click', () => {
        const mode = card.dataset.mode;
        if (!mode || mode === currentMode) return;
        applyMode(mode, { resetFiles: true });
      });
    });
  }

  function setZoneFileName(role, file) {
    const isPrimary = role === 'primary';
    const zone = isPrimary ? uploadZone : uploadZone2;
    const fileNameEl = isPrimary ? fileNamePrimary : fileNameSecondary;
    if (!zone || !fileNameEl) return;
    if (file) {
      fileNameEl.textContent = file.name;
      fileNameEl.classList.remove('hidden');
      zone.classList.add('filled');
    } else {
      fileNameEl.textContent = '';
      fileNameEl.classList.add('hidden');
      zone.classList.remove('filled');
    }
  }

  function clearSelectedFiles() {
    selectedFiles.primary = null;
    selectedFiles.secondary = null;
    fileInput.value = '';
    if (fileInput2) fileInput2.value = '';
    setZoneFileName('primary', null);
    setZoneFileName('secondary', null);
    reportBox.classList.add('hidden');
    errorBox.classList.add('hidden');
  }

  function applyMode(mode, opts = {}) {
    const options = { resetFiles: true, ...opts };
    currentMode = mode;
    console.log('[mode]', currentMode);

    const cards = modePicker?.querySelectorAll('.ts-mode-card') || [];
    cards.forEach((card) => {
      const isSelected = card.dataset.mode === currentMode;
      card.classList.toggle('selected', isSelected);
      const radio = card.querySelector('input[type="radio"]');
      if (radio) radio.checked = isSelected;
    });

    if (currentMode === 'ftd') {
      uploadZoneLabel.textContent = 'FTD troubleshoot bundle';
      fileInput.accept = '.gz,.tgz,.tar.gz,.txt';
      uploadZone2?.classList.add('hidden');
    } else if (currentMode === 'fmc') {
      uploadZoneLabel.textContent = 'FMC troubleshoot bundle';
      fileInput.accept = '.gz,.tgz,.tar.gz';
      uploadZone2?.classList.add('hidden');
    } else {
      uploadZoneLabel.textContent = 'FTD troubleshoot bundle';
      fileInput.accept = '.gz,.tgz,.tar.gz,.txt';
      if (fileInput2) fileInput2.accept = '.gz,.tgz,.tar.gz';
      uploadZone2?.classList.remove('hidden');
    }

    if (options.resetFiles) clearSelectedFiles();
  }

  function onFileSelected(file, role) {
    selectedFiles[role] = file;
    setZoneFileName(role, file);
    processBundles();
  }

  function showProgress(msg, ratio) {
    progressBox.classList.remove('hidden');
    errorBox.classList.add('hidden');
    progressMsg.textContent = msg;
    if (typeof ratio === 'number') {
      progressFill.style.width = Math.max(0, Math.min(100, ratio * 100)).toFixed(1) + '%';
    }
  }
  function hideProgress() { progressBox.classList.add('hidden'); }
  function showError(msg) {
    hideProgress();
    errorBox.classList.remove('hidden');
    errorBox.textContent = 'Error: ' + msg;
    console.error(msg);
  }

  const decodeText = (bytes) => new TextDecoder('utf-8').decode(bytes);
  const decodeVersionDat = (bytes) => {
    const s = decodeText(bytes).trim();
    const m = s.match(/VERSION\s*=\s*(\S+)/i);
    return m ? m[1] : (s || null);
  };

  function makeFtdTargets(extras, onFoundText) {
    const cpuRrdTarget = {
      regex: /LocalCpu(\d+)Usage\.rrd$/,
      required: false,
      _multi: true,
      onFound: (name, bytes) => {
        const m = name.match(/LocalCpu(\d+)Usage\.rrd$/);
        if (!m) return;
        const core = parseInt(m[1], 10);
        extras.cpuRrds[core] = bytes.buffer.slice(
          bytes.byteOffset, bytes.byteOffset + bytes.byteLength
        );
      }
    };

    return [
      {
        regex: /show_tech_output\.txt$|show.tech.*\.txt$/i,
        required: true,
        onFound: (name, bytes) => {
          console.log(`[scanner] captured ${name} (${bytes.length} bytes)`);
          onFoundText({ name, text: decodeText(bytes) });
        }
      },
      { regex: /iprep_download\/IPRVersion\.dat$/, required: false, onFound: (_n, b) => { extras.iprep = decodeVersionDat(b); } },
      { regex: /sidns_download\/IPRVersion\.dat$/, required: false, onFound: (_n, b) => { extras.sidns = decodeVersionDat(b); } },
      { regex: /siurl_download\/IPRVersion\.dat$/, required: false, onFound: (_n, b) => { extras.siurl = decodeVersionDat(b); } },
      { regex: /sfcli\.pl show summary\.output$/, required: false, onFound: (_n, b) => { extras.showSummary = decodeText(b); } },
      { regex: /var\/sf\/geodb\/ipv4_country_code_map$/, required: false, _mtimeOnly: true, onFound: (_n, _b, mtime) => { extras.geodbMtime = mtime; } },
      cpuRrdTarget,
    ];
  }

  function makeFmcTargets(extras) {
    extras.fmc = extras.fmc || {
      sfVersion: null,
      sruVersions: null,
      seuVersions: null,
      vdbConf: null,
      sruConf: null,
      hostname: null,
      sftunnel: null,
      geodbMtime: null,
    };
    const fmc = extras.fmc;

    // Keep scanning after sentinel match so we can opportunistically collect
    // all optional FMC files in one pass.
    const keepScanningTarget = { regex: /a^/, required: false, _multi: true, onFound: () => {} };

    return [
      { regex: /dir-archives\/etc\/sf\/sf-version$/, required: true, onFound: (_n, b) => { fmc.sfVersion = decodeText(b).trim(); } },
      { regex: /dir-archives\/etc\/sf\/sru_versions\.conf$/, required: false, onFound: (_n, b) => { fmc.sruVersions = decodeText(b); } },
      { regex: /dir-archives\/etc\/sf\/seu_versions\.conf$/, required: false, onFound: (_n, b) => { fmc.seuVersions = decodeText(b); } },
      { regex: /dir-archives\/etc\/sf\/\.versiondb\/vdb\.conf$/, required: false, onFound: (_n, b) => { fmc.vdbConf = decodeText(b); } },
      { regex: /dir-archives\/etc\/sf\/\.versiondb\/sru\.conf$/, required: false, onFound: (_n, b) => { fmc.sruConf = decodeText(b); } },
      { regex: /dir-archives\/etc\/hostname$/, required: false, onFound: (_n, b) => { fmc.hostname = decodeText(b).trim(); } },
      { regex: /dir-archives\/etc\/sf\/sftunnel\.conf$/, required: false, onFound: (_n, b) => { fmc.sftunnel = decodeText(b); } },
      { regex: /var\/sf\/geodb\/ipv4_country_code_map$/, required: false, _mtimeOnly: true, onFound: (_n, _b, mtime) => { fmc.geodbMtime = mtime; } },
      keepScanningTarget,
    ];
  }

  function resolveBundleType(role) {
    if (currentMode === 'both') return role === 'secondary' ? 'fmc' : 'ftd';
    return currentMode;
  }

  /* USTAR / GNU tar header layout used below:
   *   0..99    name (NUL-terminated, truncated if > 100 chars)
   *   124..135 size (octal ASCII, NUL/space terminated)
   *   156      typeflag ('0'/NUL = file, 'L' = GNU long name -- next block's data IS the real name)
   *   345..499 prefix (USTAR long-path prefix prepended to name)
   * Long-path handling: a typeflag 'L' header is followed by a data block containing
   * the next entry's full name; we capture it and apply it when the *real* header arrives.
   */
  /**
   * Multi-target streaming tar scanner.
   * targets: Array<{ regex: RegExp, required?: boolean, onFound: (name, bytes) => void }>.
   * Scanner runs until ALL `required` targets are captured (or stream ends).
   * Each target fires its onFound at most once. Non-required targets are
   * opportunistic — captured if seen, ignored otherwise.
   */
  function makeTarScanner(targets, onAllRequiredFound) {
    if (!Array.isArray(targets)) {
      const cb = onAllRequiredFound;
      targets = [{ regex: targets, required: true, onFound: cb }];
      onAllRequiredFound = null;
    }
    targets.forEach(t => { t._fired = false; t.required = t.required !== false; });
    // Multi-match targets keep capturing across the whole stream, so we must
    // NOT short-circuit when only required (single-shot) targets fire.
    const hasMulti = targets.some(t => t._multi);
    const allRequiredFired = () => !hasMulti && targets.every(t => !t.required || t._fired);

    let buf = new Uint8Array(0);
    let mode = 'header';
    let remaining = 0;
    let pad = 0;
    let captured = [];
    let capturedName = '';
    let activeTarget = null;
    let pendingLongName = '';
    let longNameChunks = [];
    let done = false;

    const readOctal = (u8, off, len) => {
      let s = '';
      for (let i = 0; i < len; i++) {
        const c = u8[off + i];
        if (c === 0 || c === 0x20) break;
        s += String.fromCharCode(c);
      }
      return s ? parseInt(s, 8) : 0;
    };
    const readStr = (u8, off, len) => {
      let end = off;
      while (end < off + len && u8[end] !== 0) end++;
      return new TextDecoder('utf-8').decode(u8.subarray(off, end));
    };

    function append(chunk) {
      if (done) return;
      const merged = new Uint8Array(buf.length + chunk.length);
      merged.set(buf, 0);
      merged.set(chunk, buf.length);
      buf = merged;

      let i = 0;
      while (true) {
        if (mode === 'header') {
          if (buf.length - i < 512) break;
          const hdr = buf.subarray(i, i + 512);
          let allZero = true;
          for (let k = 0; k < 512; k++) if (hdr[k] !== 0) { allZero = false; break; }
          if (allZero) { i += 512; continue; }

          const name     = readStr(hdr, 0, 100);
          const size     = readOctal(hdr, 124, 12);
          const mtime    = readOctal(hdr, 136, 12); // POSIX seconds since epoch
          const typeflag = String.fromCharCode(hdr[156] || 0x30);
          const prefix   = readStr(hdr, 345, 155);
          const blocks = Math.ceil(size / 512);
          pad = blocks * 512 - size;
          remaining = size;
          i += 512;

          if (typeflag === 'L') {
            mode = 'longname';
            longNameChunks = [];
            continue;
          }

          const fullName = pendingLongName || (prefix ? (prefix + '/' + name) : name);
          pendingLongName = '';

          activeTarget = null;
          if (size > 0) {
            for (const t of targets) {
              if (!t._fired && t.regex.test(fullName)) { activeTarget = t; break; }
            }
          }
          if (activeTarget) {
            // _mtimeOnly: fire immediately with header mtime, skip body to save memory.
            if (activeTarget._mtimeOnly) {
              activeTarget._fired = true;
              try { activeTarget.onFound(fullName, null, mtime); } catch (e) { console.error(e); }
              if (activeTarget._multi) activeTarget._fired = false;
              activeTarget = null;
              mode = 'skip';
            } else {
              mode = 'capture';
              capturedName = fullName;
              captured = [];
              activeTarget._capturedMtime = mtime;
            }
          } else {
            mode = 'skip';
          }
          continue;
        }

        if (mode === 'longname') {
          if (remaining > 0) {
            const take = Math.min(buf.length - i, remaining);
            if (take === 0) break;
            longNameChunks.push(buf.slice(i, i + take));
            i += take;
            remaining -= take;
            if (remaining > 0) break;
          }
          if (pad > 0) {
            const take = Math.min(buf.length - i, pad);
            if (take === 0) break;
            i += take;
            pad -= take;
            if (pad > 0) break;
          }
          let total = 0;
          for (const c of longNameChunks) total += c.length;
          const merged2 = new Uint8Array(total);
          let off2 = 0;
          for (const c of longNameChunks) { merged2.set(c, off2); off2 += c.length; }
          let end2 = merged2.length;
          while (end2 > 0 && merged2[end2 - 1] === 0) end2--;
          pendingLongName = new TextDecoder('utf-8').decode(merged2.subarray(0, end2));
          longNameChunks = [];
          mode = 'header';
          continue;
        }

        if (mode === 'capture' || mode === 'skip') {
          const avail = buf.length - i;
          if (remaining > 0) {
            const take = Math.min(avail, remaining);
            if (take === 0) break;
            if (mode === 'capture') captured.push(buf.slice(i, i + take));
            i += take;
            remaining -= take;
            if (remaining > 0) break;
          }
          if (pad > 0) {
            const take = Math.min(buf.length - i, pad);
            if (take === 0) break;
            i += take;
            pad -= take;
            if (pad > 0) break;
          }
          if (mode === 'capture') {
            let total = 0;
            for (const c of captured) total += c.length;
            const out = new Uint8Array(total);
            let off = 0;
            for (const c of captured) { out.set(c, off); off += c.length; }
            if (activeTarget) {
              activeTarget._fired = true;
              try { activeTarget.onFound(capturedName, out); } catch (e) { console.error(e); }
              // Multi-match targets (e.g. 128 LocalCpuN.rrd) re-arm after each capture.
              if (activeTarget._multi) activeTarget._fired = false;
            }
            activeTarget = null;
            captured = [];
            if (allRequiredFired()) {
              done = true;
              mode = 'done';
              buf = new Uint8Array(0);
              try { onAllRequiredFound && onAllRequiredFound(); } catch (e) { console.error(e); }
              return;
            }
            mode = 'header';
            continue;
          }
          mode = 'header';
          continue;
        }
        if (mode === 'done') return;
      }
      buf = buf.slice(i);
    }

    return { append, isDone: () => done };
  }

  async function scanBundle(file, role) {
    const bundleType = resolveBundleType(role);
    try {
      showProgress(`Loading file: ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`, 0);

      const head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
      const isGzip = head[0] === 0x1f && head[1] === 0x8b;
      const isPlainText = !isGzip && /show.?tech|Cisco Adaptive Security|Hardware:/i.test(
        new TextDecoder('utf-8', { fatal: false }).decode(head)
      );
      if (bundleType === 'ftd' && isPlainText) {
        showProgress('Processing show_tech_output.txt directly...', 0.5);
        const text = await file.text();
        return {
          text,
          sourceName: file.name,
          extras: { iprep: null, sidns: null, siurl: null, cpuRrds: {}, showSummary: null, geodbMtime: null }
        };
      }
      if (bundleType === 'fmc' && isPlainText) {
        throw new Error('FMC mode requires a troubleshoot bundle archive (.tar.gz/.tgz/.gz), not plain text.');
      }

      let foundText = null;
      const extras = bundleType === 'ftd'
        ? { iprep: null, sidns: null, siurl: null, cpuRrds: {}, showSummary: null, geodbMtime: null }
        : { fmc: { sfVersion: null, sruVersions: null, seuVersions: null, vdbConf: null, sruConf: null, hostname: null, sftunnel: null, geodbMtime: null } };

      const targets = bundleType === 'ftd'
        ? makeFtdTargets(extras, (v) => { foundText = v; })
        : makeFmcTargets(extras);
      const scanner = makeTarScanner(targets);

      let inflator = null;
      if (isGzip) {
        if (typeof pako === 'undefined') throw new Error('Failed to load pako library');
        inflator = new pako.Inflate({ chunkSize: 1024 * 1024 });
        inflator.onData = (chunk) => { if (!scanner.isDone()) scanner.append(chunk); };
      }

      const CHUNK = 8 * 1024 * 1024;
      let offset = 0;
      const total = file.size;
      while (offset < total && !scanner.isDone()) {
        const end = Math.min(offset + CHUNK, total);
        const buf = new Uint8Array(await file.slice(offset, end).arrayBuffer());
        if (isGzip) {
          inflator.push(buf, end >= total);
          if (inflator.err) throw new Error('gunzip failed: ' + inflator.msg);
        } else {
          scanner.append(buf);
        }
        offset = end;
        const ratio = offset / total;
        showProgress(
          `Scanning... ${(offset / 1024 / 1024).toFixed(0)} / ${(total / 1024 / 1024).toFixed(0)} MB` +
          (foundText ? ` — found: ${foundText.name.split('/').pop()}` : ''),
          ratio * 0.85
        );
        await new Promise(r => setTimeout(r, 0));
        if (scanner.isDone()) break;
      }

      if (bundleType === 'ftd' && !foundText) {
        throw new Error('show_tech_output.txt not found in FTD bundle.');
      }
      if (bundleType === 'fmc' && !extras.fmc?.sfVersion) {
        throw new Error('dir-archives/etc/sf/sf-version not found in FMC bundle.');
      }

      return {
        text: foundText ? foundText.text : '',
        sourceName: foundText ? foundText.name : file.name,
        extras,
      };
    } catch (e) {
      throw e;
    }
  }

  async function processBundles() {
    if (isProcessing) return;

    try {
      reportBox.classList.add('hidden');
      errorBox.classList.add('hidden');

      if (currentMode === 'both') {
        if (!selectedFiles.primary || !selectedFiles.secondary) return;
        isProcessing = true;

        const ftdResult = await scanBundle(selectedFiles.primary, 'primary');
        const fmcResult = await scanBundle(selectedFiles.secondary, 'secondary');

        const mergedExtras = {
          ...(ftdResult.extras || {}),
          fmc: fmcResult.extras?.fmc || null,
          bundleMode: 'both',
        };

        await runParseAndRender(
          ftdResult.text,
          `${ftdResult.sourceName} + ${fmcResult.sourceName}`,
          mergedExtras
        );
        return;
      }

      if (!selectedFiles.primary) return;
      isProcessing = true;

      const result = await scanBundle(selectedFiles.primary, 'primary');
      const extras = { ...(result.extras || {}), bundleMode: currentMode };
      await runParseAndRender(result.text, result.sourceName, extras);
    } catch (e) {
      showError(e.message || String(e));
    } finally {
      isProcessing = false;
    }
  }

  async function runParseAndRender(text, sourceName, extras) {
    showProgress(`Parsing... (${(text.length / 1024).toFixed(0)} KB)`, 0.9);
    await new Promise(r => setTimeout(r, 0));
    const data = window.FPRParser.parseAll(text, extras || {});
    data._sourceFile = sourceName;
    if (window.FPRParser.parseSoftwareVersions) {
      data.versions = window.FPRParser.parseSoftwareVersions(text, extras || {});
    }

    showProgress('Rendering report...', 0.97);
    await new Promise(r => setTimeout(r, 0));
    window.FPRRenderer.renderReport(data);
    window.__tsAnalyzerLastData = data;

    hideProgress();
    reportBox.classList.remove('hidden');
    reportBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // -- HTML Download --------------------------------------------------------
  // Snapshots #report into a self-contained HTML file: inlines current
  // page CSS, replaces every Chart.js <canvas> with a PNG <img> so charts
  // survive without re-running JS, and triggers a Blob download.
  document.getElementById('ts-download-html')?.addEventListener('click', () => {
    const reportNode = document.getElementById('report');
    if (!reportNode || reportNode.classList.contains('hidden')) return;

    const clone = reportNode.cloneNode(true);
    clone.querySelector('.ts-toolbar')?.remove();
    const liveCanvases = reportNode.querySelectorAll('canvas');
    const cloneCanvases = clone.querySelectorAll('canvas');
    cloneCanvases.forEach((c, i) => {
      const live = liveCanvases[i];
      if (!live) return;
      try {
        const img = document.createElement('img');
        img.src = live.toDataURL('image/png');
        img.style.cssText = 'max-width:100%;height:auto;display:block;';
        img.width = live.width;
        img.height = live.height;
        c.replaceWith(img);
      } catch { /* tainted canvas — leave placeholder */ }
    });

    const styleParts = [];
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules) styleParts.push(rule.cssText);
      } catch { /* CORS-restricted sheet — skip */ }
    }
    const css = styleParts.join('\n');

    // Filename: <hostname>_<model>_health_<YYYYMMDD_HHMMSS>.html
    const v = window.__tsAnalyzerLastData?.version || {};
    const slug = (s) => String(s || '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'device';
    const now = new Date();
    const ts = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}_${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}${String(now.getSeconds()).padStart(2,'0')}`;
    const filename = `${slug(v.hostname)}_${slug(v.model)}_health_${ts}.html`;

    const title = `FPR Health Report — ${v.hostname || 'unknown'} (${v.model || 'unknown'})`;
    const html =
`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${title.replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</title>
<style>${css}
body{margin:0;padding:24px;background:#0b1220;color:#e6ebf5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.ts-report{display:block;}
img{max-width:100%;}
@media print{body{background:#fff;color:#000;}}
</style>
</head>
<body>
<div id="tsAnalyzerView"><div class="ts-report">${clone.innerHTML}</div></div>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
