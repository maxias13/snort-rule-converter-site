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
  const fileInput    = $('file-input');
  const progressBox  = $('progress');
  const progressMsg  = $('progress-msg');
  const progressFill = $('progress-fill');
  const errorBox     = $('error-box');
  const reportBox    = $('report');

  uploadZone.addEventListener('click', (e) => {
    if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT') fileInput.click();
  });
  uploadZone.querySelector('button')?.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (f) handleFile(f);
  });
  ['dragenter', 'dragover'].forEach(ev =>
    uploadZone.addEventListener(ev, (e) => { e.preventDefault(); uploadZone.classList.add('dragging'); })
  );
  ['dragleave', 'drop'].forEach(ev =>
    uploadZone.addEventListener(ev, (e) => { e.preventDefault(); uploadZone.classList.remove('dragging'); })
  );
  uploadZone.addEventListener('drop', (e) => {
    const f = e.dataTransfer?.files?.[0];
    if (f) handleFile(f);
  });

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

  /* USTAR / GNU tar header layout used below:
   *   0..99    name (NUL-terminated, truncated if > 100 chars)
   *   124..135 size (octal ASCII, NUL/space terminated)
   *   156      typeflag ('0'/NUL = file, 'L' = GNU long name -- next block's data IS the real name)
   *   345..499 prefix (USTAR long-path prefix prepended to name)
   * Long-path handling: a typeflag 'L' header is followed by a data block containing
   * the next entry's full name; we capture it and apply it when the *real* header arrives.
   */
  function makeTarScanner(targetSuffixRegex, onFound) {
    let buf = new Uint8Array(0);
    let mode = 'header';
    let remaining = 0;
    let pad = 0;
    let captured = [];
    let capturedName = '';
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

          if (size > 0 && targetSuffixRegex.test(fullName)) {
            mode = 'capture';
            capturedName = fullName;
            captured = [];
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
            done = true;
            mode = 'done';
            buf = new Uint8Array(0);
            try { onFound(capturedName, out); } catch (e) { console.error(e); }
            return;
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

  async function handleFile(file) {
    try {
      reportBox.classList.add('hidden');
      errorBox.classList.add('hidden');
      showProgress(`Loading file: ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`, 0);

      const head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
      const isGzip = head[0] === 0x1f && head[1] === 0x8b;
      const isPlainText = !isGzip && /show.?tech|Cisco Adaptive Security|Hardware:/i.test(
        new TextDecoder('utf-8', { fatal: false }).decode(head)
      );
      if (isPlainText) {
        showProgress('Processing show_tech_output.txt directly...', 0.5);
        const text = await file.text();
        await runParseAndRender(text, file.name);
        return;
      }

      const targetRe = /show_tech_output\.txt$|show.tech.*\.txt$/i;
      let foundText = null;
      const scanner = makeTarScanner(targetRe, (name, bytes) => {
        console.log(`[scanner] captured ${name} (${bytes.length} bytes)`);
        foundText = { name, text: new TextDecoder('utf-8').decode(bytes) };
      });

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

      if (!foundText) throw new Error('show_tech_output.txt not found in bundle.');
      await runParseAndRender(foundText.text, foundText.name);
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  async function runParseAndRender(text, sourceName) {
    showProgress(`Parsing... (${(text.length / 1024).toFixed(0)} KB)`, 0.9);
    await new Promise(r => setTimeout(r, 0));
    const data = window.FPRParser.parseAll(text);
    data._sourceFile = sourceName;

    showProgress('Rendering report...', 0.97);
    await new Promise(r => setTimeout(r, 0));
    window.FPRRenderer.renderReport(data);

    hideProgress();
    reportBox.classList.remove('hidden');
    reportBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
})();
