/* Variable Set - UI controller. Wires file input + preview + FMC import flow */
(function () {
  'use strict';

  let parsedUserIpVars = {};
  let parsedUserPortVars = {};
  let currentPayloads = { hosts: [], networks: [], ports: [] };

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function $(id) { return document.getElementById(id); }

  function renderExtractResult(ipVars, portVars, ruleCount) {
    const userIp = window.AddObjectParser.filterUserVars(ipVars);
    const userPort = window.AddObjectParser.filterUserVars(portVars);
    const skipped = window.AddObjectParser.getSkippedDefaults(ipVars, portVars);
    parsedUserIpVars = userIp;
    parsedUserPortVars = userPort;

    function makeRows(obj) {
      return Object.keys(obj).sort().map(function (n) {
        const u = obj[n];
        return '<tr><td>$' + escapeHtml(n) + '</td><td>' + u.src + '</td><td>' + u.dst + '</td></tr>';
      }).join('');
    }

    const ipCount = Object.keys(userIp).length;
    const portCount = Object.keys(userPort).length;

    let html =
      '<div style="margin-bottom:8px;">Parsed rules: <strong>' + ruleCount + '</strong></div>' +
      '<div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">' +
        '<div><strong>Network object candidates (' + ipCount + ')</strong>' +
          '<table style="width:100%; margin-top:6px; border-collapse:collapse;">' +
            '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;">Variable</th><th>src</th><th>dst</th></tr></thead>' +
            '<tbody>' + (makeRows(userIp) || '<tr><td colspan="3" style="color:var(--muted);">None</td></tr>') + '</tbody>' +
          '</table></div>' +
        '<div><strong>Port object candidates (' + portCount + ')</strong>' +
          '<table style="width:100%; margin-top:6px; border-collapse:collapse;">' +
            '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;">Variable</th><th>src</th><th>dst</th></tr></thead>' +
            '<tbody>' + (makeRows(userPort) || '<tr><td colspan="3" style="color:var(--muted);">None</td></tr>') + '</tbody>' +
          '</table></div>' +
      '</div>';

    if (skipped.length) {
      html += '<div style="margin-top:10px; padding:8px; background:rgba(0,188,235,0.1); border-radius:4px; font-size:0.9em;">' +
        '<strong>Auto-excluded (FMC predefined variables):</strong> ' +
        skipped.map(function (s) { return '$' + escapeHtml(s); }).join(', ') +
      '</div>';
    }
    $('aoExtractResult').innerHTML = html;
    return ipCount + portCount;
  }

  function generateAndPreview() {
    currentPayloads = window.AddObjectGenerator.generateAllPayloads(parsedUserIpVars, parsedUserPortVars);
    const all = currentPayloads.networks.concat(currentPayloads.hosts).concat(currentPayloads.ports);
    const rows = all.map(function (p) {
      const val = p.type === 'ProtocolPortObject' ? (p.protocol + ' ' + p.port) : p.value;
      const tlabel = p.type === 'ProtocolPortObject' ? 'Port' : p.type;
      return '<tr><td>' + escapeHtml(tlabel) + '</td><td><code>' + escapeHtml(p.name) +
        '</code></td><td><code>' + escapeHtml(val) + '</code></td></tr>';
    }).join('');
    $('aoPreviewTable').innerHTML =
      '<table style="width:100%; border-collapse:collapse;">' +
        '<thead><tr style="border-bottom:1px solid var(--border);">' +
          '<th style="text-align:left; padding:6px;">Type</th>' +
          '<th style="text-align:left; padding:6px;">Name (preserved)</th>' +
          '<th style="text-align:left; padding:6px;">Random Value</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function log(msg, level) {
    const colors = { info: '#9aa', ok: '#7ec97e', err: '#f06', warn: '#ffaa00' };
    const el = $('aoProgress');
    const ts = new Date().toTimeString().slice(0, 8);
    el.innerHTML += '<div style="color:' + (colors[level || 'info']) + ';">[' + ts + '] ' + escapeHtml(msg) + '</div>';
    el.scrollTop = el.scrollHeight;
  }

  async function generateScript() {
    $('aoStep8').style.display = 'block';
    $('aoProgress').innerHTML = '';

    const total = currentPayloads.hosts.length + currentPayloads.networks.length + currentPayloads.ports.length;
    log('Generating self-contained Python script...');
    log('  Objects: ' + total + ' (' +
        currentPayloads.hosts.length + ' hosts, ' +
        currentPayloads.networks.length + ' networks, ' +
        currentPayloads.ports.length + ' ports)');

    const pyCode = window.AddObjectScriptGen.buildPythonScript(currentPayloads);
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = 'fmc_import_' + ts + '.py';
    window.AddObjectScriptGen.downloadScript(pyCode, filename);

    log('✓ Downloaded: ' + filename, 'ok');
    log('', 'info');
    log('Next steps:', 'ok');
    log('  1) Copy the file to a machine with network access to your FMC', 'info');
    log('  2) Install dependency:  pip install requests', 'info');
    log('  3) Run the script:      python3 ' + filename, 'info');
    log('  4) Enter FMC IP, username, and password when prompted', 'info');
    log('', 'info');
    log('The script preserves all object names and bulk-creates them via', 'info');
    log('FMC REST API. Already-existing objects are skipped automatically.', 'info');
  }

  function handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (ev) {
      const text = ev.target.result;
      const parsed = window.AddObjectParser.parseSnortVariables(text);
      const total = renderExtractResult(parsed.ipVars, parsed.portVars, parsed.ruleCount);
      $('aoStep3').style.display = 'block';
      if (total > 0) {
        generateAndPreview();
        $('aoStep4').style.display = 'block';
      } else {
        $('aoStep4').style.display = 'none';
      }
      $('aoStep8').style.display = 'none';
    };
    reader.onerror = function () { alert('Failed to read file'); };
    reader.readAsText(file);
  }

  function init() {
    const fileInput = $('aoRulesFile');
    if (!fileInput) return;
    fileInput.addEventListener('change', handleFileSelect);
    $('aoRegenBtn').addEventListener('click', generateAndPreview);
    $('aoConfirmBtn').addEventListener('click', generateScript);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
