/* Add Object - UI controller. Wires file input + preview + FMC import flow */
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

  async function runFmcImport() {
    const host = $('aoFmcHost').value.trim();
    const user = $('aoFmcUser').value.trim();
    const pass = $('aoFmcPass').value;
    if (!host || !user || !pass) {
      alert('Please enter FMC IP, username, and password.');
      return;
    }
    $('aoStep8').style.display = 'block';
    $('aoProgress').innerHTML = '';

    log('Connecting to FMC: https://' + host);
    let token, domainUuid;
    try {
      const auth = await window.AddObjectFmc.login(host, user, pass);
      token = auth.token;
      domainUuid = auth.domainUuid;
      log('✓ Login successful (Domain UUID: ' + domainUuid + ')', 'ok');
    } catch (e) {
      log('✗ FMC login failed: ' + e.message, 'err');
      log('Troubleshooting checklist:', 'warn');
      log('  1) Open https://' + host + '/api/api-explorer/ in a NEW browser tab.', 'warn');
      log('     If you see a cert warning, click "Advanced → Proceed". This pre-trusts the cert.', 'warn');
      log('  2) Confirm REST API is enabled on FMC:', 'warn');
      log('     System > Configuration > REST API Preferences', 'warn');
      log('  3) Confirm CORS is allowed on FMC for this origin (' + window.location.origin + ').', 'warn');
      log('     FMC must return Access-Control-Allow-Origin AND', 'warn');
      log('     Access-Control-Expose-Headers: X-auth-access-token, DOMAIN_UUID', 'warn');
      log('  4) If serving this page from file://, browser may block fetch — host via HTTP(S) instead.', 'warn');
      return;
    }

    log('Fetching existing objects...');
    let existingHosts, existingNetworks, existingPorts;
    try {
      existingHosts = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'hosts');
      existingNetworks = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'networks');
      existingPorts = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'protocolportobjects');
      log('  Existing: hosts=' + existingHosts.size + ', networks=' + existingNetworks.size + ', ports=' + existingPorts.size, 'ok');
    } catch (e) {
      log('✗ Failed to list existing objects: ' + e.message, 'err');
      return;
    }

    const hostsToCreate = currentPayloads.hosts.filter(function (p) { return !existingHosts.has(p.name); });
    const netsToCreate = currentPayloads.networks.filter(function (p) { return !existingNetworks.has(p.name); });
    const portsToCreate = currentPayloads.ports.filter(function (p) { return !existingPorts.has(p.name); });
    const skippedExisting = [];
    currentPayloads.hosts.forEach(function (p) { if (existingHosts.has(p.name)) skippedExisting.push(p.name); });
    currentPayloads.networks.forEach(function (p) { if (existingNetworks.has(p.name)) skippedExisting.push(p.name); });
    currentPayloads.ports.forEach(function (p) { if (existingPorts.has(p.name)) skippedExisting.push(p.name); });
    if (skippedExisting.length) {
      log('Already exists — SKIPPED: ' + skippedExisting.join(', '), 'warn');
    }

    log('Creating: hosts=' + hostsToCreate.length + ', networks=' + netsToCreate.length + ', ports=' + portsToCreate.length);

    const hostResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'hosts', hostsToCreate);
    const netResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'networks', netsToCreate);
    const portResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'protocolportobjects', portsToCreate);

    log('--- Final results ---', 'ok');
    log('Hosts:    success=' + hostResult.ok.length + ', failed=' + hostResult.fail.length,
        hostResult.fail.length ? 'err' : 'ok');
    log('Networks: success=' + netResult.ok.length + ', failed=' + netResult.fail.length,
        netResult.fail.length ? 'err' : 'ok');
    log('Ports:    success=' + portResult.ok.length + ', failed=' + portResult.fail.length,
        portResult.fail.length ? 'err' : 'ok');

    const allFailures = hostResult.fail.concat(netResult.fail).concat(portResult.fail);
    if (allFailures.length) {
      log('--- Failure details ---', 'err');
      allFailures.forEach(function (f) {
        log('  ' + f.payload.name + ': ' + f.error, 'err');
      });
    }
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
      $('aoStep5').style.display = 'none';
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
    $('aoConfirmBtn').addEventListener('click', function () {
      $('aoStep5').style.display = 'block';
    });
    $('aoLoginBtn').addEventListener('click', runFmcImport);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
