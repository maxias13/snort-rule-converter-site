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
      '<div style="margin-bottom:8px;">파싱된 룰: <strong>' + ruleCount + '개</strong></div>' +
      '<div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">' +
        '<div><strong>Network 객체 후보 (' + ipCount + '개)</strong>' +
          '<table style="width:100%; margin-top:6px; border-collapse:collapse;">' +
            '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;">변수</th><th>src</th><th>dst</th></tr></thead>' +
            '<tbody>' + (makeRows(userIp) || '<tr><td colspan="3" style="color:var(--muted);">없음</td></tr>') + '</tbody>' +
          '</table></div>' +
        '<div><strong>Port 객체 후보 (' + portCount + '개)</strong>' +
          '<table style="width:100%; margin-top:6px; border-collapse:collapse;">' +
            '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;">변수</th><th>src</th><th>dst</th></tr></thead>' +
            '<tbody>' + (makeRows(userPort) || '<tr><td colspan="3" style="color:var(--muted);">없음</td></tr>') + '</tbody>' +
          '</table></div>' +
      '</div>';

    if (skipped.length) {
      html += '<div style="margin-top:10px; padding:8px; background:rgba(0,188,235,0.1); border-radius:4px; font-size:0.9em;">' +
        '<strong>FMC 기본 변수로 자동 제외:</strong> ' +
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
          '<th style="text-align:left; padding:6px;">Name (그대로 유지)</th>' +
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
      alert('FMC IP, 사용자, 비밀번호를 모두 입력하세요.');
      return;
    }
    $('aoStep8').style.display = 'block';
    $('aoProgress').innerHTML = '';

    log('FMC 연결 시도: https://' + host);
    let token, domainUuid;
    try {
      const auth = await window.AddObjectFmc.login(host, user, pass);
      token = auth.token;
      domainUuid = auth.domainUuid;
      log('✓ 로그인 성공 (Domain UUID: ' + domainUuid + ')', 'ok');
    } catch (e) {
      log('✗ FMC 로그인 실패: ' + e.message, 'err');
      log('확인 사항:', 'warn');
      log('  1) FMC cert를 브라우저에서 사전 신뢰했나요? (https://' + host + ' 직접 방문)', 'warn');
      log('  2) FMC REST API 활성화 여부?', 'warn');
      log('  3) FMC에 CORS 헤더 설정 필요할 수 있음', 'warn');
      return;
    }

    log('기존 객체 조회 중...');
    let existingHosts, existingNetworks, existingPorts;
    try {
      existingHosts = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'hosts');
      existingNetworks = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'networks');
      existingPorts = await window.AddObjectFmc.listExisting(host, token, domainUuid, 'protocolportobjects');
      log('  기존: hosts=' + existingHosts.size + ', networks=' + existingNetworks.size + ', ports=' + existingPorts.size, 'ok');
    } catch (e) {
      log('✗ 기존 객체 조회 실패: ' + e.message, 'err');
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
      log('이미 존재하여 SKIP: ' + skippedExisting.join(', '), 'warn');
    }

    log('생성 시도: hosts=' + hostsToCreate.length + ', networks=' + netsToCreate.length + ', ports=' + portsToCreate.length);

    const hostResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'hosts', hostsToCreate);
    const netResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'networks', netsToCreate);
    const portResult = await window.AddObjectFmc.bulkCreate(host, token, domainUuid, 'protocolportobjects', portsToCreate);

    log('--- 최종 결과 ---', 'ok');
    log('Hosts:    성공=' + hostResult.ok.length + ', 실패=' + hostResult.fail.length,
        hostResult.fail.length ? 'err' : 'ok');
    log('Networks: 성공=' + netResult.ok.length + ', 실패=' + netResult.fail.length,
        netResult.fail.length ? 'err' : 'ok');
    log('Ports:    성공=' + portResult.ok.length + ', 실패=' + portResult.fail.length,
        portResult.fail.length ? 'err' : 'ok');

    const allFailures = hostResult.fail.concat(netResult.fail).concat(portResult.fail);
    if (allFailures.length) {
      log('--- 실패 상세 ---', 'err');
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
    reader.onerror = function () { alert('파일 읽기 실패'); };
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
