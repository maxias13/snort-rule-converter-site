/* Add Object - FMC REST API client (login + list + bulk create) */
(function () {
  'use strict';

  async function fmcLogin(host, user, pass) {
    const url = 'https://' + host + '/api/fmc_platform/v1/auth/generatetoken';
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + btoa(user + ':' + pass) }
    });
    if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);
    const token = r.headers.get('X-auth-access-token');
    const domainUuid = r.headers.get('DOMAIN_UUID');
    if (!token || !domainUuid) {
      throw new Error('응답 헤더에 X-auth-access-token / DOMAIN_UUID 없음 (CORS 차단 가능성)');
    }
    return { token: token, domainUuid: domainUuid };
  }

  async function fmcListExisting(host, token, domainUuid, endpoint) {
    const names = new Set();
    let offset = 0;
    const limit = 1000;
    while (true) {
      const url = 'https://' + host + '/api/fmc_config/v1/domain/' + domainUuid +
        '/object/' + endpoint + '?expanded=false&offset=' + offset + '&limit=' + limit;
      const r = await fetch(url, {
        headers: { 'X-auth-access-token': token, 'Accept': 'application/json' }
      });
      if (!r.ok) throw new Error('조회 실패 ' + endpoint + ': HTTP ' + r.status);
      const data = await r.json();
      (data.items || []).forEach(function (it) { names.add(it.name); });
      const total = (data.paging && data.paging.count) || 0;
      if (offset + limit >= total) break;
      offset += limit;
    }
    return names;
  }

  async function fmcBulkCreate(host, token, domainUuid, endpoint, payloads) {
    if (!payloads.length) return { ok: [], fail: [] };
    const url = 'https://' + host + '/api/fmc_config/v1/domain/' + domainUuid +
      '/object/' + endpoint + '?bulk=true';
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: {
          'X-auth-access-token': token,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payloads)
      });
      if (r.status === 200 || r.status === 201) {
        return { ok: payloads, fail: [] };
      }
      const errText = (await r.text()).substring(0, 500);
      return {
        ok: [],
        fail: payloads.map(function (p) { return { payload: p, error: errText }; })
      };
    } catch (e) {
      return {
        ok: [],
        fail: payloads.map(function (p) { return { payload: p, error: String(e) }; })
      };
    }
  }

  window.AddObjectFmc = {
    login: fmcLogin,
    listExisting: fmcListExisting,
    bulkCreate: fmcBulkCreate
  };
})();
