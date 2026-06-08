/* Add Object - FMC REST API client (login + list + bulk create) */
(function () {
  'use strict';

  async function fmcLogin(host, user, pass) {
    const url = 'https://' + host + '/api/fmc_platform/v1/auth/generatetoken';
    let r;
    try {
      r = await fetch(url, {
        method: 'POST',
        headers: { 'Authorization': 'Basic ' + btoa(user + ':' + pass) }
      });
    } catch (netErr) {
      /* TypeError "NetworkError when attempting to fetch resource" is thrown when:
         1) self-signed cert not trusted by browser
         2) CORS preflight blocked (no Access-Control-Allow-Origin header from FMC)
         3) FMC unreachable / wrong IP / firewall block
         4) FMC refusing file:// origin */
      throw new Error(
        'Network error reaching ' + url + '. Likely causes: ' +
        '(a) FMC self-signed cert NOT pre-trusted in this browser — open ' +
        'https://' + host + '/api/api-explorer/ in a NEW tab, accept the cert warning, ' +
        'then retry; ' +
        '(b) FMC did not return CORS headers (Access-Control-Allow-Origin); ' +
        '(c) FMC unreachable from this machine. Original: ' + netErr.message
      );
    }
    if (!r.ok) throw new Error('Login HTTP ' + r.status + ' ' + r.statusText);
    const token = r.headers.get('X-auth-access-token');
    const domainUuid = r.headers.get('DOMAIN_UUID');
    if (!token || !domainUuid) {
      throw new Error(
        'Auth response missing X-auth-access-token or DOMAIN_UUID header. ' +
        'Likely a CORS issue: the browser blocked access to custom response headers ' +
        'because FMC did not send Access-Control-Expose-Headers.'
      );
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
      if (!r.ok) throw new Error('List failed for ' + endpoint + ': HTTP ' + r.status);
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
