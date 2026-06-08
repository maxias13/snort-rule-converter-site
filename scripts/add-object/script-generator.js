/* Add Object - Python script generator
   Builds a self-contained Python script that the user runs locally
   to call FMC REST API directly (bypassing browser CORS/cert limitations) */
(function () {
  'use strict';

  function pyStr(s) {
    return JSON.stringify(String(s));
  }

  function buildPythonScript(fmcHost, fmcUser, payloads) {
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const hostsJson = JSON.stringify(payloads.hosts, null, 2);
    const networksJson = JSON.stringify(payloads.networks, null, 2);
    const portsJson = JSON.stringify(payloads.ports, null, 2);
    const total = payloads.hosts.length + payloads.networks.length + payloads.ports.length;

    const script = [
      '#!/usr/bin/env python3',
      '"""',
      'FMC Object Importer (auto-generated)',
      '====================================',
      'Generated at: ' + ts,
      'Target FMC:   ' + fmcHost,
      'API user:     ' + fmcUser,
      'Total objects: ' + total + ' (' +
        payloads.hosts.length + ' hosts, ' +
        payloads.networks.length + ' networks, ' +
        payloads.ports.length + ' ports)',
      '',
      'Object names are preserved exactly as found in the Snort rule file.',
      'IP/port values are randomized placeholders — replace with real values',
      'in FMC GUI after import if needed.',
      '',
      'Run this script from a host that has direct network access to the FMC',
      '(typically inside the same management network).',
      '',
      'Usage:',
      '    pip install requests',
      '    python3 ' + 'fmc_import_' + ts + '.py',
      '"""',
      '',
      'from __future__ import annotations',
      '',
      'import getpass',
      'import json',
      'import sys',
      'from datetime import datetime',
      '',
      'try:',
      '    import requests',
      '    import urllib3',
      'except ImportError:',
      '    sys.exit("ERROR: install requests first: pip install requests")',
      '',
      'urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)',
      '',
      'FMC_HOST = ' + pyStr(fmcHost),
      'FMC_USER = ' + pyStr(fmcUser),
      '',
      'HOSTS = ' + hostsJson,
      '',
      'NETWORKS = ' + networksJson,
      '',
      'PORTS = ' + portsJson,
      '',
      '',
      'def login(host, user, password):',
      '    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"',
      '    r = requests.post(url, auth=(user, password), verify=False, timeout=30)',
      '    r.raise_for_status()',
      '    token = r.headers.get("X-auth-access-token")',
      '    domain = r.headers.get("DOMAIN_UUID")',
      '    if not token or not domain:',
      '        raise RuntimeError(f"Auth failed: missing headers. Got: {dict(r.headers)}")',
      '    return token, domain',
      '',
      '',
      'def list_existing(host, token, domain, endpoint):',
      '    names = set()',
      '    offset, limit = 0, 1000',
      '    while True:',
      '        url = (f"https://{host}/api/fmc_config/v1/domain/{domain}"',
      '               f"/object/{endpoint}?expanded=false&offset={offset}&limit={limit}")',
      '        r = requests.get(url, headers={"X-auth-access-token": token},',
      '                         verify=False, timeout=60)',
      '        r.raise_for_status()',
      '        data = r.json()',
      '        for item in data.get("items", []):',
      '            names.add(item["name"])',
      '        if offset + limit >= data.get("paging", {}).get("count", 0):',
      '            break',
      '        offset += limit',
      '    return names',
      '',
      '',
      'def bulk_create(host, token, domain, endpoint, payloads):',
      '    if not payloads:',
      '        return [], []',
      '    url = (f"https://{host}/api/fmc_config/v1/domain/{domain}"',
      '           f"/object/{endpoint}?bulk=true")',
      '    r = requests.post(url, json=payloads,',
      '                      headers={"X-auth-access-token": token,',
      '                               "Content-Type": "application/json"},',
      '                      verify=False, timeout=120)',
      '    if r.status_code in (200, 201):',
      '        return list(payloads), []',
      '    err = r.text[:500]',
      '    return [], [{"name": p["name"], "error": err} for p in payloads]',
      '',
      '',
      'def main():',
      '    print(f"FMC Object Importer  (target: {FMC_HOST})")',
      '    print(f"  Hosts:    {len(HOSTS)}")',
      '    print(f"  Networks: {len(NETWORKS)}")',
      '    print(f"  Ports:    {len(PORTS)}")',
      '    print()',
      '    password = getpass.getpass(f"Password for {FMC_USER}@{FMC_HOST}: ")',
      '',
      '    print(f"\\n[+] Logging in to {FMC_HOST}...")',
      '    try:',
      '        token, domain = login(FMC_HOST, FMC_USER, password)',
      '    except Exception as e:',
      '        sys.exit(f"[!] Login failed: {e}")',
      '    print(f"    OK (domain={domain})")',
      '',
      '    print("[+] Listing existing objects...")',
      '    existing_hosts = list_existing(FMC_HOST, token, domain, "hosts")',
      '    existing_networks = list_existing(FMC_HOST, token, domain, "networks")',
      '    existing_ports = list_existing(FMC_HOST, token, domain, "protocolportobjects")',
      '    print(f"    existing: hosts={len(existing_hosts)}, "',
      '          f"networks={len(existing_networks)}, ports={len(existing_ports)}")',
      '',
      '    hosts_new = [p for p in HOSTS if p["name"] not in existing_hosts]',
      '    nets_new = [p for p in NETWORKS if p["name"] not in existing_networks]',
      '    ports_new = [p for p in PORTS if p["name"] not in existing_ports]',
      '    skipped = ([p["name"] for p in HOSTS if p["name"] in existing_hosts]',
      '               + [p["name"] for p in NETWORKS if p["name"] in existing_networks]',
      '               + [p["name"] for p in PORTS if p["name"] in existing_ports])',
      '    if skipped:',
      '        print(f"[!] Already exist (SKIP): {skipped}")',
      '',
      '    print(f"\\n[+] Creating: hosts={len(hosts_new)}, "',
      '          f"networks={len(nets_new)}, ports={len(ports_new)}")',
      '    h_ok, h_fail = bulk_create(FMC_HOST, token, domain, "hosts", hosts_new)',
      '    n_ok, n_fail = bulk_create(FMC_HOST, token, domain, "networks", nets_new)',
      '    p_ok, p_fail = bulk_create(FMC_HOST, token, domain,',
      '                               "protocolportobjects", ports_new)',
      '',
      '    print(f"\\n=== Results ===")',
      '    print(f"  Hosts:    success={len(h_ok)}, failed={len(h_fail)}")',
      '    print(f"  Networks: success={len(n_ok)}, failed={len(n_fail)}")',
      '    print(f"  Ports:    success={len(p_ok)}, failed={len(p_fail)}")',
      '',
      '    failures = h_fail + n_fail + p_fail',
      '    if failures:',
      '        print("\\n=== Failures ===")',
      '        for f in failures:',
      '            print(f"  {f[\'name\']}: {f[\'error\']}")',
      '        sys.exit(1)',
      '',
      '    report = {',
      '        "timestamp": datetime.now().isoformat(),',
      '        "fmc_host": FMC_HOST,',
      '        "skipped": skipped,',
      '        "created": {"hosts": h_ok, "networks": n_ok, "ports": p_ok},',
      '    }',
      '    out = f"fmc_import_report_{datetime.now().strftime(\'%Y%m%d_%H%M%S\')}.json"',
      '    with open(out, "w", encoding="utf-8") as f:',
      '        json.dump(report, f, indent=2, ensure_ascii=False)',
      '    print(f"\\n[+] Report saved to {out}")',
      '',
      '',
      'if __name__ == "__main__":',
      '    main()',
      ''
    ];
    return script.join('\n');
  }

  function downloadScript(content, filename) {
    const blob = new Blob([content], { type: 'text/x-python;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  window.AddObjectScriptGen = {
    buildPythonScript: buildPythonScript,
    downloadScript: downloadScript
  };
})();
