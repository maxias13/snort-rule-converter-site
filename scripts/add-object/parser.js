/* Add Object - Snort parser and FMC default variable list
   FMC 7.4 predefined variables already exist in the system */
(function () {
  'use strict';

  const FMC_DEFAULT_VARS = new Set([
    'HOME_NET', 'EXTERNAL_NET',
    'DNS_SERVERS', 'SMTP_SERVERS', 'HTTP_SERVERS', 'SQL_SERVERS',
    'TELNET_SERVERS', 'SSH_SERVERS', 'FTP_SERVERS', 'SIP_SERVERS',
    'AIM_SERVERS',
    'HTTP_PORTS', 'SHELLCODE_PORTS', 'ORACLE_PORTS', 'SSH_PORTS',
    'FTP_PORTS', 'SIP_PORTS', 'FILE_DATA_PORTS', 'GTP_PORTS'
  ]);

  /* Snort 2 header layout: action proto src_ip src_port direction dst_ip dst_port (opts)
     position-based capture is required to distinguish IP vs Port variables */
  const RULE_HEADER_RE = /^[ \t]*(?:alert|drop|log|pass|reject|sdrop|block)[ \t]+(tcp|udp|ip|icmp|http|tls|ssl|smb|dns|ftp|smtp)[ \t]+(\S+)[ \t]+(\S+)[ \t]+(->|<>|<-)[ \t]+(\S+)[ \t]+(\S+)[ \t]*\(/gim;
  const VAR_TOKEN_RE = /!?\$[A-Za-z][A-Za-z0-9_]*/g;

  function parseSnortVariables(text) {
    const ipVars = {};
    const portVars = {};
    let ruleCount = 0;
    let m;
    RULE_HEADER_RE.lastIndex = 0;
    while ((m = RULE_HEADER_RE.exec(text)) !== null) {
      ruleCount++;
      const fields = [
        [m[2], ipVars, 'src'], [m[5], ipVars, 'dst'],
        [m[3], portVars, 'src'], [m[6], portVars, 'dst']
      ];
      for (let i = 0; i < fields.length; i++) {
        const token = fields[i][0], bucket = fields[i][1], side = fields[i][2];
        const matches = token.match(VAR_TOKEN_RE) || [];
        for (let j = 0; j < matches.length; j++) {
          const name = matches[j].replace(/^!?\$/, '');
          if (!bucket[name]) bucket[name] = { src: 0, dst: 0 };
          bucket[name][side]++;
        }
      }
    }
    return { ipVars: ipVars, portVars: portVars, ruleCount: ruleCount };
  }

  function filterUserVars(vars) {
    const out = {};
    for (const k in vars) {
      if (!FMC_DEFAULT_VARS.has(k)) out[k] = vars[k];
    }
    return out;
  }

  function getSkippedDefaults(ipVars, portVars) {
    const all = new Set();
    Object.keys(ipVars).forEach(function (k) { all.add(k); });
    Object.keys(portVars).forEach(function (k) { all.add(k); });
    return Array.from(all).filter(function (k) {
      return FMC_DEFAULT_VARS.has(k);
    }).sort();
  }

  window.AddObjectParser = {
    parseSnortVariables: parseSnortVariables,
    filterUserVars: filterUserVars,
    getSkippedDefaults: getSkippedDefaults,
    FMC_DEFAULT_VARS: FMC_DEFAULT_VARS
  };
})();
