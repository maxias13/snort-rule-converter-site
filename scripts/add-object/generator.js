/* Add Object - Random value generator and FMC payload builder */
(function () {
  'use strict';

  function RandomGen() {
    this.usedIps = new Set();
    this.usedSubnets = new Set();
    this.usedPorts = new Set();
  }
  RandomGen.prototype.rand = function (min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  };
  RandomGen.prototype.hostIp = function () {
    for (let i = 0; i < 1000; i++) {
      const ip = '10.' + this.rand(0, 255) + '.' + this.rand(0, 255) + '.' + this.rand(1, 254);
      if (!this.usedIps.has(ip)) { this.usedIps.add(ip); return ip; }
    }
    throw new Error('IP pool exhausted');
  };
  RandomGen.prototype.networkCidr = function () {
    for (let i = 0; i < 1000; i++) {
      const o2 = this.rand(0, 255), o3 = this.rand(0, 255);
      const key = o2 * 256 + o3;
      if (!this.usedSubnets.has(key)) {
        this.usedSubnets.add(key);
        return '10.' + o2 + '.' + o3 + '.0/24';
      }
    }
    throw new Error('Subnet pool exhausted');
  };
  RandomGen.prototype.port = function () {
    for (let i = 0; i < 1000; i++) {
      const p = this.rand(30000, 60000);
      if (!this.usedPorts.has(p)) { this.usedPorts.add(p); return p; }
    }
    throw new Error('Port pool exhausted');
  };

  function buildNetworkPayload(name, usage, rng) {
    /* FMC API constraint: alphanumeric/_/- only, max 64 chars */
    const sanitized = name.replace(/[^A-Za-z0-9_\-]/g, '_').substring(0, 64);
    const lower = name.toLowerCase();
    const hints = ['_servers', '_net', 'network', 'subnet', '_range'];
    const isNetwork = hints.some(function (kw) { return lower.indexOf(kw) >= 0; });
    const desc = 'Auto-created from Snort variable $' + name +
      ' (src=' + usage.src + ', dst=' + usage.dst + ')';
    if (isNetwork) {
      return { name: sanitized, type: 'Network', value: rng.networkCidr(), description: desc };
    }
    return { name: sanitized, type: 'Host', value: rng.hostIp(), description: desc };
  }

  function buildPortPayload(name, usage, rng) {
    const sanitized = name.replace(/[^A-Za-z0-9_\-]/g, '_').substring(0, 64);
    const lower = name.toLowerCase();
    const udpHints = ['udp', 'dns', 'syslog', 'openvpn', 'snmp', 'ntp', 'dhcp', 'ipsec'];
    const protocol = udpHints.some(function (h) { return lower.indexOf(h) >= 0; }) ? 'UDP' : 'TCP';
    return {
      name: sanitized,
      type: 'ProtocolPortObject',
      protocol: protocol,
      port: String(rng.port()),
      description: 'Auto-created from Snort variable $' + name +
        ' (src=' + usage.src + ', dst=' + usage.dst + ')'
    };
  }

  function generateAllPayloads(userIpVars, userPortVars) {
    const rng = new RandomGen();
    const hosts = [], networks = [], ports = [];
    Object.keys(userIpVars).sort().forEach(function (name) {
      const p = buildNetworkPayload(name, userIpVars[name], rng);
      if (p.type === 'Network') networks.push(p); else hosts.push(p);
    });
    Object.keys(userPortVars).sort().forEach(function (name) {
      ports.push(buildPortPayload(name, userPortVars[name], rng));
    });
    return { hosts: hosts, networks: networks, ports: ports };
  }

  window.AddObjectGenerator = {
    RandomGen: RandomGen,
    buildNetworkPayload: buildNetworkPayload,
    buildPortPayload: buildPortPayload,
    generateAllPayloads: generateAllPayloads
  };
})();
