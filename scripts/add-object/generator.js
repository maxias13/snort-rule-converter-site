/* Variable Set - Random value generator and FMC NetworkVariable/PortVariable payload builder
   Builds entries for the variables[] array inside a Variable Set body
   (FMC schema: type=NetworkVariable | PortVariable, included.literals[]) */
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

  /* FMC variable name regex: ^[a-zA-Z0-9_.+-]{1,64}$ */
  function sanitize(name) {
    return name.replace(/[^A-Za-z0-9_.+\-]/g, '_').substring(0, 64);
  }

  function emptySide() {
    return { literals: [], variables: [], referenceObjects: [], empty: true };
  }

  function includedWith(literals) {
    return { literals: literals, variables: [], referenceObjects: [], empty: literals.length === 0 };
  }

  function buildNetworkVariable(name, usage, rng) {
    const lower = name.toLowerCase();
    const hints = ['_servers', '_net', 'network', 'subnet', '_range'];
    const isNetwork = hints.some(function (kw) { return lower.indexOf(kw) >= 0; });
    const literal = isNetwork ? rng.networkCidr() : rng.hostIp();
    return {
      name: sanitize(name),
      type: 'NetworkVariable',
      included: includedWith([literal]),
      excluded: emptySide()
    };
  }

  function buildPortVariable(name, usage, rng) {
    return {
      name: sanitize(name),
      type: 'PortVariable',
      included: includedWith([String(rng.port())]),
      excluded: emptySide()
    };
  }

  function generateAllPayloads(userIpVars, userPortVars) {
    const rng = new RandomGen();
    const ipVariables = [];
    const portVariables = [];
    Object.keys(userIpVars).sort().forEach(function (name) {
      ipVariables.push(buildNetworkVariable(name, userIpVars[name], rng));
    });
    Object.keys(userPortVars).sort().forEach(function (name) {
      portVariables.push(buildPortVariable(name, userPortVars[name], rng));
    });
    return { ipVariables: ipVariables, portVariables: portVariables };
  }

  window.AddObjectGenerator = {
    RandomGen: RandomGen,
    buildNetworkVariable: buildNetworkVariable,
    buildPortVariable: buildPortVariable,
    generateAllPayloads: generateAllPayloads
  };
})();
