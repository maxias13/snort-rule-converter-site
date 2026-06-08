/* Variable Set - Random value generator and FMC payload builder
   Builds BOTH:
   (1) Network/Host/Port Objects that live in Object Management
   (2) Variable Set entries (NetworkVariable / PortVariable) that REFERENCE
       those objects via included.referenceObjects[]

   Workflow at runtime:
     a) POST each Network/Host Object  -> capture {id, type}
     b) POST each Port Object          -> capture {id, type}
     c) PUT  the Variable Set body with variables[] entries whose
        included.referenceObjects[] = [{ id, type, name }] */
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

  /* FMC name regex (Object + Variable):  ^[a-zA-Z0-9_.+-]{1,64}$ */
  function sanitize(name) {
    return name.replace(/[^A-Za-z0-9_.+\-]/g, '_').substring(0, 64);
  }

  function emptySide() {
    return { literals: [], variables: [], referenceObjects: [], empty: true };
  }

  function includedWithRef(refName, refType) {
    return {
      literals: [],
      variables: [],
      referenceObjects: [{ name: refName, type: refType }],
      empty: false
    };
  }

  /* Heuristic to decide whether a Snort IP variable looks like a network
     (CIDR) or a single host based on common naming hints. */
  function looksLikeNetwork(name) {
    const lower = name.toLowerCase();
    const hints = ['_servers', '_net', 'network', 'subnet', '_range', '_nets'];
    return hints.some(function (kw) { return lower.indexOf(kw) >= 0; });
  }

  /* Build an FMC Network / Host Object payload (POST body for
     /object/networks  or  /object/hosts). */
  function buildNetworkObject(name, usage, rng) {
    const safeName = sanitize(name);
    const isNet = looksLikeNetwork(name);
    const desc = 'Auto-created from Snort variable $' + name +
      ' (src=' + usage.src + ', dst=' + usage.dst + ')';
    if (isNet) {
      return {
        endpoint: 'networks',
        objType: 'Network',
        body: { name: safeName, type: 'Network', value: rng.networkCidr(), description: desc }
      };
    }
    return {
      endpoint: 'hosts',
      objType: 'Host',
      body: { name: safeName, type: 'Host', value: rng.hostIp(), description: desc }
    };
  }

  /* Build an FMC Port Object payload (POST body for
     /object/protocolportobjects). */
  function buildPortObject(name, usage, rng) {
    const safeName = sanitize(name);
    const lower = name.toLowerCase();
    const udpHints = ['udp', 'dns', 'syslog', 'openvpn', 'snmp', 'ntp', 'dhcp', 'ipsec'];
    const protocol = udpHints.some(function (h) { return lower.indexOf(h) >= 0; }) ? 'UDP' : 'TCP';
    return {
      endpoint: 'protocolportobjects',
      objType: 'ProtocolPortObject',
      body: {
        name: safeName,
        type: 'ProtocolPortObject',
        protocol: protocol,
        port: String(rng.port()),
        description: 'Auto-created from Snort variable $' + name +
          ' (src=' + usage.src + ', dst=' + usage.dst + ')'
      }
    };
  }

  /* Build a Variable Set entry that REFERENCES a Network/Host Object.
     Note: Variable name is the ORIGINAL Snort variable name (sanitized);
     the referenceObjects[] entry uses the same sanitized name to bind to
     the just-created Object at runtime (Python script resolves id). */
  function buildNetworkVariableEntry(varName, objType) {
    const safeName = sanitize(varName);
    return {
      name: safeName,
      type: 'NetworkVariable',
      included: includedWithRef(safeName, objType),
      excluded: emptySide()
    };
  }

  function buildPortVariableEntry(varName) {
    const safeName = sanitize(varName);
    return {
      name: safeName,
      type: 'PortVariable',
      included: includedWithRef(safeName, 'ProtocolPortObject'),
      excluded: emptySide()
    };
  }

  /* Top-level generator. Returns the full plan for the Python script:
     {
       networkObjects: [ { endpoint, objType, body } ],
       portObjects:    [ { endpoint, objType, body } ],
       ipVariables:    [ { name, type:'NetworkVariable', included:{ referenceObjects:[{name,type}] } } ],
       portVariables:  [ { name, type:'PortVariable',    included:{ referenceObjects:[{name,type:'ProtocolPortObject'}] } } ]
     } */
  function generateAllPayloads(userIpVars, userPortVars) {
    const rng = new RandomGen();
    const networkObjects = [];
    const portObjects = [];
    const ipVariables = [];
    const portVariables = [];

    Object.keys(userIpVars).sort().forEach(function (name) {
      const obj = buildNetworkObject(name, userIpVars[name], rng);
      networkObjects.push(obj);
      ipVariables.push(buildNetworkVariableEntry(name, obj.objType));
    });
    Object.keys(userPortVars).sort().forEach(function (name) {
      const obj = buildPortObject(name, userPortVars[name], rng);
      portObjects.push(obj);
      portVariables.push(buildPortVariableEntry(name));
    });

    return {
      networkObjects: networkObjects,
      portObjects: portObjects,
      ipVariables: ipVariables,
      portVariables: portVariables
    };
  }

  window.AddObjectGenerator = {
    RandomGen: RandomGen,
    buildNetworkObject: buildNetworkObject,
    buildPortObject: buildPortObject,
    buildNetworkVariableEntry: buildNetworkVariableEntry,
    buildPortVariableEntry: buildPortVariableEntry,
    generateAllPayloads: generateAllPayloads
  };
})();
