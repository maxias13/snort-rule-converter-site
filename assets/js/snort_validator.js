/**
 * snort_validator.js - browser port of snort_2_validator + snort_3_validator
 * Source: .claude/skills/snort_{2,3}_validator/scripts/*.py
 * API: window.SnortValidator = { parse, validate, optimize, render }
 */
(function (global) {
  "use strict";

  // ---------- AST helpers ----------
  function makeOption(name, value, raw) { return { name: name, value: value, raw: raw }; }
  function makeHeader(action, proto, src_ip, src_port, direction, dst_ip, dst_port, kind) {
    return {
      action: action, proto: proto,
      src_ip: src_ip || "", src_port: src_port || "",
      direction: direction || "",
      dst_ip: dst_ip || "", dst_port: dst_port || "",
      kind: kind || "classic"
    };
  }
  function makeRule(file, line, raw, enabled, header, options, parse_errors) {
    return {
      file: file, line: line, raw: raw, enabled: enabled,
      header: header, options: options || [], parse_errors: parse_errors || [],
      sid: function () {
        for (var i = 0; i < this.options.length; i++) {
          var o = this.options[i];
          if (o.name === "sid" && o.value != null) {
            var n = parseInt(String(o.value).trim(), 10);
            return isNaN(n) ? null : n;
          }
        }
        return null;
      },
      opt: function (name) {
        for (var i = 0; i < this.options.length; i++) {
          if (this.options[i].name === name) return this.options[i];
        }
        return null;
      },
      opts: function (name) {
        var out = [];
        for (var i = 0; i < this.options.length; i++) {
          if (this.options[i].name === name) out.push(this.options[i]);
        }
        return out;
      }
    };
  }
  function makeFinding(file, line, sid, id, sev, msg, ref, sug) {
    return {
      file: file, line: line, sid: sid, check_id: id,
      severity: sev, message: msg, manual_ref: ref,
      suggestion: sug == null ? null : sug
    };
  }

  // ---------- Shared helpers ----------
  function isDigit(s) { return /^-?\d+$/.test(s); }

  // Approximate byte length of content pattern (handles |hex| segments)
  function contentLength(value) {
    if (!value) return 0;
    var s = String(value).trim();
    if (s.charAt(0) === "!") s = s.substring(1).replace(/^\s+/, "");
    if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
      s = s.substring(1, s.length - 1);
    }
    var length = 0, in_hex = false, hex_buf = [];
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (ch === "|") {
        if (in_hex) {
          var hex_str = hex_buf.join("").replace(/\s+/g, "");
          length += Math.floor(hex_str.length / 2);
          hex_buf = [];
        }
        in_hex = !in_hex;
        continue;
      }
      if (in_hex) hex_buf.push(ch);
      else length += 1;
    }
    return length;
  }

  // ============================================================
  // SNORT 2 PARSER
  // ============================================================
  var S2_ACTIONS = {
    alert: 1, log: 1, pass: 1, activate: 1, dynamic: 1,
    drop: 1, reject: 1, sdrop: 1
  };
  var S2_HEADER_RE = /^\s*(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\(/i;

  function s2_parseOneOption(token) {
    var idx = token.indexOf(":");
    if (idx >= 0) {
      var name = token.substring(0, idx).trim();
      var value = token.substring(idx + 1).trim();
      return makeOption(name, value, token);
    }
    return makeOption(token.trim(), null, token);
  }

  function s2_splitOptions(body) {
    var options = [], errors = [];
    var i = 0, n = body.length, cur = [], inQuote = false;
    while (i < n) {
      var ch = body.charAt(i);
      if (ch === "\\" && i + 1 < n) { cur.push(ch); cur.push(body.charAt(i + 1)); i += 2; continue; }
      if (ch === '"') { inQuote = !inQuote; cur.push(ch); i += 1; continue; }
      if (ch === ";" && !inQuote) {
        var tok = cur.join("").trim();
        if (tok) options.push(s2_parseOneOption(tok));
        cur = []; i += 1; continue;
      }
      cur.push(ch); i += 1;
    }
    var leftover = cur.join("").trim();
    if (leftover) errors.push("trailing option without ';': " + JSON.stringify(leftover));
    if (inQuote) errors.push("unterminated quoted string in options");
    return { options: options, errors: errors };
  }

  function s2_joinContinuations(lines) {
    var out = [], buf = [], start = 0, commented = false;
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var line = raw.replace(/\n$/, "");
      var stripped = line.replace(/^\s+/, "");
      if (buf.length === 0) {
        if (!stripped) continue;
        start = i + 1;
        commented = stripped.charAt(0) === "#";
        if (commented) {
          var inner = stripped.replace(/^#+/, "").replace(/^\s+/, "");
          var first = (inner.split(/\s+/)[0] || "").toLowerCase();
          if (!S2_ACTIONS[first]) continue;
          line = inner;
        } else {
          line = stripped;
        }
      }
      if (line.charAt(line.length - 1) === "\\") {
        buf.push(line.substring(0, line.length - 1).replace(/\s+$/, ""));
        continue;
      }
      buf.push(line);
      out.push({ start: start, text: buf.join(" ").trim(), commented: commented });
      buf = [];
    }
    if (buf.length) out.push({ start: start, text: buf.join(" ").trim(), commented: commented });
    return out;
  }

  function s2_parseRule(text, source, lineNo, enabled) {
    if (!text.trim()) return null;
    var m = S2_HEADER_RE.exec(text);
    if (!m) {
      var first = (text.split(/\s+/)[0] || "").toLowerCase();
      if (!S2_ACTIONS[first]) return null;
      return makeRule(source, lineNo, text, enabled, null, [],
        ["could not parse rule header at " + source + ":" + lineNo]);
    }
    var header = makeHeader(m[1].toLowerCase(), m[2].toLowerCase(),
      m[3], m[4], m[5], m[6], m[7], "classic");
    var bodyStart = m.index + m[0].length;
    var depth = 1, i = bodyStart, inQuote = false;
    while (i < text.length) {
      var ch = text.charAt(i);
      if (ch === "\\" && i + 1 < text.length) { i += 2; continue; }
      if (ch === '"') inQuote = !inQuote;
      else if (!inQuote) {
        if (ch === "(") depth++;
        else if (ch === ")") { depth--; if (depth === 0) break; }
      }
      i++;
    }
    if (depth !== 0) {
      return makeRule(source, lineNo, text, enabled, header, [],
        ["unbalanced parentheses in rule body"]);
    }
    var body = text.substring(bodyStart, i);
    var split = s2_splitOptions(body);
    return makeRule(source, lineNo, text, enabled, header, split.options, split.errors);
  }

  function s2_parseText(text, source) {
    source = source || "<string>";
    var rules = [];
    var lines = text.split(/\r?\n/);
    var joined = s2_joinContinuations(lines);
    for (var k = 0; k < joined.length; k++) {
      var j = joined[k];
      var r = s2_parseRule(j.text, source, j.start, !j.commented);
      if (r) rules.push(r);
    }
    return rules;
  }

  // ============================================================
  // SNORT 2 VALIDATOR (S001..S020)
  // ============================================================
  var S2_DEFAULT_CLASSTYPES = {
    "not-suspicious":1,"unknown":1,"bad-unknown":1,"attempted-recon":1,
    "successful-recon-limited":1,"successful-recon-largescale":1,
    "attempted-dos":1,"successful-dos":1,"attempted-user":1,"unsuccessful-user":1,
    "successful-user":1,"attempted-admin":1,"successful-admin":1,
    "rpc-portmap-decode":1,"shellcode-detect":1,"string-detect":1,
    "suspicious-filename-detect":1,"suspicious-login":1,"system-call-detect":1,
    "tcp-connection":1,"trojan-activity":1,"unusual-client-port-connection":1,
    "network-scan":1,"denial-of-service":1,"non-standard-protocol":1,
    "protocol-command-decode":1,"web-application-activity":1,
    "web-application-attack":1,"misc-activity":1,"misc-attack":1,
    "icmp-event":1,"kickass-porn":1,"policy-violation":1,"default-login-attempt":1,
    "sdf":1,"file-format":1,"malware-cnc":1,"client-side-exploit":1
  };
  var S2_CONTENT_MODIFIERS = {
    nocase:1,rawbytes:1,depth:1,offset:1,distance:1,within:1,
    http_uri:1,http_raw_uri:1,http_header:1,http_raw_header:1,
    http_cookie:1,http_raw_cookie:1,http_method:1,
    http_client_body:1,http_stat_code:1,http_stat_msg:1,fast_pattern:1
  };

  function s2_contentMods(opt_names, idx) {
    var out = [];
    for (var j = idx + 1; j < opt_names.length; j++) {
      if (S2_CONTENT_MODIFIERS[opt_names[j]]) out.push(opt_names[j]);
      else break;
    }
    return out;
  }

  function s2_validate(rules) {
    var findings = [], seen_sids = {};
    for (var ri = 0; ri < rules.length; ri++) {
      var r = rules[ri];
      if (r.parse_errors && r.parse_errors.length) {
        for (var pe = 0; pe < r.parse_errors.length; pe++) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S001", "error",
            "parse error: " + r.parse_errors[pe], "§3.1"));
        }
        if (!r.header) continue;
      }
      if (!r.header) continue;
      var opt_names = r.options.map(function (o) { return o.name; });

      var sid_opt = r.opt("sid"), sid = null;
      if (!sid_opt || sid_opt.value == null || !/^\d+$/.test(String(sid_opt.value).trim())) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S002", "error",
          "rule missing required `sid`", "§3.4.4",
          "add `sid:<int>;` (>= 1000000 for local rules)"));
      } else {
        sid = parseInt(String(sid_opt.value).trim(), 10);
        if (sid < 1000000 && r.file && /local/i.test(r.file)) {
          findings.push(makeFinding(r.file, r.line, sid, "S006", "error",
            "local rule uses reserved sid " + sid + " (< 1000000)", "§3.4.4",
            "use sid >= 1000000 for user/local rules"));
        }
        if (seen_sids[sid]) {
          findings.push(makeFinding(r.file, r.line, sid, "S007", "warn",
            "duplicate sid " + sid + " (previously at " +
            seen_sids[sid].file + ":" + seen_sids[sid].line + ")", "§3.4.4"));
        } else {
          seen_sids[sid] = { file: r.file, line: r.line };
        }
      }

      if (!r.opt("rev")) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S003", "warn",
          "rule missing `rev`", "§3.4.5", "add `rev:1;` and bump on every modification"));
      }
      if (!r.opt("msg")) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S004", "warn",
          "rule missing `msg`", "§3.4.1", "add a descriptive `msg:\"...\";`"));
      }
      var ct = r.opt("classtype");
      if (!ct) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S005", "warn",
          "rule missing `classtype`", "§3.4.6"));
      } else {
        var ctval = String(ct.value || "").trim();
        if (ctval && !S2_DEFAULT_CLASSTYPES[ctval]) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S016", "error",
            "unknown classtype `" + ctval + "` (not in classification.config)", "§3.4.6",
            "use a standard classtype or add `" + ctval + "` to classification.config"));
        }
      }

      var has_match = false;
      for (var i = 0; i < opt_names.length; i++) {
        if (opt_names[i] === "content" || opt_names[i] === "uricontent" || opt_names[i] === "pcre") {
          has_match = true; break;
        }
      }
      if (!has_match) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S008", "warn",
          "rule has no content/uricontent/pcre — evaluated against every packet", "§3.9.1",
          "add a literal `content:\"...\";` to leverage Boyer-Moore"));
      }

      var contents_idx = [], pcres_idx = [];
      for (var k = 0; k < opt_names.length; k++) {
        if (opt_names[k] === "content") contents_idx.push(k);
        if (opt_names[k] === "pcre") pcres_idx.push(k);
      }
      if (contents_idx.length === 1 && pcres_idx.length && pcres_idx[0] < contents_idx[0]) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S009", "info",
          "pcre precedes content — cheap-first ordering violated", "§3.9.4",
          "move `content:` before `pcre:` so Boyer-Moore filters first"));
      }

      var contents = r.opts("content");
      if (contents.length) {
        var has_fp_marker = false;
        for (var ci = 0; ci < contents_idx.length; ci++) {
          var slice = opt_names.slice(contents_idx[ci] + 1, contents_idx[ci] + 8);
          if (slice.indexOf("fast_pattern") >= 0) { has_fp_marker = true; break; }
        }
        if (contents.length > 1 && !has_fp_marker) {
          var lens = contents.map(function (c) { return contentLength(c.value); });
          var shortest = Math.min.apply(null, lens), longest = Math.max.apply(null, lens);
          if (longest > shortest * 2 && shortest < 4) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S010", "warn",
              "multiple contents, no explicit `fast_pattern` (shortest=" +
              shortest + "B, longest=" + longest + "B)", "§3.5.7",
              "mark the longest unique content with `fast_pattern;`"));
          }
        }
        for (var fi = 0; fi < contents_idx.length; fi++) {
          var mods = s2_contentMods(opt_names, contents_idx[fi]);
          if (mods.indexOf("fast_pattern") >= 0) {
            var clen = contentLength(contents[fi].value);
            if (clen < 4) {
              findings.push(makeFinding(r.file, r.line, r.sid(), "S011", "warn",
                "`fast_pattern` content is < 4 bytes (" +
                JSON.stringify(contents[fi].value) + ") — weak", "§3.5.7",
                "pick a longer, more unique content"));
            }
          }
        }
      }

      for (var oi = 0; oi < r.options.length; oi++) {
        var opt = r.options[oi];
        if (opt.name === "depth" || opt.name === "offset" ||
            opt.name === "distance" || opt.name === "within") {
          var v = String(opt.value || "").trim();
          if (!isDigit(v)) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S012", "error",
              "`" + opt.name + "` value `" + v + "` is not numeric", "§3.5.3-3.5.6"));
          }
          if (opt.name === "distance" || opt.name === "within") {
            var hasPrior = false;
            for (var pi = 0; pi < oi; pi++) {
              var n = opt_names[pi];
              if (n === "content" || n === "uricontent" || n === "pkt_data" || n === "file_data") {
                hasPrior = true; break;
              }
            }
            if (!hasPrior) {
              findings.push(makeFinding(r.file, r.line, r.sid(), "S013", "error",
                "`" + opt.name + "` has no preceding content/uricontent to anchor to",
                "§3.5.5-3.5.6"));
            }
          }
        }
      }

      for (var ni = 0; ni < r.options.length; ni++) {
        if (r.options[ni].name === "nocase") {
          var hasPriorContent = false;
          for (var nj = 0; nj < ni; nj++) {
            if (opt_names[nj] === "content" || opt_names[nj] === "uricontent") {
              hasPriorContent = true; break;
            }
          }
          if (!hasPriorContent) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S014", "warn",
              "`nocase` placed before any `content` — modifies nothing", "§3.5.2"));
          }
        }
      }

      if (r.opt("threshold")) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S015", "warn",
          "deprecated `threshold` rule option used", "§3.8",
          "migrate to `detection_filter:` or `event_filter` in threshold.conf"));
      }

      if (r.header.proto === "tcp" && !r.opt("flow") && has_match) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S017", "warn",
          "TCP rule without `flow` — direction/state ambiguous", "§3.6.10",
          "add `flow:established,to_server;` (or to_client)"));
      }

      if (r.header.src_ip === "any" && r.header.dst_ip === "any" &&
          r.header.src_port === "any" && r.header.dst_port === "any") {
        var longestC = 0;
        for (var lc = 0; lc < contents.length; lc++) {
          longestC = Math.max(longestC, contentLength(contents[lc].value));
        }
        if (longestC < 6) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S019", "info",
            "any/any header with weak content (max " + longestC +
            "B) — expensive", "§3.9.4",
            "restrict to $HOME_NET / specific ports if possible"));
        }
      }

      var pcres = r.opts("pcre");
      for (var pp = 0; pp < pcres.length; pp++) {
        var pv = String(pcres[pp].value || "").trim().replace(/^"|"$/g, "");
        var mr = /^\/([\s\S]*)\/([A-Za-z]*)$/.exec(pv);
        if (!mr) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S020", "error",
            "pcre value not in `/.../flags` form: " + JSON.stringify(pv), "§3.5.13"));
          continue;
        }
        try { new RegExp(mr[1]); }
        catch (e) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S020", "error",
            "pcre fails to compile: " + e.message, "§3.5.13"));
        }
      }
    }
    return findings;
  }

  // ============================================================
  // SNORT 2 OPTIMIZER (O001..O006)
  // ============================================================
  function s2_costScore(r) {
    if (!r.header) return 0;
    var opt_names = r.options.map(function (o) { return o.name; });
    var contents = r.opts("content");
    var has_pcre = opt_names.indexOf("pcre") >= 0;
    var contents_idx = [];
    for (var i = 0; i < opt_names.length; i++) {
      if (opt_names[i] === "content") contents_idx.push(i);
    }
    var has_fp = false;
    for (var ci = 0; ci < contents_idx.length; ci++) {
      var slice = opt_names.slice(contents_idx[ci] + 1, contents_idx[ci] + 8);
      if (slice.indexOf("fast_pattern") >= 0) { has_fp = true; break; }
    }
    var any_any = (r.header.src_ip === "any" && r.header.dst_ip === "any" &&
                   r.header.src_port === "any" && r.header.dst_port === "any");
    var no_flow = r.header.proto === "tcp" && !r.opt("flow");
    var longest = 0;
    for (var lc = 0; lc < contents.length; lc++) {
      longest = Math.max(longest, contentLength(contents[lc].value));
    }
    var short_fp = has_fp && longest < 4;
    var content_after_pcre = false;
    if (has_pcre && contents.length) {
      var first_pcre = opt_names.indexOf("pcre");
      for (var cj = 0; cj < contents_idx.length; cj++) {
        if (contents_idx[cj] > first_pcre) { content_after_pcre = true; break; }
      }
    }
    var no_classtype = !r.opt("classtype");
    return 10 * (has_pcre ? 1 : 0)
         + 5 * (!has_fp ? 1 : 0)
         + 5 * (any_any ? 1 : 0)
         + 4 * (no_flow ? 1 : 0)
         + 3 * (short_fp ? 1 : 0)
         + 2 * (content_after_pcre ? 1 : 0)
         + 1 * (no_classtype ? 1 : 0);
  }

  function s2_optimize(rules) {
    var out = [];
    for (var ri = 0; ri < rules.length; ri++) {
      var r = rules[ri];
      if (!r.header) continue;
      var opt_names = r.options.map(function (o) { return o.name; });
      var contents = r.opts("content");
      var contents_idx = [];
      for (var i = 0; i < opt_names.length; i++) {
        if (opt_names[i] === "content") contents_idx.push(i);
      }
      var has_fp = false;
      for (var ci = 0; ci < contents_idx.length; ci++) {
        var slice = opt_names.slice(contents_idx[ci] + 1, contents_idx[ci] + 8);
        if (slice.indexOf("fast_pattern") >= 0) { has_fp = true; break; }
      }
      if (contents.length > 1 && !has_fp) {
        var longest_len = -1, longest_c = null;
        for (var lc = 0; lc < contents.length; lc++) {
          var L = contentLength(contents[lc].value);
          if (L > longest_len) { longest_len = L; longest_c = contents[lc]; }
        }
        out.push(makeFinding(r.file, r.line, r.sid(), "O001", "info",
          "set fast_pattern on the longest content (" + longest_len + "B)",
          "§3.5.7 / §3.9.4",
          "after `content:" + longest_c.value + ";` add `fast_pattern;`"));
      }
      if (opt_names.indexOf("pcre") >= 0 && contents_idx.length) {
        var first_pcre = opt_names.indexOf("pcre");
        var late = false;
        for (var cj = 0; cj < contents_idx.length; cj++) {
          if (contents_idx[cj] > first_pcre) { late = true; break; }
        }
        if (late) {
          out.push(makeFinding(r.file, r.line, r.sid(), "O002", "info",
            "reorder so all content checks precede pcre", "§3.9.4",
            "literal `content:` is dramatically cheaper than `pcre:`"));
        }
      }
      if (r.header.proto === "tcp" && !r.opt("flow")) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O003", "info",
          "add `flow:established,to_server;` (or to_client)", "§3.6.10",
          "lets Snort skip rules on the wrong direction / unestablished flows"));
      }
      if (r.header.src_ip === "any" && r.header.dst_ip === "any") {
        out.push(makeFinding(r.file, r.line, r.sid(), "O004", "info",
          "header uses any/any — restrict to $HOME_NET / specific ports if possible",
          "§3.9.4"));
      }
      if (r.opt("threshold")) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O005", "warn",
          "replace deprecated `threshold:` with `detection_filter:`", "§3.8",
          "see references/deprecations.md for the migration table"));
      }
      var score = s2_costScore(r);
      if (score >= 15) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O006", "warn",
          "rule cost score = " + score + " (>=15 considered expensive)", "§3.9.4",
          "apply O001..O004 to reduce score"));
      }
    }
    return out;
  }

  // ============================================================
  // SNORT 3 PARSER
  // Differences vs S2: actions={alert,block,drop,log,pass,react,reject,rewrite},
  //   service-rule headers (no IP/port/dir), file/file_id headers,
  //   inline `# … ;` and `/* … */` comments, paren-balanced multi-line.
  // ============================================================
  var S3_ACTIONS = ["alert","block","drop","log","pass","react","reject","rewrite"];
  var S3_L34_PROTOS = ["ip","icmp","tcp","udp"];
  var S3_SERVICES = [
    "http","http2","smtp","ssl","tls","ftp","ftp-data","dns","ssh","smb",
    "netbios-ssn","imap","pop3","sip","rtsp","telnet","tftp","snmp","ldap",
    "rdp","mysql","postgres","mongo","radius","kerberos","ntp","irc","dhcp",
    "dnp3","modbus","gtp","iec104","mms","s7commplus","cip","enip"
  ];
  var S3_SPECIAL_PROTOS = ["file","file_id"];
  var S3_HEADER_CLASSIC_RE = /^\s*(alert|block|drop|log|pass|react|reject|rewrite)\s+([A-Za-z][A-Za-z0-9_\-]*)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\(/i;
  var S3_HEADER_SHORT_RE = /^\s*(?:(alert|block|drop|log|pass|react|reject|rewrite)\s+)?([A-Za-z][A-Za-z0-9_\-]*)\s*\(/i;

  function s3_stripBlockComments(text) {
    var out = [];
    var i = 0, n = text.length, in_quote = false;
    while (i < n) {
      var ch = text.charAt(i);
      if (ch === "\\" && i + 1 < n) { out.push(ch, text.charAt(i + 1)); i += 2; continue; }
      if (ch === '"') { in_quote = !in_quote; out.push(ch); i++; continue; }
      if (!in_quote && ch === "/" && i + 1 < n && text.charAt(i + 1) === "*") {
        var j = text.indexOf("*/", i + 2);
        if (j === -1) break;
        i = j + 2; out.push(" "); continue;
      }
      out.push(ch); i++;
    }
    return out.join("");
  }

  function s3_classifyHeader(action, proto) {
    var p = proto.toLowerCase();
    if (p === "file_id") return "file_id";
    if (p === "file") return "file";
    if (S3_L34_PROTOS.indexOf(p) >= 0) return "classic";
    return "service";
  }

  function s3_parseOneOption(token) {
    var ci = token.indexOf(":");
    if (ci >= 0) {
      return makeOption(token.substr(0, ci).trim(), token.substr(ci + 1).trim(), token);
    }
    return makeOption(token.trim(), null, token);
  }

  function s3_splitOptions(body) {
    var options = [], errors = [];
    var i = 0, n = body.length, cur = [];
    var in_quote = false, in_line_comment = false;
    while (i < n) {
      var ch = body.charAt(i);
      if (in_line_comment) {
        if (ch === ";") { in_line_comment = false; cur = []; }
        i++; continue;
      }
      if (ch === "\\" && i + 1 < n) { cur.push(ch, body.charAt(i + 1)); i += 2; continue; }
      if (ch === '"') { in_quote = !in_quote; cur.push(ch); i++; continue; }
      if (!in_quote && ch === "#" && cur.join("").trim() === "") {
        in_line_comment = true; i++; continue;
      }
      if (ch === ";" && !in_quote) {
        var tok = cur.join("").trim();
        if (tok) options.push(s3_parseOneOption(tok));
        cur = []; i++; continue;
      }
      cur.push(ch); i++;
    }
    var leftover = cur.join("").trim();
    if (leftover) errors.push("trailing option without ';': " + leftover);
    if (in_quote) errors.push("unterminated quoted string in options");
    return { options: options, errors: errors };
  }

  function s3_depthDelta(s, in_quote_in) {
    var d = 0, q = in_quote_in, i = 0;
    while (i < s.length) {
      var ch = s.charAt(i);
      if (ch === "\\" && i + 1 < s.length) { i += 2; continue; }
      if (ch === '"') q = !q;
      else if (!q) { if (ch === "(") d++; else if (ch === ")") d--; }
      i++;
    }
    return { delta: d, quote: q };
  }

  function s3_joinContinuations(lines) {
    var out = [];
    var buf = [], start = 0, commented = false, in_quote = false;
    for (var idx = 0; idx < lines.length; idx++) {
      var raw = lines[idx];
      var lineno = idx + 1;
      var line = raw.replace(/\n$/, "");
      var stripped = line.replace(/^\s+/, "");
      if (buf.length === 0) {
        if (!stripped) continue;
        start = lineno;
        commented = stripped.charAt(0) === "#";
        if (commented) {
          var inner = stripped.replace(/^#+\s*/, "");
          var first = inner.split(/\s+/)[0].toLowerCase();
          if (S3_ACTIONS.indexOf(first) < 0 && S3_SPECIAL_PROTOS.indexOf(first) < 0) continue;
          line = inner;
        } else {
          line = stripped;
        }
      }
      if (line.charAt(line.length - 1) === "\\") {
        buf.push(line.substr(0, line.length - 1).replace(/\s+$/, ""));
        continue;
      }
      buf.push(line);
      var joined = buf.join(" ").trim();
      var dd = s3_depthDelta(joined, false);
      if (dd.delta <= 0 && !dd.quote) {
        out.push({ start: start, text: joined, commented: commented });
        buf = []; in_quote = false;
      } else {
        in_quote = dd.quote;
      }
    }
    if (buf.length) out.push({ start: start, text: buf.join(" ").trim(), commented: commented });
    return out;
  }

  function s3_buildRule(text, source, line, enabled, header, body_start) {
    var depth = 1, i = body_start, in_quote = false;
    while (i < text.length) {
      var ch = text.charAt(i);
      if (ch === "\\" && i + 1 < text.length) { i += 2; continue; }
      if (ch === '"') in_quote = !in_quote;
      else if (!in_quote) {
        if (ch === "(") depth++;
        else if (ch === ")") { depth--; if (depth === 0) break; }
      }
      i++;
    }
    if (depth !== 0) {
      var rb = makeRule(source, line, text, enabled, header, []);
      rb.parse_errors = ["unbalanced parentheses in rule body"];
      return rb;
    }
    var body = text.substr(body_start, i - body_start);
    var sp = s3_splitOptions(body);
    var r = makeRule(source, line, text, enabled, header, sp.options);
    r.parse_errors = sp.errors;
    return r;
  }

  function s3_parseRule(text, source, line, enabled) {
    text = s3_stripBlockComments(text);
    if (!text.trim()) return null;
    var m = S3_HEADER_CLASSIC_RE.exec(text);
    if (m && S3_L34_PROTOS.indexOf(m[2].toLowerCase()) >= 0) {
      var header = makeHeader(m[1].toLowerCase(), m[2].toLowerCase(),
                              m[3], m[4], m[5], m[6], m[7]);
      header.kind = "classic";
      return s3_buildRule(text, source, line, enabled, header, m[0].length);
    }
    var ms = S3_HEADER_SHORT_RE.exec(text);
    if (ms) {
      var action = (ms[1] || "alert").toLowerCase();
      var proto = ms[2].toLowerCase();
      var kind = s3_classifyHeader(action, proto);
      if (kind === "classic") {
        var rb = makeRule(source, line, text, enabled, null, []);
        rb.parse_errors = ["classic header missing src/port/dir/dst tokens at " + source + ":" + line];
        return rb;
      }
      var header2 = makeHeader(action, proto, "", "", "", "", "");
      header2.kind = kind;
      return s3_buildRule(text, source, line, enabled, header2, ms[0].length);
    }
    var first = (text.split(/\s+/)[0] || "").toLowerCase();
    if (S3_ACTIONS.indexOf(first) < 0 && S3_SPECIAL_PROTOS.indexOf(first) < 0) return null;
    var rb2 = makeRule(source, line, text, enabled, null, []);
    rb2.parse_errors = ["could not parse rule header at " + source + ":" + line];
    return rb2;
  }

  function s3_parseText(text, source) {
    source = source || "<string>";
    var rules = [];
    var lines = text.split(/\r?\n/);
    var joined = s3_joinContinuations(lines);
    for (var i = 0; i < joined.length; i++) {
      var rec = joined[i];
      var r = s3_parseRule(rec.text, source, rec.start, !rec.commented);
      if (r) rules.push(r);
    }
    return rules;
  }

  // Stub registry — populated by chunks below
  // ============================================================
  // SNORT 3 VALIDATOR (S001..S025)
  // ============================================================
  var S3_DEFAULT_CLASSTYPES = S2_DEFAULT_CLASSTYPES;
  var S3_STICKY_BUFFERS = [
    "http_uri","http_raw_uri","http_header","http_raw_header","http_cookie",
    "http_raw_cookie","http_method","http_client_body","http_raw_body",
    "http_stat_code","http_stat_msg","http_true_ip","http_version",
    "http_trailer","http_raw_trailer","http_param","http_raw_request",
    "http_raw_status","file_data","pkt_data","raw_data","js_data","vba_data",
    "base64_data","sip_method","sip_header","sip_body","sip_stat_code",
    "ssl_state","ssl_version","dce_iface","dce_opnum","dce_stub_data"
  ];
  var S3_CURSOR_REL = ["distance","within"];
  var S3_CURSOR_ABS = ["depth","offset"];
  var S3_REMOVED_OPTIONS = {
    "uricontent": "use sticky buffer `http_uri;` then `content:\"...\";`",
    "rem":        "use C-style `/* ... */` comments inside the rule body",
    "threshold":  "use `event_filter` (threshold.lua) or `detection_filter:` per-rule",
    "activates":  "removed; use flowbits or rule chaining via `flowbits:set,...`",
    "activated_by": "removed; use flowbits / detection_filter",
    "logto":      "removed; use output plugins / log-to-file in snort.lua"
  };
  var S3_INVALID_PCRE_FLAGS = "UIPHDMCKSYBO";

  function s3_validate(rules) {
    var findings = [];
    var seen_sids = {};
    for (var ri = 0; ri < rules.length; ri++) {
      var r = rules[ri];
      if (r.parse_errors && r.parse_errors.length) {
        for (var pe = 0; pe < r.parse_errors.length; pe++) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S001", "error",
            "parse error: " + r.parse_errors[pe], "rules/intro"));
        }
        if (!r.header) continue;
      }
      if (!r.header) continue;
      var opt_names = r.options.map(function (o) { return o.name; });
      var sid_opt = r.opt("sid");
      var sid_val = sid_opt && sid_opt.value && sid_opt.value.trim();
      if (!sid_opt || !sid_val || !/^\d+$/.test(sid_val)) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S002", "error",
          "rule missing required `sid`", "rules/options/general/sid",
          "add `sid:<int>;` (>= 1000000 for local rules)"));
      } else {
        var sid = parseInt(sid_val, 10);
        if (sid < 1000000 && r.file && r.file.toLowerCase().indexOf("local") >= 0) {
          findings.push(makeFinding(r.file, r.line, sid, "S006", "error",
            "local rule uses reserved sid " + sid + " (< 1000000)",
            "rules/options/general/sid", "use sid >= 1000000 for user/local rules"));
        }
        if (seen_sids[sid]) {
          findings.push(makeFinding(r.file, r.line, sid, "S007", "warn",
            "duplicate sid " + sid + " (previously at " + seen_sids[sid].file + ":" + seen_sids[sid].line + ")",
            "rules/options/general/sid"));
        } else {
          seen_sids[sid] = { file: r.file, line: r.line };
        }
      }
      if (!r.opt("rev")) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S003", "warn",
          "rule missing `rev`", "rules/options/general/rev", "add `rev:1;`"));
      }
      if (!r.opt("msg")) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S004", "warn",
          "rule missing `msg`", "rules/options/general/msg", "add `msg:\"...\";`"));
      }
      var ct = r.opt("classtype");
      if (!ct) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S005", "warn",
          "rule missing `classtype`", "rules/options/general/classtype"));
      } else {
        var ctval = (ct.value || "").trim();
        if (ctval && S3_DEFAULT_CLASSTYPES.indexOf(ctval) < 0) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S016", "error",
            "unknown classtype `" + ctval + "`", "rules/options/general/classtype",
            "use a standard classtype or add `" + ctval + "` to classification.config"));
        }
      }
      var has_match = opt_names.indexOf("content") >= 0 ||
                      opt_names.indexOf("pcre") >= 0 ||
                      opt_names.indexOf("regex") >= 0;
      if (!has_match) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S008", "warn",
          "rule has no content/pcre/regex — evaluated against every packet",
          "rules/options/payload",
          "add a literal `content:\"...\";` to leverage fast-pattern matching"));
      }
      var contents_idx = [], pcres_idx = [];
      for (var i = 0; i < opt_names.length; i++) {
        if (opt_names[i] === "content") contents_idx.push(i);
        if (opt_names[i] === "pcre" || opt_names[i] === "regex") pcres_idx.push(i);
      }
      if (contents_idx.length && pcres_idx.length && pcres_idx[0] < contents_idx[0]) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S009", "info",
          "pcre/regex precedes content — cheap-first ordering violated",
          "rules/options/payload/pcre",
          "move `content:` before `pcre:` so fast-pattern filters first"));
      }
      var contents = r.opts("content");
      if (contents.length) {
        var fp_marked = [];
        for (var fi = 0; fi < opt_names.length; fi++) {
          if (opt_names[fi] === "fast_pattern") {
            for (var k = fi - 1; k >= 0; k--) {
              if (opt_names[k] === "content") { fp_marked.push(k); break; }
              if (S3_STICKY_BUFFERS.indexOf(opt_names[k]) >= 0) break;
            }
          }
        }
        if (contents.length > 1 && !fp_marked.length) {
          var shortest = Infinity, longest = 0;
          for (var ci = 0; ci < contents.length; ci++) {
            var L = contentLength(contents[ci].value);
            if (L < shortest) shortest = L;
            if (L > longest) longest = L;
          }
          if (longest > shortest * 2 && shortest < 4) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S010", "warn",
              "multiple contents, no explicit `fast_pattern` (shortest=" + shortest + "B, longest=" + longest + "B)",
              "rules/options/payload/fast_pattern",
              "mark the longest unique content with `fast_pattern;`"));
          }
        }
        for (var fk = 0; fk < fp_marked.length; fk++) {
          var marked = r.options[fp_marked[fk]];
          if (contentLength(marked.value) < 4) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S011", "warn",
              "`fast_pattern` content is < 4 bytes (" + marked.value + ") — weak",
              "rules/options/payload/fast_pattern",
              "pick a longer, more unique content"));
          }
        }
      }
      for (var oi = 0; oi < r.options.length; oi++) {
        var opt = r.options[oi];
        if (S3_CURSOR_ABS.indexOf(opt.name) >= 0 || S3_CURSOR_REL.indexOf(opt.name) >= 0) {
          var v = (opt.value || "").trim();
          if (!/^-?\d+$/.test(v)) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S012", "error",
              "`" + opt.name + "` value `" + v + "` is not numeric", "rules/options/payload"));
          }
          if (S3_CURSOR_REL.indexOf(opt.name) >= 0) {
            var anchor = false;
            for (var ai = 0; ai < oi; ai++) {
              if (opt_names[ai] === "content" || S3_STICKY_BUFFERS.indexOf(opt_names[ai]) >= 0) {
                anchor = true; break;
              }
            }
            if (!anchor) {
              findings.push(makeFinding(r.file, r.line, r.sid(), "S013", "error",
                "`" + opt.name + "` has no preceding content/sticky-buffer to anchor to",
                "rules/options/payload"));
            }
          }
        }
        if (opt.name === "nocase") {
          var has_prev_content = false;
          for (var nci = 0; nci < oi; nci++) {
            if (opt_names[nci] === "content") { has_prev_content = true; break; }
          }
          if (!has_prev_content) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S014", "warn",
              "`nocase` placed before any `content` — modifies nothing",
              "rules/options/payload/content"));
          }
        }
        if (S3_REMOVED_OPTIONS[opt.name]) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S015", "error",
            "removed/deprecated rule option `" + opt.name + "` is not valid in Snort 3",
            "rules/migrating", S3_REMOVED_OPTIONS[opt.name]));
        }
      }
      if (r.header.proto === "tcp" && !r.opt("flow") && has_match) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S017", "warn",
          "TCP rule without `flow` — direction/state ambiguous",
          "rules/options/non-payload/flow", "add `flow:established,to_server;`"));
      }
      if (r.header.kind === "classic" &&
          r.header.src_ip === "any" && r.header.dst_ip === "any" &&
          r.header.src_port === "any" && r.header.dst_port === "any") {
        var lng = 0;
        for (var lci = 0; lci < contents.length; lci++) lng = Math.max(lng, contentLength(contents[lci].value));
        if (lng < 6) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S019", "info",
            "any/any header with weak content (max " + lng + "B) — expensive to evaluate",
            "rules/headers", "restrict to $HOME_NET / specific ports if possible"));
        }
      }
      var pcres = r.opts("pcre");
      for (var pi = 0; pi < pcres.length; pi++) {
        var pv = (pcres[pi].value || "").trim().replace(/^"|"$/g, "");
        var mr = /^\/(.*)\/([A-Za-z]*)$/.exec(pv);
        if (!mr) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S020", "error",
            "pcre value not in `/.../flags` form: " + pv, "rules/options/payload/pcre"));
          continue;
        }
        try { new RegExp(mr[1]); }
        catch (e) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S020", "error",
            "pcre fails to compile: " + e.message, "rules/options/payload/pcre"));
        }
        var bad = "";
        for (var bf = 0; bf < mr[2].length; bf++) {
          if (S3_INVALID_PCRE_FLAGS.indexOf(mr[2].charAt(bf)) >= 0) bad += mr[2].charAt(bf);
        }
        if (bad) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S021", "error",
            "pcre uses Snort-2-only flags `" + bad + "` (use sticky buffers in Snort 3)",
            "rules/migrating",
            "drop the flag and place the matching sticky buffer (e.g. `http_uri;`) before the pcre"));
        }
      }
      if (r.header.kind === "service") {
        var md_service = r.opt("service");
        var md_meta = r.opt("metadata");
        var declared = !!md_service ||
          (md_meta && md_meta.value && md_meta.value.indexOf("service") >= 0);
        if (!declared) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S022", "warn",
            "service rule (`" + r.header.proto + "`) without `service:` or `metadata: service <name>;`",
            "rules/headers", "add `service:" + r.header.proto + ";`"));
        }
        if (S3_SERVICES.indexOf(r.header.proto) < 0) {
          findings.push(makeFinding(r.file, r.line, r.sid(), "S023", "info",
            "service `" + r.header.proto + "` not in known service list — verify it matches a configured inspector",
            "rules/headers"));
        }
      }
      var last_sticky = -1, last_sticky_name = "", sticky_used = true;
      for (var si = 0; si < opt_names.length; si++) {
        var nm = opt_names[si];
        if (S3_STICKY_BUFFERS.indexOf(nm) >= 0) {
          if (last_sticky >= 0 && !sticky_used) {
            findings.push(makeFinding(r.file, r.line, r.sid(), "S024", "warn",
              "sticky buffer `" + last_sticky_name + "` set but no content/pcre/regex follows before next buffer",
              "rules/options/payload"));
          }
          last_sticky = si; last_sticky_name = nm; sticky_used = false;
        } else if (nm === "content" || nm === "pcre" || nm === "regex") {
          sticky_used = true;
        }
      }
      if (last_sticky >= 0 && !sticky_used) {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S024", "warn",
          "trailing sticky buffer `" + last_sticky_name + "` has no content/pcre/regex after it",
          "rules/options/payload"));
      }
      if (opt_names.indexOf("file_data") >= 0 && r.header.kind === "classic") {
        findings.push(makeFinding(r.file, r.line, r.sid(), "S025", "info",
          "`file_data` used in classic header rule — usually paired with HTTP/SMTP/IMAP/POP3/FTP service rule",
          "rules/options/payload/file_data",
          "convert to a service rule (e.g. `alert http (...)`)"));
      }
    }
    return findings;
  }

  // ===== SNORT 3 OPTIMIZER =====
  var S3_SERVICE_TO_DEFAULT_BUFFER = {
    "http": "http_uri", "http2": "http_uri",
    "smtp": "file_data", "imap": "file_data", "pop3": "file_data",
    "ftp": "file_data", "ftp-data": "file_data"
  };

  function s3_costScore(r) {
    if (!r.header) return 0;
    var opt_names = r.options.map(function(o){ return o.name; });
    var contents = r.opts("content");
    var has_pcre = opt_names.indexOf("pcre") >= 0 || opt_names.indexOf("regex") >= 0;
    var contents_idx = [];
    for (var i = 0; i < opt_names.length; i++) if (opt_names[i] === "content") contents_idx.push(i);
    var has_fp = false;
    for (var k = 0; k < contents_idx.length; k++) {
      var ci = contents_idx[k];
      if (opt_names.slice(ci + 1, ci + 8).indexOf("fast_pattern") >= 0) { has_fp = true; break; }
    }
    var classic_any = (r.header.kind === "classic"
      && r.header.src_ip === "any" && r.header.dst_ip === "any"
      && r.header.src_port === "any" && r.header.dst_port === "any");
    var no_flow = r.header.proto === "tcp" && r.opt("flow") === null;
    var longest = 0;
    for (var c = 0; c < contents.length; c++) {
      var L = contentLength(contents[c].value);
      if (L > longest) longest = L;
    }
    var short_fp = has_fp && longest < 4;
    var content_after_pcre = false;
    if (has_pcre && contents_idx.length) {
      var first_pcre = -1;
      for (var p = 0; p < opt_names.length; p++) {
        if (opt_names[p] === "pcre" || opt_names[p] === "regex") { first_pcre = p; break; }
      }
      if (first_pcre >= 0) {
        for (var q = 0; q < contents_idx.length; q++) {
          if (contents_idx[q] > first_pcre) { content_after_pcre = true; break; }
        }
      }
    }
    var no_classtype = r.opt("classtype") === null;
    var meta = r.opt("metadata");
    var no_service = (r.header.kind === "service"
      && r.opt("service") === null
      && !(meta && meta.value && meta.value.indexOf("service") >= 0));
    var invalid_pcre_flag = false;
    var pcres = r.opts("pcre");
    for (var pi = 0; pi < pcres.length; pi++) {
      var v = (pcres[pi].value || "").trim().replace(/^"|"$/g, "");
      if (v.indexOf("/") >= 0 && !v.endsWith("/")) {
        var tail = v.split("/").pop();
        for (var ti = 0; ti < tail.length; ti++) {
          if (S3_INVALID_PCRE_FLAGS[tail[ti]]) { invalid_pcre_flag = true; break; }
        }
        if (invalid_pcre_flag) break;
      }
    }
    var has_sticky = false;
    for (var si = 0; si < opt_names.length; si++) {
      if (S3_STICKY_BUFFERS.indexOf(opt_names[si]) >= 0) { has_sticky = true; break; }
    }
    var raw_content_in_service = (r.header.kind === "service" && contents.length > 0 && !has_sticky);
    return (10 * (has_pcre ? 1 : 0)
      + 6 * (invalid_pcre_flag ? 1 : 0)
      + 5 * (!has_fp ? 1 : 0)
      + 5 * (classic_any ? 1 : 0)
      + 4 * (no_flow ? 1 : 0)
      + 4 * (no_service ? 1 : 0)
      + 4 * (raw_content_in_service ? 1 : 0)
      + 3 * (short_fp ? 1 : 0)
      + 2 * (content_after_pcre ? 1 : 0)
      + 1 * (no_classtype ? 1 : 0));
  }

  function s3_optimize(rules) {
    var out = [];
    for (var ri = 0; ri < rules.length; ri++) {
      var r = rules[ri];
      if (!r.header) continue;
      var opt_names = r.options.map(function(o){ return o.name; });
      var contents = r.opts("content");
      var contents_idx = [];
      for (var i = 0; i < opt_names.length; i++) if (opt_names[i] === "content") contents_idx.push(i);

      // O001: longest content as fast_pattern
      var has_fp = false;
      for (var k = 0; k < contents_idx.length; k++) {
        var ci = contents_idx[k];
        if (opt_names.slice(ci + 1, ci + 8).indexOf("fast_pattern") >= 0) { has_fp = true; break; }
      }
      if (contents.length > 1 && !has_fp) {
        var longest_len = 0, longest_c = null;
        for (var c = 0; c < contents.length; c++) {
          var L = contentLength(contents[c].value);
          if (L > longest_len) { longest_len = L; longest_c = contents[c]; }
        }
        if (longest_c) {
          out.push(makeFinding(r.file, r.line, r.sid(), "O001", "info",
            "set fast_pattern on the longest content (" + longest_len + "B)",
            "rules/options/payload/fast_pattern",
            "after `content:" + longest_c.value + ";` add `fast_pattern;`"));
        }
      }

      // O002: content before pcre/regex
      var has_pcre = opt_names.indexOf("pcre") >= 0 || opt_names.indexOf("regex") >= 0;
      if (has_pcre && contents_idx.length) {
        var first_re = -1;
        for (var p = 0; p < opt_names.length; p++) {
          if (opt_names[p] === "pcre" || opt_names[p] === "regex") { first_re = p; break; }
        }
        var late = false;
        for (var q = 0; q < contents_idx.length; q++) if (contents_idx[q] > first_re) { late = true; break; }
        if (late) {
          out.push(makeFinding(r.file, r.line, r.sid(), "O002", "info",
            "reorder so all content checks precede pcre/regex",
            "rules/options/payload/pcre",
            "literal `content:` is dramatically cheaper than `pcre:`"));
        }
      }

      // O003: flow on TCP classic
      if (r.header.kind === "classic" && r.header.proto === "tcp" && r.opt("flow") === null) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O003", "info",
          "add `flow:established,to_server;` (or to_client)",
          "rules/options/non-payload/flow",
          "lets Snort skip rules on the wrong direction / unestablished flows"));
      }

      // O004: tighten any/any
      if (r.header.kind === "classic" && r.header.src_ip === "any" && r.header.dst_ip === "any") {
        out.push(makeFinding(r.file, r.line, r.sid(), "O004", "info",
          "header uses any/any — restrict to $HOME_NET / specific ports if possible",
          "rules/headers", null));
      }

      // O005: prefer service rules over classic+ports for app-layer
      var appPorts = {"80":1,"443":1,"25":1,"21":1,"110":1,"143":1};
      var hasAppOpt = false;
      var appOpts = ["http_uri","http_header","http_client_body","file_data","pkt_data"];
      for (var ao = 0; ao < appOpts.length; ao++) if (opt_names.indexOf(appOpts[ao]) >= 0) { hasAppOpt = true; break; }
      if (r.header.kind === "classic" && r.header.proto === "tcp"
          && appPorts[r.header.dst_port] && !hasAppOpt && contents.length > 0) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O005", "info",
          "classic TCP rule on port " + r.header.dst_port + " with raw content — consider a service rule + sticky buffer",
          "rules/migrating",
          "rewrite as `alert http (...)` and add `http_uri;` / `file_data;`"));
      }

      // O006: deprecated threshold
      if (r.opt("threshold") !== null) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O006", "warn",
          "replace deprecated `threshold:` with `event_filter` / `detection_filter:`",
          "rules/migrating",
          "see references/deprecations_vs_snort2.md for the migration table"));
      }

      // O007: service rule without explicit binding
      if (r.header.kind === "service") {
        var md_service = r.opt("service");
        var md_meta = r.opt("metadata");
        var declared = md_service !== null
          || (md_meta && md_meta.value && md_meta.value.indexOf("service") >= 0);
        if (!declared) {
          out.push(makeFinding(r.file, r.line, r.sid(), "O007", "warn",
            "service rule (`" + r.header.proto + "`) lacks explicit service binding",
            "rules/headers",
            "add `service:" + r.header.proto + ";`"));
        }
      }

      // O008: service rule using raw content w/o sticky buffer
      var has_sticky = false;
      for (var sk = 0; sk < opt_names.length; sk++) if (S3_STICKY_BUFFERS.indexOf(opt_names[sk]) >= 0) { has_sticky = true; break; }
      if (r.header.kind === "service" && contents.length > 0 && !has_sticky) {
        var sticky = S3_SERVICE_TO_DEFAULT_BUFFER[r.header.proto];
        var msg = "service `" + r.header.proto + "` uses raw content with no sticky buffer — inspector cursor defaults to `pkt_data`";
        var sug = sticky
          ? "prepend `" + sticky + ";` before the first `content:`"
          : "prepend the appropriate sticky buffer (http_uri, http_header, file_data, ...) before content";
        out.push(makeFinding(r.file, r.line, r.sid(), "O008", "info", msg, "rules/options/payload", sug));
      }

      // O009: pcre with Snort-2-only buffer flags
      var pcres = r.opts("pcre");
      for (var pi = 0; pi < pcres.length; pi++) {
        var v = (pcres[pi].value || "").trim().replace(/^"|"$/g, "");
        if (v.indexOf("/") >= 0) {
          var tail = v.split("/").pop();
          var bad = [];
          for (var ti = 0; ti < tail.length; ti++) {
            if (S3_INVALID_PCRE_FLAGS[tail[ti]] && bad.indexOf(tail[ti]) < 0) bad.push(tail[ti]);
          }
          if (bad.length) {
            bad.sort();
            out.push(makeFinding(r.file, r.line, r.sid(), "O009", "warn",
              "pcre uses Snort-2 buffer flag(s) `" + bad.join("") + "` — migrate to sticky buffer",
              "rules/migrating",
              "drop the flag and place e.g. `http_uri;` or `http_header;` before the pcre"));
          }
        }
      }

      // O010: cost score badge
      var score = s3_costScore(r);
      if (score >= 15) {
        out.push(makeFinding(r.file, r.line, r.sid(), "O010", "warn",
          "rule cost score = " + score + " (>=15 considered expensive)",
          "rules/options/payload",
          "apply O001..O008 to reduce score"));
      }
    }
    return out;
  }

  function dispatchParse(text, version, source) {
    return version === 3 ? s3_parseText(text, source) : s2_parseText(text, source);
  }
  function dispatchValidate(rules, version) {
    return version === 3 ? s3_validate(rules) : s2_validate(rules);
  }
  function dispatchOptimize(rules, version) {
    return version === 3 ? s3_optimize(rules) : s2_optimize(rules);
  }

  function severityClass(s) {
    return ({ error: "sv-err", warn: "sv-warn", info: "sv-info" })[s] || "sv-info";
  }

  function renderFindings(findings, container, opts) {
    opts = opts || {};
    if (!container) return;
    if (!findings.length) {
      container.innerHTML = '<div class="snortval-empty">No findings.</div>';
      return;
    }
    var by_sev = { error: [], warn: [], info: [] };
    for (var i = 0; i < findings.length; i++) {
      (by_sev[findings[i].severity] || by_sev.info).push(findings[i]);
    }
    var html = ['<div class="snortval-summary">',
      '<span class="sv-badge sv-err">errors: ' + by_sev.error.length + '</span> ',
      '<span class="sv-badge sv-warn">warnings: ' + by_sev.warn.length + '</span> ',
      '<span class="sv-badge sv-info">info: ' + by_sev.info.length + '</span>',
      '</div><table class="snortval-tbl"><thead><tr>',
      '<th>Sev</th><th>SID</th><th>Line</th><th>Check</th><th>Message</th><th>Ref</th>',
      '</tr></thead><tbody>'];
    function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    }); }
    var order = ["error", "warn", "info"];
    for (var oi = 0; oi < order.length; oi++) {
      var arr = by_sev[order[oi]];
      for (var fi = 0; fi < arr.length; fi++) {
        var f = arr[fi];
        html.push('<tr class="' + severityClass(f.severity) + '">',
          '<td>' + esc(f.severity) + '</td>',
          '<td>' + esc(f.sid == null ? "-" : f.sid) + '</td>',
          '<td>' + esc(f.line) + '</td>',
          '<td>' + esc(f.check_id) + '</td>',
          '<td>' + esc(f.message) + (f.suggestion ? '<div class="sv-sug">→ ' + esc(f.suggestion) + '</div>' : '') + '</td>',
          '<td>' + esc(f.manual_ref || "") + '</td>',
          '</tr>');
      }
    }
    html.push('</tbody></table>');
    container.innerHTML = html.join("");
  }

  var SnortValidator = {
    parse: dispatchParse,
    validate: dispatchValidate,
    optimize: dispatchOptimize,
    render: renderFindings,
    _: {
      makeOption: makeOption, makeHeader: makeHeader, makeRule: makeRule,
      makeFinding: makeFinding, contentLength: contentLength, isDigit: isDigit,
      s2_parseText: s2_parseText, s2_validate: s2_validate, s2_optimize: s2_optimize,
      s3_parseText: s3_parseText, s3_validate: s3_validate, s3_optimize: s3_optimize
    }
  };

  global.SnortValidator = SnortValidator;
})(window);
