/* rrd-parser.js
 *
 * Pure-JS parser for RRDtool v3 binary databases (little-endian, 64-bit
 * platform, 8-byte aligned). Targets the .rrd files Cisco FTD ships in
 * troubleshoot bundles under /var/sf/time_series/.
 *
 * Layout (offsets in bytes for the FTD layout we care about):
 *   0x000  stat_head_t   128 bytes  magic "RRD\0", version "0003\0",
 *                                   float_cookie, ds_cnt, rra_cnt, pdp_step
 *   0x080  ds_def_t      120 bytes  per DS:  name[20] + type[20] + 10*unival
 *   ...    rra_def_t     120 bytes  per RRA: cf_nam[20] + row_cnt(u64)
 *                                            + pdp_per_row(u64) + 10*unival
 *   ...    live_head_t    16 bytes  last_up(u64) + last_up_usec(u64)
 *   ...    pdp_prep_t     80 bytes  per DS: last_ds[30] + 10*unival(2 pad bytes)
 *   ...    cdp_prep_t     80 bytes  per (DS x RRA): 10*unival
 *   ...    rra_ptr_t       8 bytes  per RRA: cur_row(u64)
 *   ...    row data              for each RRA: rows * ds_cnt * 8 bytes (double)
 *
 * `unival` is an 8-byte union (u64 / double / etc).  We treat it as either
 * depending on context.  All multi-byte ints are little-endian; doubles are
 * IEEE-754 little-endian.  NaN sentinel = 0x7FF8000000000000 (== JS NaN).
 *
 * We only support the subset Cisco emits:
 *   - version "0003"
 *   - 1 DS per file (SINGLE_DS, GAUGE)
 *   - 12 RRAs (MIN/MAX/AVG x 4 windows)
 *   - little-endian, 8-byte alignment
 *
 * Parser is lenient: unknown CF strings pass through, extra params ignored.
 */
(function (root) {
  'use strict';

  var STAT_HEAD_SIZE = 128;
  var DS_DEF_SIZE    = 120;
  var RRA_DEF_SIZE   = 120;
  var LIVE_HEAD_SIZE = 16;
  var PDP_PREP_SIZE  = 112;
  var CDP_PREP_SIZE  = 80;
  var RRA_PTR_SIZE   = 8;
  var DOUBLE_SIZE    = 8;

  function readCStr(view, off, maxLen) {
    var bytes = [];
    for (var i = 0; i < maxLen; i++) {
      var b = view.getUint8(off + i);
      if (b === 0) break;
      bytes.push(b);
    }
    return String.fromCharCode.apply(null, bytes);
  }

  function readU64(view, off) {
    // RRD never exceeds 2^53, safe to coerce via two reads
    var lo = view.getUint32(off, true);
    var hi = view.getUint32(off + 4, true);
    return hi * 0x100000000 + lo;
  }

  function readDouble(view, off) {
    return view.getFloat64(off, true);
  }

  /**
   * Parse an RRDtool v3 binary file.
   *
   * @param {ArrayBuffer} buffer  Raw .rrd file contents
   * @returns {Object} {
   *   version, step, lastUpdate (unix seconds),
   *   ds: [{name, type, lastDS}],
   *   rras: [{cf, pdpPerRow, rows, curRow, step (seconds), data: Float64Array}]
   * }
   * `data` is row-major DS-major; for single DS we expose it directly.
   * Each row's timestamp is computed as:
   *   ts(i) = baseTs - (rows - 1 - relIdx) * step
   * where relIdx walks the ring buffer starting at curRow+1 (oldest).
   */
  function parseRRD(buffer) {
    if (!(buffer instanceof ArrayBuffer)) {
      throw new Error('parseRRD: expected ArrayBuffer');
    }
    if (buffer.byteLength < STAT_HEAD_SIZE) {
      throw new Error('parseRRD: buffer too small');
    }
    var view = new DataView(buffer);

    var magic = readCStr(view, 0, 4);
    if (magic !== 'RRD') throw new Error('parseRRD: not an RRD file (magic=' + magic + ')');
    var version = readCStr(view, 4, 5);
    if (version !== '0003') {
      throw new Error('parseRRD: only v3 supported (got ' + version + ')');
    }
    // float_cookie at 0x10 (skip — only used for endianness check)
    var dsCnt    = readU64(view, 0x18);
    var rraCnt   = readU64(view, 0x20);
    var pdpStep  = readU64(view, 0x28);
    // par[10] follows but unused by us (offsets 0x30..0x7F)

    var off = STAT_HEAD_SIZE;

    // --- ds_def[] ---
    var ds = [];
    for (var i = 0; i < dsCnt; i++) {
      var dsName = readCStr(view, off, 20);
      var dsType = readCStr(view, off + 20, 20);
      ds.push({ name: dsName, type: dsType, lastDS: null });
      off += DS_DEF_SIZE;
    }

    // --- rra_def[] ---
    var rras = [];
    for (var r = 0; r < rraCnt; r++) {
      var cf = readCStr(view, off, 20);
      var rowCnt    = readU64(view, off + 24);
      var pdpPerRow = readU64(view, off + 32);
      rras.push({
        cf: cf,
        rows: rowCnt,
        pdpPerRow: pdpPerRow,
        step: pdpPerRow * pdpStep,
        curRow: 0,
        data: null
      });
      off += RRA_DEF_SIZE;
    }

    // --- live_head ---
    var lastUpdate = readU64(view, off);
    // last_up_usec at off+8 (ignored)
    off += LIVE_HEAD_SIZE;

    // --- pdp_prep[ds_cnt] ---
    for (var p = 0; p < dsCnt; p++) {
      ds[p].lastDS = readCStr(view, off, 30);
      off += PDP_PREP_SIZE;
    }

    // --- cdp_prep[ds_cnt * rra_cnt] ---
    off += dsCnt * rraCnt * CDP_PREP_SIZE;

    // --- rra_ptr[rra_cnt] ---
    for (var rr = 0; rr < rraCnt; rr++) {
      rras[rr].curRow = readU64(view, off);
      off += RRA_PTR_SIZE;
    }

    // --- row data per RRA ---
    for (var rrIdx = 0; rrIdx < rraCnt; rrIdx++) {
      var rra = rras[rrIdx];
      var nDoubles = rra.rows * dsCnt;
      var bytesNeeded = nDoubles * DOUBLE_SIZE;
      if (off + bytesNeeded > buffer.byteLength) {
        throw new Error(
          'parseRRD: truncated row data at RRA ' + rrIdx +
          ' (need ' + bytesNeeded + ' bytes, have ' +
          (buffer.byteLength - off) + ')'
        );
      }
      // Slice into a fresh Float64Array (copy — DataView reads handle endianness
      // explicitly but TypedArray construction respects host endianness only).
      var arr = new Float64Array(nDoubles);
      for (var k = 0; k < nDoubles; k++) {
        arr[k] = readDouble(view, off + k * DOUBLE_SIZE);
      }
      rra.data = arr;
      off += bytesNeeded;
    }

    return {
      version: version,
      step: pdpStep,
      lastUpdate: lastUpdate,
      ds: ds,
      rras: rras
    };
  }

  /**
   * Materialize one RRA as an ordered [{ts, val}] series, oldest first.
   *
   * Replicates `rrdtool fetch <CF> -e <lastUpdate> -s <lastUpdate - rows*step>`
   * behaviour: ring-buffer rotation + per-bucket timestamp = floor((bucketStart)/step)*step + step.
   *
   * For multi-DS files, pass dsIndex (default 0).
   */
  function rraToSeries(rrd, rraIndex, dsIndex) {
    if (dsIndex == null) dsIndex = 0;
    var rra = rrd.rras[rraIndex];
    if (!rra) throw new Error('rraToSeries: no such RRA ' + rraIndex);
    var dsCnt = rrd.ds.length;
    var step  = rra.step;
    var rows  = rra.rows;

    // Bucket end of newest sample = floor(lastUpdate / step) * step
    var newestEnd = Math.floor(rrd.lastUpdate / step) * step;
    var oldestStart = newestEnd - (rows - 1) * step;

    // Ring buffer: oldest sample lives at index (curRow + 1) % rows
    var startIdx = (rra.curRow + 1) % rows;
    var out = new Array(rows);
    for (var i = 0; i < rows; i++) {
      var ringIdx = (startIdx + i) % rows;
      var v = rra.data[ringIdx * dsCnt + dsIndex];
      out[i] = { ts: oldestStart + i * step, val: v };
    }
    return out;
  }

  /**
   * Pick RRA indices for the canonical FTD 4-window setup
   * (12 RRAs: 4 windows x [MIN, MAX, AVG]).
   *
   * Returns indices keyed by 'daily'/'weekly'/'monthly'/'yearly', each with
   * {min, max, avg} index references.  Falls back to nearest-step match if
   * the file doesn't follow the exact 4-window pattern.
   */
  function classifyRRAs(rrd) {
    // Group RRAs by (step, cf)
    var byStep = {};
    rrd.rras.forEach(function (rra, idx) {
      var k = rra.step;
      if (!byStep[k]) byStep[k] = {};
      byStep[k][rra.cf] = idx;
    });
    var steps = Object.keys(byStep).map(Number).sort(function (a, b) { return a - b; });

    // Map shortest → daily, then weekly, monthly, yearly
    var labels = ['daily', 'weekly', 'monthly', 'yearly'];
    var out = {};
    for (var i = 0; i < steps.length && i < labels.length; i++) {
      out[labels[i]] = {
        step: steps[i],
        min: byStep[steps[i]].MIN,
        max: byStep[steps[i]].MAX,
        avg: byStep[steps[i]].AVERAGE
      };
    }
    return out;
  }

  var api = {
    parseRRD: parseRRD,
    rraToSeries: rraToSeries,
    classifyRRAs: classifyRRAs
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.RRDParser = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
