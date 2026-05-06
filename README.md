# Snort 2 → Snort 3 Local Rule Converter

A single-file browser app for working with Cisco Secure Firewall (FTD / Firepower)
**Snort rule sets** and **troubleshoot bundles**. Everything runs **100% in the
browser** — no rules, no traffic, and no troubleshoot data ever leave your machine.

> Open `index.html` directly, or serve the folder with any static HTTP server.

---

## Features

The app is organized as a tabbed workspace. Each tab is self-contained and
operates entirely client-side.

| Tab | Purpose |
|---|---|
| 🏠 **Home** | Landing page, recent updates, and quick links. |
| ⚡ **Rule Optimization (Snort 2 / Snort 3)** | Lints, deduplicates, and rewrites local rules. Generates a downloadable HTML optimization report. |
| 🔀 **Rules Migration** | Converts Snort 2 rules to Snort 3 syntax (sticky-buffers, `pcre` flag rewrites, `threshold` → `detection_filter` / `event_filter`, `uricontent` → `http_uri`, action remaps, etc.) with side-by-side diff. |
| 🐍 **Python Validator** | In-browser static analyzer for Snort 3 rules with a Python-backed rule-engine view. |
| 🧬 **Search Duplicate Rules** | Detects duplicate / near-duplicate rules across pasted or uploaded rule sets. |
| 📥 **Download Files** | Bundled reference assets — Snort 2 / 3 manuals (EN / KR) and the FMC Snort 2 local-rules exporter script. |
| 🔄 **Snort 2 SRU Updates** | Browse the latest Cisco Snort 2 SRU update history. |
| 📋 **Snort 3 LSP Updates** | Browse the latest Cisco Snort 3 LSP update history. |
| 🔬 **Analysis TS File** | Drop in a Firepower troubleshoot bundle (`.tar.gz`) or a `show_tech_output.txt` and get a full health report (CPU, memory, block pools, conn / xlate, ASP drops, Snort statistics, per-interface stats). |
| 💬 **Feedback** | In-app feedback board. |
| 🔍 **Search Snort Rules** *(external link)* | Opens [snort.org rule docs search](https://www.snort.org/rule-docs-search). |
| 📊 **Performance Calculator** *(external link)* | Opens [Cisco NGFW Performance Estimator](https://ngfwpe.cisco.com). |

---

## 🔬 Analysis TS File — what it parses

The TS analyzer is a streaming, in-browser troubleshoot decoder. It accepts
either:

- A raw `show_tech_output.txt`, **or**
- A full `*-troubleshoot.tar.gz` bundle (any size — the file is streamed in
  8 MB chunks; gzip is decompressed in 1 MB pako chunks; the embedded TAR is
  walked entry-by-entry to locate `show_tech_output.txt` without ever holding
  the whole archive in memory).

Once the `show tech` text is in hand it is split by `==== ... ====` /
`---- show <command> ----` separators and each section is parsed into a
typed model:

- `show version` → device model, hardware, serial, software version, uptime
- `show cpu usage`, `show cpu detailed`
- `show memory`, `show memory detail`, **block pools** (`show blocks`)
- `show conn count`, `show xlate count`, conn / NAT growth
- `show traffic` — per-interface and aggregated bps / pps / avg packet size
- `show interface` — link, errors, drops, queue depth
- `show asp drop` — top drop reasons with severity
- `show snort statistics` / `show snort instances` — per-instance load, bypass

The renderer then produces a Cisco-branded health report with:

- A device summary card
- Severity-classified findings (Critical / Warning / Info) with thresholds:
  - CPU 5-min ≥ 90 % → Critical, ≥ 70 % → Warning
  - Memory ≥ 90 % → Critical, ≥ 80 % → Warning
  - ASP top drop reason > 10⁹ → Critical, > 10⁶ → Warning
  - Snort `bypassed (down)` > 0 → Critical, `bypassed (busy)` > 0 → Warning
- Collapsible per-section panels with raw values
- Toolbar: **Expand all / Collapse all / Print (Save as PDF)**

All rendering uses Chart.js + plain DOM — no server round-trips, no upload.

---

## Getting started

```bash
# Just open it
open index.html

# …or serve it (recommended so XHR / fetch and module loaders behave normally)
python3 -m http.server 8766
# then visit http://localhost:8766/
```

No build step. No `npm install`. The few external dependencies (pako, Chart.js,
icon font) load from public CDNs.

---

## Repository layout

```
snort-rule-converter-site/
├── index.html                          # The entire app (UI + most logic)
├── snort-logo.png                      # App icon
├── scripts/
│   ├── README.md
│   └── ts-analyzer/                    # Analysis TS File feature
│       ├── parser.js                   # tar.gz streaming + show-tech section parser
│       ├── renderer.js                 # health-report renderer (Chart.js)
│       └── app.js                      # drop-zone, file picker, progress wiring
└── Download_Files/                     # Assets surfaced by the Download Files tab
    ├── 20260426_002539_snort_2_rules_exporter_all.py
    ├── snort_2_manual.pdf
    ├── snort_2_manual_new_EN.pdf
    ├── snort_2_manual_new_KR.pdf
    └── snort_3_manual.pdf
```

---

## Privacy

- No telemetry.
- No upload, no fetch of user data.
- Rule text and troubleshoot bundles are read with the `File` API and parsed
  in-page; nothing is sent over the network.
- The only outbound requests are CDN fetches for `pako` and `Chart.js` (and
  the GFM-style icon font used by the UI).

---

## Browser support

Tested on current Chromium-based browsers and Safari. Requires:

- ES2020+ JavaScript
- `Blob.stream()` (for the TS analyzer streaming reader)
- `IntersectionObserver` (for tab-aware lazy init)

---

## License

Internal use. See repository owner for redistribution terms.
