# Snort 2 → Snort 3 Local Rule Converter

> **Site URL:** https://maxias13.github.io/snort-rule-converter/  
> **Site Owner:** Jungsub Shin (kaishin@cisco.com)  
> **Disclaimer:** All information provided on this site is not official information from Cisco Systems. Please use it with caution.

---

## Overview

A fully static, single-file web application (`index.html`) that helps network security engineers migrate Cisco Secure Firewall (formerly Firepower) local Snort 2 rules to Snort 3 format.  
No backend server required — hosted on GitHub Pages.

---

## Features

### 1. Home — Rule Converter
Converts Snort 2 local rules to Snort 3 syntax via a **4-pass conversion pipeline**.

#### Conversion Algorithm

**Pass 1 — Option-Level Keyword Transformation**

Each rule is parsed into a header and semicolon-delimited options (quote-aware, escape-aware tokenizer). The following transformations are applied per keyword:

| Snort 2 | Action | Snort 3 Result |
|---------|--------|----------------|
| `uricontent:"X"` | Split into sticky buffer + content | `http_uri; content:"X"` |
| `flowbits:set,name` | Converted to host-tracked xbits | `xbits:set,name,track ip_src` |
| `flowbits:noalert` | Standalone flag conversion | `noalert` |
| `flowbits:reset` | No Snort 3 equivalent | ⚠ removed + WARNING |
| `isdataat:N,rawbytes` | rawbytes sub-option stripped | `isdataat:N` |
| `file_data:mime` | Parameter stripped | `file_data` |
| `fast_pattern:only` | `:only` qualifier removed | `fast_pattern` |
| `metadata:service http` | service entries promoted | `service:http` |
| `sameip` | Renamed | `same_ip` |
| `rawbytes`, `threshold`, `resp`, `react`, `tag`, `activates`, `activated_by`, `logto`, `session`, `stream_reassemble`, `replace` | Removed in Snort 3 | ⚠ removed + WARNING |

**Pass 2 — Sticky Buffer Reordering**

In Snort 3, sticky buffer keywords (`http_uri`, `http_header`, etc.) must appear **before** their associated `content` option. This pass moves any out-of-order sticky buffers to the correct position.

**Pass 3 — PCRE HTTP Flag Conversion**

Snort 2 PCRE uses single-letter HTTP flags (e.g. `/pattern/Ui` for URI). Snort 3 replaces these with sticky buffers placed before the pcre option.

```
pcre:"/pattern/Ui"  →  http_uri; pcre:"/pattern/i"
```

**Pass 4 — Content Modifier Inlining**

In Snort 3, positional modifiers (`depth`, `within`, `offset`, `distance`, `nocase`, `fast_pattern`) must be inlined as comma-separated arguments inside the content option.

```
content:"X"; depth:20; nocase; distance:0;
→ content:"X", depth 20, nocase, distance 0;
```

**Final Steps**
- `gid`, `sid`, `rev` are always sorted to the end of the options in that order
- If a **Start SID** is specified, each rule's SID is remapped sequentially from that value
- Original → new SID mapping is persisted to `localStorage` for cross-session traceability

#### Additional Home Features
- **File drag & drop** — drag a `.rules` file directly onto the input area
- **Side-by-side diff view** — token-level diff highlighting between original and converted rules
- **Rule explanation panel** — per-rule breakdown of action, protocol, network, detection criteria, metadata
- **Download converted rules** — export as `.rules` file with FMC-compatible naming

---

### 2. Rule Optimization

Analyzes Snort 2 or Snort 3 local rules, provides optimization suggestions in **Korean**, and emits an auto-fixed version of each rule.

- **Version toggle** — Snort 2 / Snort 3 selector applies version-specific checks
- **Multi-line rule support** — parenthesis depth tracking joins formatted multi-line rules before analysis
- **Version mismatch detection** — warns if Snort 3-only keywords appear in a Snort 2 rule (or vice versa)
- **Per-rule suggestions** — categorized as `PERF` (performance), `WARN` (correctness), `INFO` (best practice)
- **Per-option detailed explanation** — `OPT_EXPLAIN` database covers ~40 keywords with Korean descriptions
- **Click to expand** — rule header shows truncated rule, click to reveal full text
- **Auto-fix engine** — `applySnort2Fixes()` / `applySnort3Fixes()` automatically rewrites each rule to follow best practices and lists the changes that were applied
- **All Optimized Rules panel** — top-of-screen aggregated view of every fixed rule with a one-click **Copy All** button (rendered for **both Snort 2 and Snort 3**)
- **Per-rule Optimized Rule section** — each rule card shows its fixed version + auto-fixes list + per-rule Copy button (rendered for **both Snort 2 and Snort 3**)

#### Suggestion Categories (examples)

| Level | Example Check |
|-------|---------------|
| PERF | `pcre` without preceding `content` anchor |
| PERF | Multiple `content` options without `fast_pattern` |
| PERF | Missing `flow` option |
| WARN | Unknown rule action |
| WARN | Missing `msg`, `sid`, `rev` |
| WARN | SID not in local rule range (1,000,000–1,999,999) |
| WARN | Deprecated Snort 2 keywords present |
| INFO | `flowbits` → `xbits` migration note |
| INFO | `dce_stub_data` requires dce2 inspector |

#### Auto-Fix Examples

| Version | Auto-Fix |
|---------|----------|
| Snort 2 / 3 | Inject `fast_pattern` on the longest `content` when missing |
| Snort 2 / 3 | Append `flow:established,to_server;` when `flow` is absent |
| Snort 2 / 3 | Reorder `gid; sid; rev;` to the end of the option list |
| Snort 3 | Convert `uricontent:"X"` → `http_uri; content:"X"` |
| Snort 3 | Convert `flowbits:set,name` → `xbits:set,name,track ip_src` |
| Snort 3 | Strip Snort-2-only modifiers (`rawbytes`, `:only`, `metadata:service http` → `service:http`) |
| Snort 3 | Inline positional content modifiers (`depth`, `within`, `offset`, `distance`, `nocase`, `fast_pattern`) |
| Snort 3 | Promote sticky buffers (`http_uri`, `http_header`, …) before their `content` |

---

### 3. Python Validator

Generates a standalone Python 3 script (`validate_snort3.py`) for offline Snort 3 rule validation.

- **No dependencies** — pure Python 3, no external packages required
- **Embed converted rules** — load rules converted on the Home tab directly into the script
- **Network variable inputs** — configure `$HOME_NET` / `$EXTERNAL_NET` (Source/Dest IP/CIDR)
- **Apply to Script** — commits network variables into the generated script
- **Download / Copy** — export the script for use in CI/CD pipelines or local validation

---

### 4. Snort SRU Updates

Displays the current week's **Snort 2 Subscriber Rule Update (SRU)** release notes.

- Fetches all advisory pages for the current week (Sunday–Saturday) in parallel via `Promise.all`
- Source: `snort.org/advisories/talos-rules-YYYY-MM-DD`
- Filters blocks matching `Snort version 2XXXXXXX` pattern
- Shows **New / Modified / Deleted** rule counts per day with collapsible day blocks
- CORS-proxied via `api.codetabs.com` when direct fetch is blocked

---

### 5. Snort LSP Updates

Displays the current week's **Snort 3 Lightweight Security Package (LSP)** release notes.

- Same fetch and display architecture as SRU
- Filters blocks matching `Snort version 3.X.X.X` pattern
- Shows **New / Modified / Deleted** rules per day

---

### 6. Site Information

Static informational page covering:
- Site owner, site name, purpose, target users
- Feature list with detailed conversion algorithm documentation
- Technical stack (GitHub Pages, Cloudflare Workers, GitHub Issues API)
- Disclaimer

---

### 7. Useful Script Download

An inline page (the header **"Useful Script Download"** button switches the main view, just like Home / Rule Optimization / etc.) that lists helper scripts (e.g. FMC Snort 2 rule exporter) directly from the GitHub repository's `Download_Files/` folder.

#### Architecture

```
Browser
    ↓  GET (public, no auth)
GitHub Contents API
    ↓
maxias13/snort-rule-converter-site/Download_Files/  (branch: main)
```

- Download list is fetched live via the GitHub Contents API on every modal open — no rebuild required when files are added or removed.
- File browser link in the modal footer opens `tree/main/Download_Files` on GitHub for direct browsing.

#### Tabs

| Tab | Access | Behavior |
|-----|--------|----------|
| Download | Public | Lists every file in `Download_Files/` with size + click-to-download |
| Upload (Admin) | Password + GitHub PAT | Drops a new file into `Download_Files/` via authenticated `PUT` |

#### Upload Flow (Admin)

1. Enter admin password — verified client-side via SHA-256 hash compare against the embedded hash constant.
2. Provide a GitHub PAT (Personal Access Token) with `contents:write` scope on this repo. The PAT is persisted in `localStorage` (`scriptdl_pat`) so it survives reloads.
3. Drop or pick a file → it is base64-encoded in the browser and `PUT` to `Download_Files/<filename>` via the GitHub Contents API with commit message `"Add Download_Files/<filename> via web upload"`.
4. The download list refreshes immediately after the upload commit.

> Files are served live from `/Download_Files` on GitHub — anything pushed to that folder (via the web UI or `git push`) appears in the modal automatically.

---

### 8. Feedback Board

Community bulletin board where visitors can leave feedback without a GitHub account.

#### Architecture

```
Browser (no login required)
    ↓
Cloudflare Worker (snort-feedback.snort-feedback.workers.dev)
    ↓  [GitHub token stored server-side as environment secret]
GitHub Issues API (maxias13/snort-rule-converter, label: feedback)
```

#### Post Types

| Type | Badge Color | Notes |
|------|-------------|-------|
| Feature Request | Cyan | Open to all visitors |
| Bug Report | Red | Open to all visitors |
| Suggestion | Yellow | Open to all visitors |
| Notice | Gold ★ | **Admin only** — requires password (SHA-256 hashed, client-side gate) |

#### Behavior
- **Notice** posts always appear at the top of the list
- Posts show title only by default — click to expand author, date, content
- Submitted posts are stored as GitHub Issues and can be managed (edited/closed/deleted) at `github.com/maxias13/snort-rule-converter/issues`
- Active tab persists in URL hash (e.g. `#feedbackView`) — survives page refresh

---

## Technical Stack

| Component | Technology |
|-----------|-----------|
| Hosting | GitHub Pages (static) |
| Frontend | Pure HTML / CSS / JavaScript — zero dependencies |
| Feedback Backend | Cloudflare Workers + GitHub Issues REST API |
| Fonts | Google Fonts (Inter) |
| Rule update source | snort.org Talos advisory pages |
| CORS proxy fallback | api.codetabs.com |

---

## Navigation

| Tab | URL Hash | Description |
|-----|----------|-------------|
| Home | `#homeView` | Rule converter + diff view |
| Rule Optimization | `#optimizerView` | Per-rule analysis (Korean) |
| Python Validator | `#validatorView` | Downloadable validation script |
| Snort SRU Updates | `#sruView` | Weekly Snort 2 rule changes |
| Snort LSP Updates | `#lspView` | Weekly Snort 3 rule changes |
| Site Information | `#siteinfoView` | About this site |
| Feedback | `#feedbackView` | Community board |
| Useful Script Download | (modal) | Lists & downloads files from `Download_Files/`; admin upload |
| How to write Snort 3 rules ↗ | — | External link to docs.snort.org |

---

## Repository

- **Source:** `index.html` (single-file application)
- **GitHub:** https://github.com/maxias13/snort-rule-converter-site
- **Live Site:** https://maxias13.github.io/snort-rule-converter-site/
