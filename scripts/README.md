# Useful Scripts

This folder hosts downloadable utility scripts/programs surfaced via the **Useful Script Download** button on the site.

## How it works

The site uses the GitHub Contents API to read this folder live and renders a download list in a modal popup. There is **no need to edit `index.html`** when adding/removing scripts.

```
GET https://api.github.com/repos/maxias13/snort-rule-converter-site/contents/scripts?ref=main
```

Each file in this folder (excluding this `README.md`) automatically appears in the modal with:

- File name
- File size
- A direct **Download** button (uses `download_url` returned by the API)

## How to add a new script (admin)

1. Drop the file into this `scripts/` folder.
2. Commit & push to `main`.
3. The site will pick it up on the next page load (modal fetches the list on open).

### Naming convention

Per the project rule, prefix with timestamp:

```
YYYYMMDD_HHMMSS_<descriptive_name>.<ext>
```

Examples:
- `20260426_120000_snort2_to_snort3_migrate.py`
- `20260426_120500_rule_dedup_check.sh`

## Notes

- GitHub Contents API has a **60 requests/hour** unauthenticated rate limit per IP. For a low-traffic site this is fine.
- Files larger than 100 MB should not be committed to git (use Releases instead).
- Binary files are supported — the modal links straight to `raw.githubusercontent.com` via `download_url`.
