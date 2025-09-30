# ip-and-Domain-Blocklist-checker

Run bulk checks of IPs/domains/URLs against many reputation/blocklist sources from GitHub Actions.

## How to use

1. Create a new GitHub repository and push these files.
2. Edit `data/urls.example.txt` -> rename to `data/urls.txt` and put one target per line (IP, domain or URL).
3. Edit `data/checkers.example.json` -> rename to `data/checkers.json` and add/enable the checkers you want. The example contains several common ones; you can add 100+ entries.
4. Add API keys (if any) in repository `Settings -> Secrets and variables -> Actions -> Secrets` using names mentioned in checkers.json (e.g. `VT_API_KEY`, `ABUSEIPDB_KEY`).
5. Go to the repository Actions tab, open the **Run blocklist checks** workflow and run it manually (workflow_dispatch). The job will run and upload artifacts (`results.json`, `report.txt`).

## Outputs
- `outputs/results.json` — raw JSON with per-target, per-checker responses and parsed flags.
- `outputs/report.txt` — simple text summary for quick reading.

## Notes & caveats
- This scaffold tries to be generic: checkers can be defined as `api` or `page` types. Parsing is intentionally simple (JSON key lookup or regex). For complex provider pages you may need custom parsing code.
- Respect rate limits. For a large number of checkers/targets you should add delays or batch sizes.
- Don't expose API keys. Use GitHub Secrets.

## Extending to 100+ checkers
- Create `data/checkers.json` with entries for each provider. Many providers have similar response structures; reuse pattern entries.
- For providers without an API, you can sometimes parse the public web lookup page, but site changes may break parsing.
```

````

### `requirements.txt`
```text
httpx>=0.24.0
python-dateutil>=2.8.2
aiofiles>=23.1.0
````
