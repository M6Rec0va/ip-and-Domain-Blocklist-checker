#!/usr/bin/env python3
"""
Simple async checker engine.
- Reads targets (one per line)
- Reads checkers.json describing how to query each provider
- Runs requests concurrently with timeouts and saves results

This script intentionally keeps parsing simple. For complex providers add custom handlers.
"""
import asyncio
import argparse
import json
import os
import re
import base64
from typing import Any, Dict, List
import httpx
from dateutil import parser as dateparser

# basic helper to substitute ${ENV_VAR} in headers/endpoint
env_pattern = re.compile(r"\$\{([A-Z0-9_]+)\}")


def env_sub(s: Any) -> Any:
    if isinstance(s, str):
        def repl(m):
            return os.environ.get(m.group(1), "")
        return env_pattern.sub(repl, s)
    if isinstance(s, dict):
        return {k: env_sub(v) for k, v in s.items()}
    if isinstance(s, list):
        return [env_sub(v) for v in s]
    return s


async def fetch_checker(client: httpx.AsyncClient, checker: Dict[str, Any], target: str) -> Dict[str, Any]:
    c = dict(checker)
    c = json.loads(json.dumps(c))  # deep copy
    c = env_sub(c)
    name = c.get("name")
    method = c.get("method", "GET").upper()
    endpoint = c.get("endpoint", "").replace("{target}", target)
    # special-case: VirusTotal requires urlsafe-base64 of url without padding
    if "{encoded_target}" in checker.get("endpoint", ""):
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        endpoint = c.get("endpoint", "").replace("{encoded_target}", encoded)
    headers = c.get("headers", {}) or {}

    # handle POST with template
    json_body = None
    if c.get("post_json_template"):
        body = json.dumps(c.get("post_json_template"))
        body = body.replace("{target}", target)
        json_body = json.loads(body)

    out = {"checker": name, "target": target, "ok": False, "raw": None, "parsed": None}
    try:
        resp = await client.request(method, endpoint, headers=headers, json=json_body, timeout=30.0)
        out["raw"] = {"status_code": resp.status_code, "text_snippet": resp.text[:2000]}
        # try parse
        if resp.headers.get("content-type", "").lower().startswith("application/json"):
            data = resp.json()
            out["parsed"] = data
            path = c.get("response_path")
            if path:
                v = data
                for p in path:
                    if isinstance(v, dict) and p in v:
                        v = v[p]
                    else:
                        v = None
                        break
                out["parsed_value"] = v
                # interpret value >0 or truthy as flagged
                out["ok"] = bool(v)
            else:
                # if json returned and non-empty -> mark as seen
                out["ok"] = bool(data)
        else:
            text = resp.text
            # if checker provides a 'match_regex'
            if c.get("match_regex"):
                r = re.search(c.get("match_regex"), text, re.I)
                out["parsed_value"] = bool(r)
                out["ok"] = bool(r)
            else:
                out["parsed_value"] = None
                out["ok"] = resp.status_code == 200
    except Exception as e:
        out["error"] = str(e)
    return out


async def run_all(targets: List[str], checkers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, verify=True) as client:
        tasks = []
        for target in targets:
            t = target.strip()
            if not t:
                continue
            for checker in checkers:
                tasks.append(fetch_checker(client, checker, t))
        # run in bounded concurrency
        sem = asyncio.Semaphore(50)

        async def sem_task(task):
            async with sem:
                return await task

        wrapped = [sem_task(task) for task in tasks]
        for f in asyncio.as_completed(wrapped):
            r = await f
            results.append(r)
    return results


def load_targets(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]
    return lines


def load_checkers(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", default="data/urls.txt")
    parser.add_argument("--checkers", default="data/checkers.json")
    parser.add_argument("--out", default="outputs/results.json")
    parser.add_argument("--report", default="outputs/report.txt")
    args = parser.parse_args()

    targets = load_targets(args.urls)
    checkers = load_checkers(args.checkers)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    results = await run_all(targets, checkers)

    # save raw
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"meta": {"targets_count": len(targets), "checkers_count": len(checkers)}, "results": results}, f, indent=2)

    # write simple report
    lines = []
    for r in results:
        ok = r.get("ok")
        lines.append(f"{r['target']} | {r['checker']} -> {'FLAGGED' if ok else 'clean'} | parsed={r.get('parsed_value')} | status={r.get('raw',{}).get('status_code')}")
    with open(args.report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Wrote {args.out} and {args.report}")


if __name__ == '__main__':
    asyncio.run(main())
