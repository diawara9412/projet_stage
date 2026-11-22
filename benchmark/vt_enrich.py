#!/usr/bin/env python3
"""Enrichit les IP du dataset réel avec VirusTotal (last_analysis_stats), en cache.
VT gratuit = 4 requêtes/min → sleep 16 s. Cache incrémental (repris si coupé)."""
import json, time, sys, pathlib, os
import requests

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
DATA = json.loads((_ROOT / "benchmark/dataset_realworld.json").read_text())
CACHE = _ROOT / "benchmark/vt_cache.json"
cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}

todo = [ip for ip, _ in DATA if ip not in cache]
print(f"À enrichir : {len(todo)}/{len(DATA)} (cache={len(cache)})", file=sys.stderr, flush=True)

for i, ip in enumerate(todo, 1):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": KEY}, timeout=25)
        if r.status_code == 429:                      # rate limit → attendre plus
            time.sleep(30); r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": KEY}, timeout=25)
        st = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        cache[ip] = {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                     "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0)}
    except Exception as e:
        cache[ip] = {"error": str(e)[:80]}
    CACHE.write_text(json.dumps(cache))               # incrémental
    if i % 10 == 0:
        print(f"  {i}/{len(todo)} …", file=sys.stderr, flush=True)
    time.sleep(16)                                    # respecte 4/min

print(f"Terminé : {len(cache)} IP en cache VT.", file=sys.stderr, flush=True)
