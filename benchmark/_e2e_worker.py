#!/usr/bin/env python3
"""Worker e2e — lancé en sous-processus PAR MODÈLE (WORKER_MODEL/SUPERVISOR_MODEL/GROQ_API_KEY
fixés par le parent). Pour chaque app à automate : génère la VRAIE chaîne via le pipeline
complet des agents (analyseur LLM → firewall → IDS → IPS → déployeur, deploy=False),
puis ressort {app: {allow_ips, agents:{firewall:{source,errors}, ids, ips}}} en JSON.
"""
import sys, json, os, tempfile, pathlib, logging
logging.disable(logging.CRITICAL)                    # silence les agents
_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from architectures.supervisor.run_supervisor_test import _run_graph, _field

# apps ayant un automate _whitelist.json (indispensable pour générer une chaîne)
APPS = os.environ.get("E2E_APPS", "dropbox,faceswitch,lequipe,viber").split(",")


def automate_ips(d):
    ips = [(t.get("network_call") or {}).get("ip") for t in d.get("transitions", [])]
    return sorted({ip for ip in ips if isinstance(ip, str) and ip.count(".") == 3})


def build_train_automate(app):
    src = _ROOT / f"automates/{app}_whitelist.json"
    if not src.exists():
        return None, []
    d = json.loads(src.read_text())
    ips = automate_ips(d)
    train = ips[::2]                                  # même split que eval_16
    d["transitions"] = [t for t in d.get("transitions", [])
                        if (t.get("network_call") or {}).get("ip") in set(train)]
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(d, tmp); tmp.close()
    return tmp.name, train


def is_ext_ip(ip):
    return isinstance(ip, str) and ip.count(".") == 3 and not ip.startswith("10.") and "/" not in ip


def extract(result):
    chain = _field(result, "security_chain")
    rules = _field(chain, "firewall_rules") or []
    allow = sorted({_field(r, "dst_ip") for r in rules
                    if _field(r, "action") in ("ALLOW", "ALLOW_AND_INSPECT") and is_ext_ip(_field(r, "dst_ip"))})
    agents = {}
    for name, fld in [("firewall", "firewall_verification_report"),
                      ("ids", "ids_verification_report"),
                      ("ips", "ips_verification_report")]:
        rep = _field(result, fld)
        agents[name] = {
            "source": _field(rep, "source") if rep else None,
            "errors": _field(rep, "total_erreurs_llm_avant_correction") if rep else None,
        }
    return {"allow_ips": allow, "agents": agents}


out = {}
for app in APPS:
    autom, train = build_train_automate(app)
    if not autom:
        continue
    try:
        result = _run_graph(autom, deploy=False)
        out[app] = extract(result)
    except Exception as e:
        out[app] = {"error": str(e)[:150]}
    finally:
        try:
            os.unlink(autom)
        except Exception:
            pass

print("###JSON###" + json.dumps(out))
