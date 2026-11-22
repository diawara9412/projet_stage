#!/usr/bin/env python3
"""Démo temps réel — génération d'une chaîne de sécurité par agents LLM.

Backend FastAPI : exécute le VRAI graphe LangGraph (Groq) et streame, via
WebSocket, chaque étape des agents coordonnés par le superviseur, puis la
traduction en règles OpenFlow.

Lancer :  python3 demo_server.py       (puis ouvrir http://127.0.0.1:8000)
"""
import asyncio, pathlib, sys
import anyio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from architectures.supervisor.behavior_supervisor import build_behavior_graph, BehaviorState
from tools.behavior_traces import enrich
from tools.behavior_chain import reference_chain
from tools.behavior_deploy import to_deployable

app = FastAPI()
WEB = ROOT / "demo_web"
GRAPH = build_behavior_graph()

KIND = {"exact": "port", "prefix": "plage", "any": "joker", "org": "organisation", "orphan": "non résolu"}


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


def _events_from(chunk: dict, store: dict) -> list[dict]:
    """Traduit une mise à jour LangGraph {node: delta} en événements front."""
    out = []
    for node, delta in chunk.items():
        if not isinstance(delta, dict):
            continue
        if node == "supervisor":
            log = delta.get("supervisor_log") or []
            out.append({"type": "supervisor", "route": delta.get("next_agent"),
                        "reason": (log[-1] if log else "")})
        elif node == "analyzer":
            prof = delta.get("profile") or {}
            store["profile"] = prof
            rares = prof.get("rare_transitions", [])
            watch = {t["from"] for t in rares} | {t["to"] for t in rares}
            states = [{"label": s["label"], "kind": KIND.get(s["spec"]["kind"], s["spec"]["kind"]),
                       "watched": s["label"] in watch}
                      for s in prof.get("services", []) if s.get("destinations")]
            out.append({"type": "done", "agent": "analyzer",
                        "n_states": prof.get("stats", {}).get("n_services"),
                        "n_rare": prof.get("stats", {}).get("n_rare"),
                        "states": states,
                        "rares": [f'{t["from"]} → {t["to"]}  ({t["probability"]*100:.2f}%)'.replace(".", ",")
                                  for t in rares]})
        elif node == "firewall":
            dec = delta.get("firewall_decision") or {}
            rep = delta.get("firewall_report") or {}
            out.append({"type": "done", "agent": "firewall",
                        "decisions": dec.get("services", []),
                        "source": rep.get("source"), "retries": rep.get("retries", 0)})
        elif node == "ids":
            dec = delta.get("ids_decision") or {}
            rep = delta.get("ids_report") or {}
            out.append({"type": "done", "agent": "ids",
                        "signatures": [s.get("service") for s in dec.get("signatures", [])],
                        "source": rep.get("source")})
        elif node == "verifier":
            rep = delta.get("verification_report") or {}
            st = rep.get("stats", {})
            out.append({"type": "done", "agent": "verifier",
                        "valid": rep.get("is_valid"), "score": rep.get("quality_score"),
                        "n_err": st.get("errors"), "n_warn": st.get("warnings")})
        elif node == "deployer":
            res = delta.get("deployment_result") or {}
            out.append({"type": "done", "agent": "deployer",
                        "n_fw": res.get("n_firewall_rules"),
                        "n_sig": res.get("n_ids_signatures"),
                        "fallback": res.get("used_fallback")})
    return out


@app.websocket("/ws/run")
async def ws_run(ws: WebSocket):
    await ws.accept()
    q = ws.query_params
    app_name = q.get("app", "viber")
    model = q.get("model", "openai/gpt-oss-120b")
    use_llm = q.get("mode", "llm") != "demo"
    sabotage = q.get("sabotage") or None
    store: dict = {}
    try:
        await ws.send_json({"type": "start", "app": app_name, "model": model, "use_llm": use_llm})
        state = BehaviorState(app=app_name, model=model, use_llm=use_llm, sabotage=sabotage)
        gen = GRAPH.stream(state, stream_mode="updates")
        SENT = object()

        def _next():
            return next(gen, SENT)

        while True:
            chunk = await anyio.to_thread.run_sync(_next)
            if chunk is SENT:
                break
            for ev in _events_from(chunk, store):
                await ws.send_json(ev)
                await asyncio.sleep(0.5)   # cadence lisible

        # ── traduction en OpenFlow (ce que le contrôleur installerait) ──
        prof = store.get("profile") or enrich(app_name)
        dep = to_deployable(reference_chain(prof))
        fr = dep["firewall_rules"]
        sample = [{"id": r.get("id"), "dst_ip": r.get("dst_ip"),
                   "proto": r.get("protocol"), "port": r.get("dst_port"),
                   "action": r.get("action")} for r in fr[:4]]
        await ws.send_json({"type": "openflow", "sample": sample,
                            "n_fw": len(fr), "n_sig": len(dep["ids_signatures"])})
        await ws.send_json({"type": "end"})
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_json({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    print("\n  Démo agents → http://127.0.0.1:8000\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
