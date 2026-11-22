#!/usr/bin/env python3
"""
architectures/supervisor/supervisor_service.py — Superviseur en MODE SERVICE
(niveau 3 de la boucle autonomique).

Au lieu d'un run « one-shot », c'est le MÊME pipeline d'assemblage enrobé dans une
boucle qui surveille la file Redis « sdn:anomalies » (alimentée par le contrôleur
lancé en `--loop`). Pour chaque flux inconnu :

  - DÉCISION :
      * ÉTENDRE  → dérive légitime : la destination appartient au même opérateur
                   qu'une destination déjà whitelistée (même ASN, ou repli même
                   préfixe /16). On l'ajoute à la liste blanche.
      * BLOQUER  → ni ASN ni préfixe connu → réellement inconnu (journalisé).
  - SI ÉTENDRE : on régénère la chaîne (chemin déterministe, sans LLM) et on la
    redéploie via REST → le contrôleur se met à jour SANS redémarrage.

Boucle fermée MAPE-K : Monitor (contrôleur) → Analyze/Plan (ici) → Execute (REST).

Pré-requis :
  T1 : sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --loop
  T2 : sudo python3 deploy_mini_demo.py [--nat]
  T3 : python3 architectures/supervisor/run_supervisor_test.py --deploy --automate <app>_whitelist
  T4 : python3 architectures/supervisor/supervisor_service.py --app <app>
  (puis générer du trafic inconnu, ex. rejeu d'une autre app)

Usage :
  python3 architectures/supervisor/supervisor_service.py --app lequipe [--asn]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import redis

from tools.chain_tools import generate_chain_from_analysis
from agents.chain_analyzer import _analyze_deterministic
from tools.deployment_tools import install_chain_via_rest
from state import FirewallRule, IdsSignature, IpsAction
from whitelist import threat_intel

_ALLOWED_PROTO = ("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "ARP")


def _proto_literal(proto: str) -> str:
    """Mappe le proto observé vers la valeur attendue par FirewallRule (sinon 'any')."""
    p = (proto or "").upper()
    return p if p in _ALLOWED_PROTO else "any"

ENDPOINT = "http://127.0.0.1:8080/firewall"
QUEUE = "sdn:anomalies"


def _prefix16(ip: str) -> str | None:
    try:
        return ".".join(ip.split(".")[:2])
    except Exception:
        return None


def _resolve_asn(ip: str) -> int | None:
    """ASN d'une IP via le résolveur du projet (RDAP). None si indispo/échec."""
    try:
        from enrichment.asn_resolver import AsnResolver
        res = AsnResolver().resolve(ip)
        return getattr(res, "asn", None)
    except Exception:
        return None


class SupervisorService:
    def __init__(self, app: str, use_asn: bool = False, agentic: bool = False):
        self.app = app
        self.use_asn = use_asn
        self.agentic = agentic   # niveau 3 : caractérisation agentique (FW+IDS+IPS) de l'inconnu
        self.automate_path = _ROOT / "automates" / f"{app}_whitelist.json"
        self.automate = json.loads(self.automate_path.read_text())

        # Connaissances « légitimes » pour décider la dérive
        self.known_ips: set[str] = set()
        self.known_prefix: set[str] = set()
        for t in self.automate.get("transitions", []):
            ip = (t.get("network_call") or {}).get("ip")
            if ip:
                self.known_ips.add(ip)
                p = _prefix16(ip)
                if p:
                    self.known_prefix.add(p)
        self.known_asn: set[int] = set()  # rempli paresseusement si --asn

        self.blocked: list[tuple] = []   # (ip,port,proto) → règles DROP explicites (prio 950)
        self.ids_sigs: list[IdsSignature] = []   # niveau 3 : signatures IDS générées au runtime
        self.ips_acts: list[IpsAction] = []      # niveau 3 : actions IPS générées au runtime
        self.n_ext = 0
        self.n_block = 0
        self.n_ids = 0
        self.r = redis.Redis(host="127.0.0.1", port=6379, db=0)

    # ── Décision ────────────────────────────────────────────────────────────
    def _known_asns(self) -> set[int]:
        if self.known_asn:
            return self.known_asn
        for ip in list(self.known_ips)[:30]:  # échantillon → limite les lookups
            a = _resolve_asn(ip)
            if a:
                self.known_asn.add(a)
        return self.known_asn

    def decide(self, ip: str, port, proto: str) -> tuple[str, str]:
        if self.use_asn:
            asn = _resolve_asn(ip)
            if asn and asn in self._known_asns():
                return "EXTEND", f"même ASN AS{asn} qu'une destination légitime"
        p = _prefix16(ip)
        if p and p in self.known_prefix:
            return "EXTEND", f"même préfixe /16 ({p}.x) qu'une destination légitime"
        return "BLOCK", "ni ASN ni préfixe connu → réellement inconnu"

    # ── Exécution : extension + redéploiement ────────────────────────────────
    def extend(self, ip: str, port, proto: str) -> None:
        n = len(self.automate["transitions"]) + 1
        svc = f"wl-{ip}-{port or 'any'}-{proto}"
        self.automate["transitions"].append({
            "id": f"auto{n:04d}", "from": "INITIAL", "to": svc,
            "label": f"auto-extend → {ip}:{port}",
            "network_call": {"ip": ip, "port": port, "protocol": (proto or "tcp").upper()},
            "service": {"name": svc, "type": "whitelist", "reputation": "trusted"},
            "suspicion": {"score": 0, "flags": [], "notes": "auto-extension (dérive légitime)"},
            "behavior": {"probability": 1.0},
        })
        self.known_ips.add(ip)
        p = _prefix16(ip)
        if p:
            self.known_prefix.add(p)
        self.redeploy()

    def block(self, ip: str, port, proto: str) -> None:
        """Branche BLOCK active : mémorise la destination et redéploie avec une
        règle DROP explicite (prio 950, jetée en hardware sur le switch)."""
        if (ip, port, proto) not in self.blocked:
            self.blocked.append((ip, port, proto))
        self.redeploy()

    def redeploy(self) -> None:
        analysis = _analyze_deterministic(self.automate)
        chain = generate_chain_from_analysis(analysis)
        # Injecte les DROP explicites des inconnus refusés (prio forcée à 950 par le contrôleur).
        for i, (ip, port, proto) in enumerate(self.blocked, start=1):
            chain.firewall_rules.append(FirewallRule(
                id=f"AUTO-BLOCK-{i:03d}", action="BLOCK", direction="outbound",
                dst_ip=ip, dst_port=(port if proto in ("tcp", "udp") else None),
                protocol=_proto_literal(proto), priority=950,
                comment="auto-block (inconnu hors profil)"))
        # Niveau 3 : signatures IDS + actions IPS générées au runtime par les agents.
        chain.ids_signatures.extend(self.ids_sigs)
        chain.ips_actions.extend(self.ips_acts)
        install_chain_via_rest(chain.model_dump(), ENDPOINT)

    # ── Enrichissement RÉACTIF (les outils, comme au proactif) ─────────────────
    def _enrich(self, ip: str) -> dict:
        """À l'escalade, l'agent APPELLE ses outils (comme au proactif) : ASN +
        RDAP/whois + réputation par organisation. Ne se contente plus d'une liste
        locale. Retourne {asn, org, reputation, vt}. Robuste si outil indispo."""
        vt = 0
        try:
            from enrichment import virustotal
            vt = virustotal.check_ip(ip).get("malicious", 0)   # nb de moteurs VirusTotal
        except Exception:
            pass
        try:
            from enrichment.asn_resolver import AsnResolver
            from enrichment.classifier import reputation_state
            res = AsnResolver(enable_rdap=True).resolve(ip)
            return {"asn": getattr(res, "asn", None),
                    "org": getattr(res, "org", None) or "?",
                    "reputation": reputation_state(res), "vt": vt}
        except Exception as exc:
            print(f"   ⚠️ enrichissement indisponible pour {ip} : {exc}")
            return {"asn": None, "org": "?", "reputation": "unknown", "vt": vt}

    def extend_inspect(self, ip: str, port, proto: str, org: str) -> None:
        """ALLOW + SURVEILLANCE IDS : org de confiance mais IP inconnue → on laisse
        passer SOUS surveillance (allow-then-inspect). L'IDS observe → re-escalade si
        comportement suspect. C'est le cas du C2 planqué sur un cloud de confiance."""
        sid = f"IDS-WATCH-{len(self.ids_sigs) + 1:03d}"
        self.ids_sigs.append(IdsSignature(
            id=sid, name="TRUSTED_ORG_WATCH", pattern_type="monitored",
            match_criteria={"dst_ip": ip, "dst_port": port,
                            "protocol": (proto or "tcp").upper()},
            severity="LOW",
            comment=f"org de confiance '{org}' mais IP inconnue → surveillance IDS"))
        self.n_ids += 1
        self.extend(ip, port, proto)   # ALLOW + redeploy (la chaîne inclut ids_sigs)

    def _decide_via_agents(self, ip: str, port, proto: str) -> str | None:
        """RÉACTIF via les VRAIS agents : construit un mini-profil de la destination
        escaladée et invoque le GRAPHE LangGraph complet (Analyseur → Firewall → IDS →
        IPS → Déployeur, coordonnés par le Superviseur). Les agents ANALYSENT (avec tous
        les outils : threat_intel + VirusTotal + ASN/whois) et GÉNÈRENT la règle.
        Retourne 'BLOCK' / 'ALLOW' selon ce que le Firewall a décidé, ou None si échec."""
        import tempfile, os, json as _json
        from architectures.supervisor.run_supervisor_test import _run_graph, _field
        autom = {
            "automate_id": f"reactive-{ip}", "app_name": self.app,
            "states": [{"id": "INITIAL"}, {"id": "dest"}],
            "transitions": [{
                "id": "r1", "from": "INITIAL", "to": "dest",
                "label": f"escalade -> {ip}:{port}",
                "network_call": {"ip": ip, "port": port, "protocol": (proto or "tcp").upper()},
                "service": {"name": f"esc-{ip}", "reputation": "neutral", "type": "escalated"},
                "suspicion": {"score": 0, "flags": []},
                "behavior": {"probability": 1.0},
            }],
        }
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        _json.dump(autom, tmp); tmp.close()
        try:
            result = _run_graph(tmp.name, deploy=False)          # les VRAIS agents tournent
            chain = _field(result, "security_chain")
            rules = _field(chain, "firewall_rules") or _field(result, "firewall_rules") or []
            for r in rules:
                if _field(r, "dst_ip") == ip:
                    if _field(r, "action") == "BLOCK":
                        return "BLOCK"
                    if _field(r, "action") in ("ALLOW", "ALLOW_AND_INSPECT"):
                        return "ALLOW"
            return "ALLOW"                                        # aucun BLOCK pour l'IP
        except Exception as exc:
            print(f"   ⚠️ run agents (graphe LangGraph) échoué pour {ip} : {exc}")
            return None
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

    # ── NIVEAU 3 : caractérisation agentique d'un flux jamais vu ───────────────
    def agentic_handle(self, ip: str, port, proto: str) -> tuple[str, str]:
        """Le contrôleur a escaladé un paquet inconnu. Les agents REFONT leur travail
        sur ce flux : d'abord la liste C2 locale + /16, PUIS l'ENRICHISSEMENT réel
        (ASN + RDAP/whois + réputation org) — plus de décision aveugle.
        Retourne (décision, explication)."""
        rep = threat_intel.reputation(ip)
        p = _prefix16(ip)
        if rep == "malicious":
            # Menace CONNUE (liste C2) → BLOCK direct (pas d'IDS : bloqué = rien à inspecter).
            if (ip, port, proto) not in self.blocked:
                self.blocked.append((ip, port, proto))
            self.redeploy()
            return "BLOCK", "menace connue (threat-intel C2) → FW BLOCK"
        if p and p in self.known_prefix:
            self.extend(ip, port, proto)
            return "EXTEND", f"même préfixe /16 ({p}.x) qu'une destination légitime"

        # ── AMBIGU → les VRAIS agents (graphe LangGraph complet) génèrent la chaîne ──
        dec = self._decide_via_agents(ip, port, proto)
        if dec == "BLOCK":
            threat_intel.add_malicious(ip)                       # apprentissage
            if (ip, port, proto) not in self.blocked:
                self.blocked.append((ip, port, proto))
            self.redeploy()
            return "BLOCK", "agents LangGraph (Analyseur+Firewall, tous outils) → BLOCK + réputation apprise"
        if dec == "ALLOW":
            self.extend_inspect(ip, port, proto, "?")
            return "ALLOW+IDS", "agents LangGraph → ALLOW_AND_INSPECT (surveillé)"
        # dec is None (graphe indisponible) → FALLBACK rapide déterministe ci-dessous

        # ── FALLBACK : l'agent ENRICHIT (VirusTotal + whois/asn) sans le graphe ──
        enr = self._enrich(ip)
        asn, org, orep, vt = enr["asn"], enr["org"], enr["reputation"], enr.get("vt", 0)
        tag = f"AS{asn} / '{org}'"
        # VirusTotal = signal de menace le plus fiable → BLOCK + RÉTROACTION (apprentissage)
        if vt >= 1:
            threat_intel.add_malicious(ip)          # mémorise → bloqué DIRECTEMENT ensuite (niveau 2)
            if (ip, port, proto) not in self.blocked:
                self.blocked.append((ip, port, proto))
            self.redeploy()
            return "BLOCK", f"VirusTotal : {vt} moteur(s) malveillant(s) → BLOCK + réputation mise à jour (apprise)"
        if orep == "untrusted":
            # org douteuse (mots-clés / BGP) → BLOCK MOTIVÉ (plus aveugle)
            if (ip, port, proto) not in self.blocked:
                self.blocked.append((ip, port, proto))
            self.redeploy()
            return "BLOCK", f"enrichissement whois/asn : {tag} DOUTEUSE → BLOCK"
        if orep == "trusted":
            # org de confiance MAIS IP inconnue → ALLOW_AND_INSPECT (surveillé)
            # (c'est ici qu'on attrape un C2 planqué sur un cloud de confiance)
            self.extend_inspect(ip, port, proto, org)
            return "ALLOW+IDS", f"enrichissement whois/asn : {tag} de confiance mais IP inconnue → ALLOW_AND_INSPECT (surveillé)"
        # neutral / unknown → fail-closed BLOCK, mais MOTIVÉ par l'enrichissement
        if (ip, port, proto) not in self.blocked:
            self.blocked.append((ip, port, proto))
        self.redeploy()
        return "BLOCK", f"enrichissement whois/asn : {tag} non fiable (réputation={orep}) → fail-closed BLOCK"

    # ── NIVEAU 3bis : escalade d'un DOMAINE (SNI) depuis s2 ────────────────────
    def domain_handle(self, ip: str, domain: str, port, proto: str) -> tuple[str, str]:
        """Le contrôleur a escaladé un DOMAINE (SNI). L'agent appelle VirusTotal-domaine
        (l'appel en ligne se fait ICI, hors du chemin critique du contrôleur). Si le
        domaine est malveillant → BLOCK l'IP + met à jour la réputation (apprentissage)."""
        vt = 0
        try:
            from enrichment import virustotal
            vt = virustotal.check_domain(domain).get("malicious", 0)
        except Exception:
            pass
        if vt >= 1:
            threat_intel.add_malicious(ip)          # apprend l'IP derrière le domaine
            if (ip, port, proto) not in self.blocked:
                self.blocked.append((ip, port, proto))
            self.redeploy()
            return "BLOCK", f"VirusTotal-domaine '{domain}' : {vt} moteur(s) → BLOCK + réputation apprise"
        return "ALLOW", f"domaine '{domain}' propre selon VirusTotal → laissé"

    # ── Boucle service ────────────────────────────────────────────────────────
    def run(self) -> None:
        mode = "AGENTIQUE niveau 3 (FW+IDS+IPS)" if self.agentic else (
            "ASN+/16" if self.use_asn else "/16")
        print(f"🔁 Superviseur-service démarré — app={self.app}, file='{QUEUE}', décision={mode}")
        print(f"   base connue : {len(self.known_ips)} IP, {len(self.known_prefix)} préfixes /16"
              + (f", threat-intel : {threat_intel.n_known()} IP malveillantes connues" if self.agentic else ""))
        print("   en attente de flux inconnus…\n")
        while True:
            item = self.r.blpop(QUEUE, timeout=5)
            if item is None:
                continue
            t0 = time.time()
            try:
                ev = json.loads(item[1])
            except Exception:
                continue
            ip, port, proto = ev.get("ip"), ev.get("port"), ev.get("proto")
            domain = ev.get("domain")
            if not ip:
                continue
            if domain:
                # escalade d'un DOMAINE (SNI) depuis s2 → l'agent appelle VT-domaine
                decision, why = self.domain_handle(ip, domain, port, proto)
                if decision.startswith("BLOCK"):
                    self.n_block += 1
            elif self.agentic:
                # NIVEAU 3 : les agents refont leur travail sur ce paquet jamais vu.
                decision, why = self.agentic_handle(ip, port, proto)
                if decision.startswith("EXTEND"):
                    self.n_ext += 1
                else:
                    self.n_block += 1
            else:
                decision, why = self.decide(ip, port, proto)
                if decision == "EXTEND":
                    self.extend(ip, port, proto)
                    self.n_ext += 1
                else:
                    self.block(ip, port, proto)   # branche BLOCK active : pose un DROP prio 950
                    self.n_block += 1
            dt = (time.time() - t0) * 1000
            print(f"  [{decision:^14}] {ip}:{port}/{proto:<4} — {why}  "
                  f"({dt:.0f} ms)  [ext={self.n_ext} block={self.n_block} ids={self.n_ids}]")


def main() -> int:
    ap = argparse.ArgumentParser(description="Superviseur en mode service (boucle autonomique)")
    ap.add_argument("--app", default="lequipe", help="app dont la whitelist est déployée")
    ap.add_argument("--asn", action="store_true",
                    help="décide aussi par ASN (RDAP) ; sinon préfixe /16 seulement")
    ap.add_argument("--agentic", action="store_true",
                    help="NIVEAU 3 : caractérisation agentique de l'inconnu (FW+IDS+IPS via threat-intel)")
    args = ap.parse_args()
    SupervisorService(args.app, use_asn=args.asn, agentic=args.agentic).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
