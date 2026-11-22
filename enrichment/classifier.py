"""
enrichment/classifier.py — Classifieur des destinations en 6 catégories (étape 4).

NOMENCLATURE : alignée sur le chapitre Schnepf (§1.6). Soit `lf` l'état de l'automate
correspondant à `f.orgname`, `p` la probabilité d'une transition bouclant sur `lf`
(self-loop P(lf→lf)), `a = f.dstaddr` la destination et `|lf.ports|` le nombre de
ports distincts. Les seuils opérateur portent les noms de l'article :
  - attack_limit     : proba max d'une transition bouclant sur un état (= self-loop).
  - port_scan_limit  : nombre max de ports dans un flux (= |lf.ports|).
  - unsafe_threshold : valeur max du bgp_ranking (placeholder tant que BGP absent).
  - tau_dos          : *VARIANTE PROPRE* (proxy volumétrique en octets) — voir DoS.

Catégories (prédicats de l'article + contributions propres signalées) :
  - DoS       : bytes_total ≥ tau_dos  [VARIANTE PROPRE volumétrique ; l'article
                définit dos via attack_limit ∧ ip_limit ∧ min_interval ∧ min_size,
                données partiellement absentes — alignement reporté palier C/D]
  - Port scan : |lf.ports| ≥ port_scan_limit  (article : + conjonction dos, palier C)
  - Worm      : self-loop p ≥ attack_limit ET réputation = neutral
                [l'article : p ≥ attack_limit ∧ count(pt) ≥ port_limit ; la condition
                de réputation est une CONTRIBUTION PROPRE]
  - Botnet    : self-loop p ≥ attack_limit ET réputation ∈ {untrusted, unknown}
                [CONTRIBUTION PROPRE — l'article : count(a) ≥ ip_limit, ou protocole
                anormal + intervalle court ; critère self-loop+réputation différent]
  - Unsafe    : réputation = untrusted (substitut de bgp_ranking ≥ unsafe_threshold)
  - Safe      : org de confiance OU aucune autre catégorie (article : safe ← ¬dos ∧
                ¬port_scan ∧ ¬unsafe ∧ ¬∃pt(worm ∨ botnet))
  - Monitored : CONTRIBUTION PROPRE (absente de l'article) — défaut de surveillance
                pour neutral/unknown sans signal d'attaque.

PRIORITÉ (catégorie primaire = tier de défense) :
  Botnet > Worm > DoS > Port scan > Unsafe > Monitored > Safe
Les autres catégories matchées sont conservées (renforcent le score, pas le tier).

MAPPING catégorie → chaîne (article §1.6, p.22), reflété dans DEFENSE_TIER :
  safe → FW (stateless ◦≫ stateful) ; unsafe → FW+DPI+DLP (ici substitué FW+IDS,
  faute de permissions Android) ; dos/port_scan → FW ◦≫ IDS(limit) ◦≫ FW ;
  worm/botnet → stateless FW = BLOCK.

PROTECTION SAFE [CONTRIBUTION PROPRE] : si réputation = trusted, on N'ÉMET PAS de flag
comportemental (worm/botnet déjà exclus car exigent non-trusted ; dos/port_scan
supprimés SAUF s'il y a ≥ 2 signaux comportementaux indépendants).

Réputation à 4 états [CONTRIBUTION PROPRE] dérivés du résolveur (étape 3) :
  trusted (allowlist) / untrusted (mots-clés mauvais, BGP plus tard) /
  neutral (org résolue mais non listée) / unknown (non résolue : base absente, etc.)

Seuils PROVISOIRES (à reporter dans metadata.thresholds, ajustables) :
  attack_limit=0.8, port_scan_limit=10, tau_dos=1_000_000 (1 Mo),
  unsafe_threshold=placeholder BGP.

Rétro-compatibilité : les anciens noms (tau_selfloop, tau_ports, tau_unsafe_bgp)
restent acceptés en entrée de classify() et sont normalisés.

Ce module NE fait PAS : ajouts chain_tools (étape 5), JSON (6), dry-run (7).
Aucun réseau, aucun LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Seuils de départ (PROVISOIRES — choix méthodologique documenté).
# Noms alignés sur l'article (Schnepf §1.6). tau_dos = variante propre (volumétrique).
DEFAULT_THRESHOLDS: dict = {
    "attack_limit": 0.8,        # ex-tau_selfloop : proba max de self-loop P(lf→lf)
    "port_scan_limit": 10,      # ex-tau_ports : nb max de ports distincts |lf.ports|
    "tau_dos": 1_000_000,       # octets — VARIANTE PROPRE (pas de seuil dos dans l'article)
    # ex-tau_unsafe_bgp. Utilisé UNIQUEMENT par la variante BGP (opt-in). Valeur
    # PROVISOIRE, NON CALIBRÉE SCIENTIFIQUEMENT → tout résultat de la variante BGP
    # est PRÉLIMINAIRE tant que ce seuil n'est pas calibré (ne jamais présenter comme ferme).
    "unsafe_threshold": 0.5,    # bgp_rank ≥ 0.5 → untrusted (placeholder à calibrer)
    # ── Palier B : seuils article exposés en SIGNAUX CORROBORANTS (informationnels).
    #    PROVISOIRES — n'entrent dans AUCUNE condition de catégorie (cf. classify()).
    "ip_limit": 50,             # count(a) : nb max d'occurrences (flux) d'une IP — PROVISOIRE
    "min_size": 5,              # avg_size ≤ min_size = flux « petits » (paquets/flux) — PROVISOIRE
}

# Anciens noms acceptés en entrée (rétro-compat) → noms de l'article.
_THRESHOLD_ALIASES: dict = {
    "tau_selfloop": "attack_limit",
    "tau_ports": "port_scan_limit",
    "tau_unsafe_bgp": "unsafe_threshold",
}


def _normalize_thresholds(t: dict) -> dict:
    """Accepte les anciens noms de seuils et les mappe sur ceux de l'article."""
    out = dict(t)
    for old, new in _THRESHOLD_ALIASES.items():
        if old in out and new not in out:
            out[new] = out[old]
    return out

# Priorité décroissante : la 1ʳᵉ catégorie matchée devient la catégorie primaire.
PRIORITY = ["botnet", "worm", "dos", "port_scan", "unsafe", "monitored", "safe"]

# Tier de défense indicatif par catégorie.
DEFENSE_TIER = {
    "safe": "FW",
    "monitored": "FW+IDS(LOW)",   # surveillance légère (ni blocage, ni allow pur)
    "unsafe": "FW+IDS",
    "dos": "FW+IDS",
    "port_scan": "FW+IDS",
    "worm": "BLOCK",
    "botnet": "BLOCK",
}

# Mots-clés d'org « mauvaise réputation » (placeholder factuel avant BGP Ranking).
_BAD_ORG_KEYWORDS = ["bulletproof", "anonymous", "anonymizer", "proxy"]


@dataclass
class Classification:
    dst_ip: str
    primary: str                         # catégorie primaire (→ tier de défense)
    categories: list[str] = field(default_factory=list)   # toutes les catégories matchées
    score: int = 0                       # 0-10 (n'influence pas le tier)
    reputation: str = "unknown"
    defense_tier: str = "FW"
    evidence: dict = field(default_factory=dict)   # détails factuels (seuils franchis)


# ---------------------------------------------------------------------------
# Réputation (4 états) depuis le résultat du résolveur (étape 3)
# ---------------------------------------------------------------------------

def reputation_state(asn_result, unsafe_threshold: float | None = None) -> str:
    """Dérive l'état de réputation : trusted / untrusted / neutral / unknown.

    ``unsafe_threshold`` (variante BGP, opt-in) : si fourni ET que l'ASN a un
    bgp_rank ≥ seuil, la destination est ``untrusted`` (chemin SUPPLÉMENTAIRE vers
    untrusted, qui existe déjà via mots-clés). Défaut None → branche jamais prise :
    avec BGP off (ou bgp_rank=None), le résultat est STRICTEMENT identique à la baseline.
    """
    if asn_result is None or getattr(asn_result, "source", "unavailable") == "unavailable" \
            or not getattr(asn_result, "org", None):
        return "unknown"
    if getattr(asn_result, "is_trusted", False):
        return "trusted"
    org = (asn_result.org or "").lower()
    if any(k in org for k in _BAD_ORG_KEYWORDS):
        return "untrusted"
    # Variante BGP (opt-in) : réputation négative de l'ASN → untrusted. PRÉLIMINAIRE
    # tant que unsafe_threshold n'est pas calibré (cf. DEFAULT_THRESHOLDS).
    bgp_rank = getattr(asn_result, "bgp_rank", None)
    if bgp_rank is not None and unsafe_threshold is not None and bgp_rank >= unsafe_threshold:
        return "untrusted"
    return "neutral"


# ---------------------------------------------------------------------------
# Classification d'une destination
# ---------------------------------------------------------------------------

def classify(
    *,
    dst_ip: str = "?",
    bytes_total: int = 0,
    distinct_ports: int = 0,
    self_loop: float | None = 0.0,
    reputation: str = "unknown",
    label_type: str = "ORG",
    packets_total: int = 0,
    nb_flows: int = 0,
    thresholds: dict | None = None,
) -> Classification:
    """Classe une destination. Entrées = stats CSV + self-loop DOT + réputation.

    ``label_type`` (du parseur DOT) : worm/botnet ne sont dérivés QUE si == "ORG".
    Sur les automates "PORT", le self-loop est une propriété du PORT (pas de l'IP) :
    ce n'est pas un signal de comportement par IP, donc worm/botnet sont désactivés
    (limite documentée). DoS, port_scan (CSV) et safe/unsafe (réputation) restent
    valides sur les deux types.

    ``packets_total`` et ``nb_flows`` (Palier B) servent UNIQUEMENT à exposer les
    métriques de l'article — count(a) = nb_flows et avg_size = packets_total/nb_flows
    — comme SIGNAUX CORROBORANTS informationnels dans evidence. Elles n'entrent dans
    AUCUNE condition de catégorie : la classification est strictement inchangée.
    """
    t = _normalize_thresholds(thresholds or DEFAULT_THRESHOLDS)
    sl = self_loop or 0.0

    # ── Signaux bruts ───────────────────────────────────────────────────────
    dos = bytes_total >= t["tau_dos"]                 # VARIANTE PROPRE (volumétrique)
    port_scan = distinct_ports >= t["port_scan_limit"]   # article : |lf.ports| ≥ port_scan_limit
    # worm/botnet : self-loop p ≥ attack_limit, valide PAR IP uniquement sur ORG.
    selfloop_valid = (label_type == "ORG") and (sl >= t["attack_limit"])
    worm = selfloop_valid and reputation == "neutral"
    botnet = selfloop_valid and reputation in ("untrusted", "unknown")
    unsafe = reputation == "untrusted"

    # ── PROTECTION SAFE : org de confiance ──────────────────────────────────
    if reputation == "trusted":
        # worm/botnet déjà exclus (exigent non-trusted). On supprime dos/port_scan
        # SAUF s'il y a ≥ 2 signaux comportementaux indépendants (preuve forte).
        if sum([dos, port_scan]) < 2:
            dos = False
            port_scan = False

    # ── Agrégation par priorité ─────────────────────────────────────────────
    matched = []
    if botnet:
        matched.append("botnet")
    if worm:
        matched.append("worm")
    if dos:
        matched.append("dos")
    if port_scan:
        matched.append("port_scan")
    if unsafe:
        matched.append("unsafe")

    # ── Catégorie primaire (priorité + politique unknown) ────────────────────
    if matched:
        primary = matched[0]                          # un signal d'attaque l'emporte
    elif reputation == "trusted":
        primary = "safe"                              # RÈGLE D'OR : trusted = safe pur
    else:
        # neutral / unknown sans signal d'attaque → SURVEILLANCE par défaut.
        primary = "monitored"
    if not matched:
        matched = [primary]

    # ── Score 0-10 (indicatif, n'affecte pas le tier) ───────────────────────
    score = {"untrusted": 5, "unknown": 1, "neutral": 0, "trusted": 0}[reputation]
    score += 5 if botnet else 0
    score += 3 if worm else 0
    score += 2 if dos else 0
    score += 2 if port_scan else 0
    if primary == "monitored":
        score = max(score, 1)
    score = min(score, 10)

    # ── Palier B : métriques article en SIGNAUX CORROBORANTS (informationnels) ─
    # count(a) = nb d'occurrences (flux) de l'IP ; avg_size = paquets moyens / flux.
    # corroborates_* indiquent si le critère de l'article serait satisfait — pour
    # information/audit seulement : ils n'ont AUCUN effet sur primary/categories/score.
    count_a = nb_flows
    avg_size = round(packets_total / nb_flows, 2) if nb_flows else 0.0
    corroboration = {
        "count_a": count_a,            # = count(a) de l'article (lf.count(a))
        "avg_size": avg_size,          # = lf.avg_size (paquets / flux)
        "ip_limit": t.get("ip_limit"),
        "min_size": t.get("min_size"),
        # critères article (informationnels — n'altèrent pas la catégorie) :
        "ip_limit_met": (count_a >= t["ip_limit"]) if t.get("ip_limit") is not None else None,
        "min_size_met": (0 < avg_size <= t["min_size"]) if t.get("min_size") is not None else None,
    }

    evidence = {
        "bytes_total": bytes_total, "distinct_ports": distinct_ports,
        "self_loop": round(sl, 3), "reputation": reputation, "label_type": label_type,
        "selfloop_used": selfloop_valid,   # False sur PORT (limite documentée)
        "triggers": {"dos": dos, "port_scan": port_scan, "worm": worm,
                     "botnet": botnet, "unsafe": unsafe},
        "corroboration": corroboration,    # Palier B — informationnel, sans effet
        "thresholds": {k: t[k] for k in ("attack_limit", "port_scan_limit", "tau_dos")},
    }

    return Classification(
        dst_ip=dst_ip, primary=primary, categories=matched or ["safe"],
        score=score, reputation=reputation, defense_tier=DEFENSE_TIER[primary],
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Batterie de tests (synthétiques + réel pokemongo), SANS LLM, SANS réseau
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    T = DEFAULT_THRESHOLDS
    print("Seuils :", {k: T[k] for k in ("attack_limit", "port_scan_limit", "tau_dos")})
    print("=" * 78)

    cases = [
        ("Google trusted self-loop 0.78 (anti-FP)", dict(bytes_total=105_000, distinct_ports=1, self_loop=0.78, reputation="trusted"), "safe"),
        ("Trusted MÊME avec self-loop 0.85 (protection)", dict(bytes_total=200_000, distinct_ports=1, self_loop=0.85, reputation="trusted"), "safe"),
        ("Volume élevé 5 Mo (neutral)", dict(bytes_total=5_000_000, distinct_ports=1, self_loop=0.1, reputation="neutral"), "dos"),
        ("15 ports distincts (neutral)", dict(bytes_total=10_000, distinct_ports=15, self_loop=0.1, reputation="neutral"), "port_scan"),
        ("Self-loop 0.9 + org inconnue", dict(bytes_total=10_000, distinct_ports=1, self_loop=0.9, reputation="unknown"), "botnet"),
        ("Self-loop 0.9 + org neutral", dict(bytes_total=10_000, distinct_ports=1, self_loop=0.9, reputation="neutral"), "worm"),
        ("Untrusted seul (mauvaise rep)", dict(bytes_total=10_000, distinct_ports=1, self_loop=0.1, reputation="untrusted"), "unsafe"),
        ("PRIORITÉ : botnet+dos+portscan", dict(bytes_total=5_000_000, distinct_ports=15, self_loop=0.9, reputation="untrusted"), "botnet"),
        ("PRIORITÉ : dos+portscan (neutral)", dict(bytes_total=5_000_000, distinct_ports=15, self_loop=0.1, reputation="neutral"), "dos"),
        ("Trusted + dos+portscan = 2 signaux forts → gardés", dict(bytes_total=5_000_000, distinct_ports=15, self_loop=0.1, reputation="trusted"), "dos"),
    ]
    ok = 0
    for name, kw, expected in cases:
        c = classify(**kw)
        verdict = "✅" if c.primary == expected else "❌"
        if c.primary == expected:
            ok += 1
        print(f"  {verdict} {name:<48} → primary={c.primary:<10} "
              f"(attendu {expected}) cats={c.categories} score={c.score} tier={c.defense_tier}")
    print("=" * 78)
    print(f"  Synthétiques : {ok}/{len(cases)} OK")

    # ── Passe RÉELLE pokemongo (comportemental seul : réputation unknown,
    #    self-loop non joint par IP tant que la base ASN manque) ──────────────
    print("\n" + "=" * 78)
    print("  RÉEL pokemongo (réputation=unknown, self-loop non joint → comportemental)")
    print("=" * 78)
    try:
        from enrichment.csv_reader import read_app
        r = read_app("pokemongo")
        counts: dict[str, int] = {}
        for ep in r.endpoints.values():
            c = classify(dst_ip=ep.dst_ip, bytes_total=ep.bytes_total,
                         distinct_ports=len(ep.ports), self_loop=0.0, reputation="unknown")
            counts[c.primary] = counts.get(c.primary, 0) + 1
        print(f"  {len(r.endpoints)} IP destinations → répartition catégories : {counts}")
        print("  (toutes 'safe' attendu : volumes < 1 Mo, 1 port, self-loop non disponible)")
    except Exception as exc:
        print(f"  (passe réelle indisponible : {exc})")
