# P4 — Décision par DOMAINE / SNI au runtime : faisabilité

## Ce que c'est
Capturer, au moment de la connexion, le vrai NOM que le client demande — SNI du ClientHello TLS
(server_name) ou nom de la requête DNS forward (api.viber.com) — pour décider par DOMAINE au lieu
du /16. But : rattraper le malware CO-HÉBERGÉ (même /16/cloud que l'app) que /16, ASN et réputation ratent.

## 1. Fichiers/fonctions touchés
- ryu_app/sdn_executor.py:_setup_switch  → flow udp/53 → CONTROLLER (voir le DNS) ou allow-then-inspect (SNI)
- ryu_app/sdn_executor.py:_handle_unknown_flow → parser DNS/SNI depuis pkt, construire table IP↔domaine
- ryu_app/sdn_executor.py:_hybrid_decide → décider par domaine
- NOUVEAU whitelist/apk_domains.py → extraire les domaines forward légitimes depuis l'APK (profil)
- NOUVEAU parseur DNS/SNI (os-ken n'a PAS de parseur dns → manuel ou dnslib)
- benchmark/live_eval.py → trafic NOMMÉ (curl/openssl) au lieu de hping3→IP (sinon rien à capturer)

## 2. Deux voies
A. DNS forward (simple) : mirror udp/53 → contrôleur, parser la réponse DNS → IP↔domaine.
   - aujourd'hui DNS = ALLOW NORMAL (make_whitelist_automate.py:39) → forwardé, pas vu → ajouter le mirror.
   - contourné par DoH/DoT (chiffré).
B. SNI TLS (robuste mais dur) : parser server_name du ClientHello (443).
   - contrôleur reçoit le paquet ENTIER (OFPCML_NO_BUFFER) → peut parser.
   - MAIS la table-miss ne donne que le SYN (pas de SNI) → laisser le handshake se faire
     (allow-then-inspect, stateful) → change la posture fail-closed.
   - contourné par ECH (SNI chiffré, rare).

## 3. Trou de données (vrai blocage)
Profil des domaines forward légitimes : absent des traces (rDNS only).
Sources : APK static (partiel : viber.com/dropbox.com OK, sur-approximé, faceswitch→rien) OU capture live (Android abandonné).

## 4. Risques
- allow-then-inspect ouvre une fenêtre (1er flux passe avant inspection) → affaiblit fail-closed.
- table IP↔domaine partagée contrôleur↔service = même piège inter-processus que le cookie → store partagé (Redis).
- DoH/ECH → angles morts.
- rejeu hping3→IP = rien à capturer → besoin trafic nommé.

## 5. Limite conceptuelle (= sa FORCE)
P4 = IDENTITÉ (le nom demandé), pas réputation → distingue api.viber.com de api.lequipe.fr sur le MÊME AWS
→ attrape le co-hébergé ET un C2 inédit (s'il a un domaine ≠ ceux de l'app). Seul signal visant le coin idéal
(recall haut + FPR bas). Limite : nom en clair requis (SNI/DNS non chiffrés) + profil forward. ECH → aveugle.

## 6. Verdict
Faisable en principe mais PAS avant la soutenance (2 chantiers + trou de données + piège inter-processus).
→ ARCHITECTURE CIBLE / direction principale. Point fort : l'évaluation offline PROUVE déjà que le domaine
serait le meilleur (FNR 0, meilleur F1) → P4 est motivé par les résultats, même non implémenté.
