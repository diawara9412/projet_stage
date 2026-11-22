#!/bin/bash
# test_complet.sh — TEST COMPLET du système (projet_chaine)
#   Phase 1 : contrôleur (FW s1 + IDS s2 + réputation/16 + agents + SNI + beaconing) + réseau
#   Phase 2 : les AGENTS déploient la whitelist → le contrôleur RÉPARTIT (FW→s1, IDS→s2)
#   Phase 3 : rejeu du dataset Mischief (couches IP : s1 + contrôleur + agents) + qui attrape quoi
#   Phase 4 : s2 attrape le DOMAINE (SNI)
#   Phase 5 : s2 attrape le COMPORTEMENT (beaconing)
#   + capture 2 pcaps (côté h0 / côté IDS) pour Wireshark
export SUDO_ASKPASS=/home/kali/.askpass.sh
cd /home/kali/Desktop/projet_chaine || exit 1
D=/home/kali/Desktop/demo_run ; mkdir -p "$D"
PCAP=/home/kali/Desktop
say(){ echo; echo "═══════════════ $* ═══════════════"; }
S(){ sudo -A "$@"; }

# ── 0. nettoyage ──
redis-cli del sdn:anomalies >/dev/null 2>&1
S fuser -k 6653/tcp 8080/tcp 2>/dev/null; sleep 1
S mn -c >/dev/null 2>&1
rm -f "$D/topo.run" "$D/h0.pid" "$PCAP"/test_*.pcap

say "PHASE 1 — Contrôleur (tous les modes) + réseau h0→s1(FW)→s2(IDS)→nat"
nohup sudo -A python3 ryu_app/run_manager.py ryu_app.sdn_executor --hybrid --sfc --stateful --inspect > "$D/ctrl.log" 2>&1 &
for i in $(seq 1 25); do ss -ltn 2>/dev/null | grep -q ':6653' && break; sleep 1; done
ss -ltn 2>/dev/null | grep -q ':6653' && echo "  ✓ contrôleur up" || { echo "  ✗ contrôleur KO"; exit 1; }
nohup sudo -A python3 "$D/topo_bg.py" > "$D/topo.log" 2>&1 &
for i in $(seq 1 30); do grep -q TOPO_UP "$D/topo.log" 2>/dev/null && break; sleep 1; done
H0=$(cat "$D/h0.pid" 2>/dev/null); echo "  ✓ réseau up (h0 pid=$H0)"

say "PHASE 2 — Les AGENTS déploient la whitelist → le contrôleur RÉPARTIT sur s1/s2"
timeout 240 python3 architectures/supervisor/run_supervisor_test.py --deploy --automate dropbox_whitelist > "$D/deploy.log" 2>&1
grep -E "installée sur switch" "$D/ctrl.log" | sed 's/.*sdn_executor: /  /' | tail -2
echo "  → s1 (FW)  : $(S ovs-ofctl dump-flows s1 -O OpenFlow13 | grep -cE 'priority=(100|950|50)') règles firewall (ALLOW/BLOCK/LAN)"
echo "  → s2 (IDS) : $(S ovs-ofctl dump-flows s2 -O OpenFlow13 | grep -cE 'priority=900') signatures IDS"
nohup python3 -u architectures/supervisor/supervisor_service.py --app dropbox --agentic > "$D/service.log" 2>&1 &
sleep 4; echo "  ✓ service agentique en écoute"

# ── captures Wireshark ──
S tcpdump -i s1-eth1 -w "$PCAP/test_cote_h0.pcap" -U >/dev/null 2>&1 &
S tcpdump -i s2-eth1 -w "$PCAP/test_cote_IDS.pcap" -U >/dev/null 2>&1 &
sleep 1

say "PHASE 3 — Rejeu du dataset MISCHIEF (couches IP)"
timeout 180 sudo -A python3 benchmark/live_eval.py --app dropbox 2>&1 | grep -E "benign|mal_|Matrice|Accuracy"
echo "  ── qui a attrapé quoi (couches IP) ──"
echo "    • RÉPUTATION → BLOCK (contrôleur, C2 connus) : $(grep -c 'RÉPUTATION malveillante' "$D/ctrl.log")"
echo "    • /16 connu → ALLOW (contrôleur, cohost=fuite)  : $(grep -c '/16 connu' "$D/ctrl.log")"
echo "    • AMBIGU → escaladé aux AGENTS (whois/asn)      : $(grep -c 'ESCALADÉ aux agents' "$D/ctrl.log")"

say "PHASE 4 — s2 attrape le DOMAINE (SNI) : IP de confiance + domaine C2"
cat > "$D/c_sni.json" <<'EOF'
{"chain_id":"sni","source_app_name":"sni","global_risk_level":"medium","firewall_rules":[
 {"id":"W","action":"ALLOW_AND_INSPECT","dst_ip":"8.8.8.8","protocol":"TCP","dst_port":443,"priority":100},
 {"id":"L","action":"ALLOW","dst_ip":"10.0.0.0/24","protocol":"any","priority":50},
 {"id":"A","action":"ALLOW","dst_ip":"any","protocol":"ARP","priority":50}],
 "ids_signatures":[{"id":"S","name":"SNI","pattern_type":"suspicious_url","match_criteria":{"dst_ip":"8.8.8.8","protocol":"TCP","dst_port":443},"severity":"HIGH","comment":"sni"}],"ips_actions":[]}
EOF
curl -s --max-time 10 -X POST -H 'Content-Type: application/json' -d @"$D/c_sni.json" http://127.0.0.1:8080/firewall/install >/dev/null
sleep 1
timeout 15 sudo -A mnexec -a "$H0" bash -c "echo | openssl s_client -connect 8.8.8.8:443 -servername test-c2.evil.com >/dev/null 2>&1"
sleep 2
grep -E "IDS SNI : domaine MALVEILLANT" "$D/ctrl.log" | sed 's/.*sdn_executor: /  /' | tail -1
S ovs-ofctl dump-flows s1 -O OpenFlow13 | grep -qE "priority=950,ip,nw_dst=8.8.8.8" && echo "  → s1 BLOQUE 8.8.8.8 (déclenché par s2/domaine)" || echo "  (pas de block SNI)"

say "PHASE 5 — s2 attrape le COMPORTEMENT (beaconing) : rappels réguliers"
cat > "$D/c_beacon.json" <<'EOF'
{"chain_id":"beacon","source_app_name":"beacon","global_risk_level":"medium","firewall_rules":[
 {"id":"W","action":"ALLOW_AND_INSPECT","dst_ip":"192.0.2.5","protocol":"TCP","dst_port":443,"priority":100},
 {"id":"L","action":"ALLOW","dst_ip":"10.0.0.0/24","protocol":"any","priority":50},
 {"id":"A","action":"ALLOW","dst_ip":"any","protocol":"ARP","priority":50}],
 "ids_signatures":[{"id":"B","name":"BEACON","pattern_type":"beaconing","match_criteria":{"dst_ip":"192.0.2.5","protocol":"TCP","dst_port":443},"severity":"MEDIUM","comment":"beacon"}],"ips_actions":[]}
EOF
curl -s --max-time 10 -X POST -H 'Content-Type: application/json' -d @"$D/c_beacon.json" http://127.0.0.1:8080/firewall/install >/dev/null
sleep 1
timeout 40 sudo -A mnexec -a "$H0" bash -c 'for i in $(seq 1 8); do hping3 -S -c 1 --fast -p 443 192.0.2.5 >/dev/null 2>&1; sleep 1.2; done'
sleep 2
grep -E "BEACONING" "$D/ctrl.log" | sed 's/.*sdn_executor: /  /' | tail -1
S ovs-ofctl dump-flows s1 -O OpenFlow13 | grep -qE "priority=950,ip,nw_dst=192.0.2.5" && echo "  → s1 BLOQUE 192.0.2.5 (déclenché par s2/comportement)" || echo "  (pas de block beaconing)"

say "RÉCAP — qui attrape quoi"
cat <<'EOF'
  IP C2 connue (réputation)   → contrôleur → BLOCK sur s1        (l'IDS ne sert pas)
  cohost (même /16)           → contrôleur → ALLOW sur s1        (fuite /16 assumée)
  inconnu (org)               → AGENTS (whois/asn) → BLOCK ou ALLOW_AND_INSPECT
  domaine malveillant (SNI)   → s2 copie → contrôleur → BLOCK s1  ← rôle unique de s2
  beaconing (comportement)    → s2 copie → contrôleur → BLOCK s1  ← rôle unique de s2
EOF
echo "  Pcaps Wireshark : $PCAP/test_cote_h0.pcap  et  $PCAP/test_cote_IDS.pcap"

# ── teardown ──
S pkill -f "tcpdump -i s" 2>/dev/null
rm -f "$D/topo.run"; sleep 2
ps -eo pid,args | awk '/[s]upervisor_service\.py/{print $1}' | while read p; do kill "$p" 2>/dev/null; done
S fuser -k 6653/tcp 8080/tcp 2>/dev/null; sleep 1
S mn -c >/dev/null 2>&1
S chmod 644 "$PCAP"/test_*.pcap 2>/dev/null
echo; echo "✓ Test complet terminé. Environnement nettoyé."
