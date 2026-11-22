"""Dashboard Streamlit pour visualiser la topologie SDN."""
import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
import json
from pathlib import Path

st.set_page_config(page_title="Stage SDN - Multi-agents LangGraph", layout="wide")

st.title("🌐 Système multi-agents SDN pour simulation réseau")
st.markdown("**Stage TELECOM Nancy / INRIA RESIST** — Encadré par M. Badonnel")

# Sidebar pour les paramètres
st.sidebar.header("Configuration")

topology_choice = st.sidebar.selectbox(
    "Topologie à déployer",
    ["Abilene (11 nœuds)", "Geant2012 (40 nœuds)"]
)

attack_choice = st.sidebar.selectbox(
    "Type d'attaque",
    ["SYN flood (DDoS)", "Port scan (reconnaissance)"]
)

# Deux colonnes : visualisation à gauche, infos à droite
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("📊 Topologie SDN")
    
    # Charger et afficher la topologie
    topo_name = topology_choice.split(" ")[0]
    G = nx.read_graphml(f"/home/kali/Desktop/projet/topologies/{topo_name}.graphml")
    
    fig, ax = plt.subplots(figsize=(10, 7))
    pos = nx.spring_layout(G, seed=42, k=1.5)
    
    node_labels = {n: f"s{i}\n(h{i})" for i, n in enumerate(G.nodes())}
    
    nx.draw_networkx_edges(G, pos, edge_color='gray', width=2, alpha=0.6, ax=ax)
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=2000,
                            edgecolors='darkblue', linewidths=2, ax=ax)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=9,
                             font_weight='bold', ax=ax)
    
    ax.set_title(f"Topologie {topo_name}")
    ax.axis('off')
    
    st.pyplot(fig)

with col2:
    st.subheader("📈 Statistiques")
    st.metric("Nœuds", len(G.nodes()))
    st.metric("Liens", len(G.edges()))
    st.metric("Degré moyen", round(sum(dict(G.degree()).values()) / len(G.nodes()), 2))
    
    st.subheader("🎯 Architecture des agents")
    st.markdown("""
    - **Supervisor** : orchestre les workers
    - **TopologyDesigner** : déploie la topologie
    - **TrafficGenerator** : génère le trafic légitime
    - **AttackSimulator** : lance les attaques
    """)
    
    st.subheader("🛠️ Outils techniques")
    st.markdown("""
    - **LangGraph** : framework multi-agents
    - **Groq + Llama 3.3 70B** : LLM des agents
    - **Mininet** : émulation réseau SDN
    - **Open vSwitch** : switches programmables
    - **hping3 + nmap** : attaques
    """)

st.markdown("---")
st.subheader("🚀 Lancement de la simulation")

if st.button("▶️ Lancer la simulation complète"):
    st.info("Pour lancer la simulation, ouvre un terminal et tape :")
    st.code("sudo -E python3 main.py --request 'Demo SDN' --topology-hint small --attacks syn_flood --stream")

# Section pour afficher le dernier rapport
st.markdown("---")
st.subheader("📄 Dernier rapport de simulation")

captures_dir = Path("/home/kali/Desktop/projet/captures")
reports = sorted(captures_dir.glob("simulation_report_*.md"), reverse=True)

if reports:
    latest = reports[0]
    st.markdown(f"**Fichier** : `{latest.name}`")
    with open(latest) as f:
        st.markdown(f.read())
else:
    st.info("Aucune simulation lancée pour l'instant.")
