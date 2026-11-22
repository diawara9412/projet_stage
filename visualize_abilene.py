"""Génère une image PNG de la topologie Abilene pour les slides."""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Pas besoin d'affichage interactif
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# Charger Abilene depuis le fichier Topology Zoo
graphml_path = "/home/kali/Desktop/projet/topologies/Abilene.graphml"
G = nx.read_graphml(graphml_path)

# Renommer les nœuds avec un format clair
node_labels = {n: f"s{i}\n+\nh{i}" for i, n in enumerate(G.nodes())}

# Calculer un layout reproductible avec spring force
pos = nx.spring_layout(G, seed=42, k=2.0, iterations=100)

# Créer la figure
fig, ax = plt.subplots(figsize=(14, 10))

# Dessiner les liens (les fibres inter-switches)
nx.draw_networkx_edges(
    G, pos,
    edge_color='#2C3E50',
    width=2.5,
    alpha=0.6,
    ax=ax
)

# Dessiner les nœuds (chaque cercle = switch + host attaché)
nx.draw_networkx_nodes(
    G, pos,
    node_color='#3498DB',
    node_size=3500,
    edgecolors='#1F4E79',
    linewidths=3,
    ax=ax
)

# Dessiner les labels à l'intérieur des nœuds
nx.draw_networkx_labels(
    G, pos,
    labels=node_labels,
    font_size=10,
    font_weight='bold',
    font_color='white',
    ax=ax
)

# Titre principal
ax.set_title(
    "Topologie SDN Abilene (Internet Topology Zoo)\n"
    f"{len(G.nodes())} switches Open vSwitch + {len(G.nodes())} hosts + {len(G.edges())} liens inter-switches",
    fontsize=15,
    fontweight='bold',
    pad=20
)

# Légende
legend_elements = [
    mpatches.Patch(
        facecolor='#3498DB',
        edgecolor='#1F4E79',
        label='Switch SDN (OVS) avec host attaché'
    ),
    mpatches.Patch(
        facecolor='#2C3E50',
        label='Lien inter-switch (fibre)'
    ),
]
ax.legend(
    handles=legend_elements,
    loc='lower right',
    fontsize=11,
    framealpha=0.9
)

ax.axis('off')
plt.tight_layout()

# Créer le dossier captures si nécessaire
output_dir = Path("/home/kali/Desktop/projet/captures")
output_dir.mkdir(parents=True, exist_ok=True)

# Sauvegarder l'image
output_path = output_dir / "abilene_topology.png"
plt.savefig(
    output_path,
    dpi=150,
    bbox_inches='tight',
    facecolor='white',
    edgecolor='none'
)
plt.close()

# Afficher quelques statistiques
print("=" * 60)
print("✅ Image générée avec succès")
print("=" * 60)
print(f"  Fichier         : {output_path}")
print(f"  Taille topologie : {len(G.nodes())} nœuds, {len(G.edges())} liens")
print(f"  Source          : Internet Topology Zoo")
print()
print("Pour l'ouvrir :")
print(f"  xdg-open {output_path}")
print("=" * 60)
