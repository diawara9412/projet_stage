"""
architectures/supervisor/ — Architecture de type SUPERVISEUR.

Contenu :
- ``supervisor_agent.py`` : le nœud chef + la logique de routage conditionnel.
- ``graph_supervisor.py`` : construction du graphe LangGraph (arêtes
  conditionnelles, pas fixes).
- ``run_supervisor_test.py`` : point d'entrée de test du routage.

État de l'avancement (incrémental) :
- Étape 1 (actuelle) : le Superviseur ne sait router que vers UN sous-agent,
  l'Analyzer (réutilise ``agents/chain_analyzer.py``).
- Étapes suivantes : ajout des agents Firewall, IDS, IPS, Déployeur, un par un.
"""
