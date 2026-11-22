"""
architectures/ — Architectures multi-agents comparées dans ce stage.

Ce paquet regroupe les DIFFÉRENTES façons d'orchestrer les mêmes agents de
sécurité SDN, afin de les comparer expérimentalement :

- L'architecture LINÉAIRE (baseline) vit toujours à la racine
  (``graph_phase2.py``) et n'est PAS déplacée ici.
- L'architecture SUPERVISEUR (nouvelle) est définie dans
  ``architectures/supervisor/`` : un nœud chef route dynamiquement vers les
  sous-agents via des arêtes conditionnelles.

Les deux architectures réutilisent les MÊMES agents (``agents/*.py``) et le
même état (``state.py``) — seule l'orchestration change.
"""
