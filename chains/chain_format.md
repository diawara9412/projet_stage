# Format JSON d'une Chaîne de Sécurité

## Présentation

Une chaîne de sécurité est le résultat de l'analyse d'un automate réseau. Elle regroupe trois couches de protection complémentaires :

1. **Firewall** (`firewall_rules`) — filtrage statique du trafic
2. **IDS** (`ids_signatures`) — détection d'intrusions basée sur des signatures
3. **IPS** (`ips_actions`) — réponses automatiques aux détections

La chaîne est consommée par le `PolicyEnforcer` pour déployer les règles sur les switches OVS via le contrôleur Ryu.

---

## Schéma JSON racine

```json
{
  "chain_id": "string",
  "app_name": "string",
  "automate_id": "string",
  "generated_at": "string (ISO 8601)",
  "risk_level": "string",
  "global_suspicion_score": 0.0,
  "firewall_rules": [ ... ],
  "ids_signatures": [ ... ],
  "ips_actions": [ ... ],
  "deployment": { ... }
}
```

---

## Champs racine

| Champ                    | Type   | Obligatoire | Exemple                   | Signification                                             |
|--------------------------|--------|-------------|---------------------------|-----------------------------------------------------------|
| `chain_id`               | string | Oui         | `"chain_pokemon_go_v1"`   | Identifiant unique de la chaîne                           |
| `app_name`               | string | Oui         | `"Pokemon GO"`            | Application concernée                                     |
| `automate_id`            | string | Oui         | `"pokemon_go_v1"`         | Référence vers l'automate source                          |
| `generated_at`           | string | Non         | `"2024-04-15T15:00:00Z"`  | Horodatage de génération (ISO 8601)                       |
| `risk_level`             | string | Oui         | `"medium"`                | Niveau de risque global : `low`, `medium`, `high`, `critical` |
| `global_suspicion_score` | float  | Oui         | `3.2`                     | Score de suspicion global (0.0 à 10.0)                    |
| `firewall_rules`         | array  | Oui         | voir ci-dessous           | Règles de filtrage                                        |
| `ids_signatures`         | array  | Oui         | voir ci-dessous           | Signatures de détection                                   |
| `ips_actions`            | array  | Oui         | voir ci-dessous           | Actions de réponse automatique                            |
| `deployment`             | object | Non         | voir ci-dessous           | Paramètres de déploiement OVS/Ryu                         |

---

## Section `firewall_rules`

Chaque règle de pare-feu définit un filtre statique appliqué sur le trafic entrant et sortant.

```json
{
  "rule_id": "string",
  "priority": 100,
  "action": "string",
  "direction": "string",
  "match": {
    "src_ip": "string",
    "dst_ip": "string",
    "src_port": null,
    "dst_port": 443,
    "protocol": "string",
    "ip_range": "string"
  },
  "description": "string",
  "rationale": "string"
}
```

### Champs d'une règle firewall

| Champ         | Type   | Obligatoire | Exemple              | Signification                                              |
|---------------|--------|-------------|----------------------|------------------------------------------------------------|
| `rule_id`     | string | Oui         | `"fw_allow_niantic"` | Identifiant unique de la règle                             |
| `priority`    | int    | Oui         | `100`                | Priorité d'application (plus élevé = appliqué en premier) |
| `action`      | string | Oui         | `"allow"` / `"block"` / `"log"` | Action à effectuer                            |
| `direction`   | string | Oui         | `"outbound"` / `"inbound"` / `"both"` | Sens du trafic filtré                  |
| `match.src_ip`   | string | Non      | `"10.0.0.0/8"`       | IP source ou CIDR à matcher                                |
| `match.dst_ip`   | string | Non      | `"35.190.0.0/16"`    | IP destination ou CIDR à matcher                          |
| `match.src_port` | int   | Non      | `null`               | Port source (`null` = tous)                                |
| `match.dst_port` | int   | Non      | `443`                | Port destination (`null` = tous)                           |
| `match.protocol` | string | Non     | `"TCP"` / `"UDP"` / `"ICMP"` / `"any"` | Protocole                         |
| `match.ip_range` | string | Non     | `"185.220.101.0/24"` | CIDR alternatif (pour groupes d'IPs)                       |
| `description` | string | Non         | `"Autorise Niantic"` | Description fonctionnelle                                  |
| `rationale`   | string | Non         | `"Service légitime"` | Justification de la règle                                  |

**Valeurs de `action` :**
- `allow` : laisser passer le paquet
- `block` : rejeter le paquet (DROP)
- `log` : laisser passer mais enregistrer dans les logs
- `block_and_log` : rejeter et enregistrer

---

## Section `ids_signatures`

Chaque signature IDS décrit un **pattern de trafic suspect** à surveiller. Lorsqu'une correspondance est détectée, une alerte est générée.

```json
{
  "sig_id": "string",
  "name": "string",
  "type": "string",
  "severity": "string",
  "match": {
    "pattern_type": "string",
    "dst_ip": "string",
    "dst_port": null,
    "protocol": "string",
    "payload_regex": null,
    "frequency_threshold": null,
    "window_seconds": null,
    "byte_threshold": null
  },
  "description": "string",
  "mitre_attack": "string"
}
```

### Champs d'une signature IDS

| Champ                       | Type   | Obligatoire | Exemple                         | Signification                                          |
|-----------------------------|--------|-------------|---------------------------------|--------------------------------------------------------|
| `sig_id`                    | string | Oui         | `"ids_beaconing_c2"`            | Identifiant unique de la signature                     |
| `name`                      | string | Oui         | `"Détection beaconing C2"`      | Nom lisible                                            |
| `type`                      | string | Oui         | voir tableau ci-dessous         | Catégorie de la détection                              |
| `severity`                  | string | Oui         | `"low"` / `"medium"` / `"high"` / `"critical"` | Sévérité de l'alerte          |
| `match.pattern_type`        | string | Oui         | `"frequency"` / `"regex"` / `"threshold"` / `"ip_list"` | Type de matching   |
| `match.dst_ip`              | string | Non         | `"185.220.101.0/24"`            | IP destination ciblée                                  |
| `match.dst_port`            | int    | Non         | `9001`                          | Port destination                                       |
| `match.protocol`            | string | Non         | `"TCP"`                         | Protocole                                              |
| `match.payload_regex`       | string | Non         | `"/(cmd\|exec\|shell)/"`        | Expression régulière sur le payload                    |
| `match.frequency_threshold` | int    | Non         | `30`                            | Nombre d'occurrences avant déclenchement               |
| `match.window_seconds`      | int    | Non         | `60`                            | Fenêtre de temps pour le comptage (secondes)           |
| `match.byte_threshold`      | int    | Non         | `50000`                         | Volume de données (octets) avant déclenchement         |
| `description`               | string | Non         | `"Connexions régulières vers..."` | Description de la signature                          |
| `mitre_attack`              | string | Non         | `"T1071.001"`                   | Technique MITRE ATT&CK correspondante                  |

**Valeurs de `type` :**

| Type                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `syn_flood`           | Déluge de paquets SYN (DDoS TCP)                                 |
| `port_scan`           | Balayage de ports séquentiels ou aléatoires                     |
| `beaconing`           | Appels répétitifs vers un C2 à intervalle régulier              |
| `data_exfiltration`   | Volume de données sortantes anormalement élevé                  |
| `tor_communication`   | Communication avec un nœud Tor connu                            |
| `dga_detection`       | Résolution de domaines générés algorithmiquement                |
| `suspicious_path`     | Requête HTTP vers des chemins suspects                           |
| `self_signed_cert`    | Négociation TLS avec certificat auto-signé                       |
| `protocol_anomaly`    | Protocole utilisé sur un port non standard                       |
| `geo_anomaly`         | Trafic vers un pays non attendu pour l'application              |

---

## Section `ips_actions`

Chaque action IPS définit la **réponse automatique** déclenchée lorsqu'une signature IDS est activée.

```json
{
  "action_id": "string",
  "triggered_by": "string",
  "action_type": "string",
  "target": "string",
  "parameters": {
    "duration_seconds": 300,
    "rate_limit_kbps": null,
    "alert_channel": "string",
    "block_direction": "string"
  },
  "description": "string"
}
```

### Champs d'une action IPS

| Champ                        | Type   | Obligatoire | Exemple                      | Signification                                              |
|------------------------------|--------|-------------|------------------------------|------------------------------------------------------------|
| `action_id`                  | string | Oui         | `"ips_block_tor"`            | Identifiant unique de l'action                             |
| `triggered_by`               | string | Oui         | `"ids_tor_communication"`    | `sig_id` de la signature IDS associée                      |
| `action_type`                | string | Oui         | voir tableau ci-dessous      | Type d'action à effectuer                                  |
| `target`                     | string | Oui         | `"src_ip"` / `"dst_ip"` / `"flow"` | Cible de l'action                                    |
| `parameters.duration_seconds`| int    | Non         | `300`                        | Durée du blocage ou de la limitation (secondes)            |
| `parameters.rate_limit_kbps` | int    | Non         | `128`                        | Débit maximum autorisé (kbps) pour `rate_limit`            |
| `parameters.alert_channel`   | string | Non         | `"syslog"` / `"email"` / `"slack"` | Canal de notification                              |
| `parameters.block_direction` | string | Non         | `"outbound"` / `"both"`     | Direction du blocage                                       |
| `description`                | string | Non         | `"Bloquer toute comm. Tor"` | Description de l'action                                    |

**Valeurs de `action_type` :**

| Type              | Description                                                         |
|-------------------|---------------------------------------------------------------------|
| `block_source`    | Bloquer toutes les connexions depuis l'IP source                    |
| `block_dest`      | Bloquer toutes les connexions vers l'IP destination                 |
| `block_flow`      | Bloquer le flux spécifique (5-tuple : src/dst IP+port+proto)        |
| `rate_limit`      | Limiter le débit du flux suspect                                    |
| `quarantine`      | Isoler l'hôte source du reste du réseau                            |
| `alert`           | Envoyer une alerte sans bloquer (mode moniteur)                     |
| `reset_connection`| Envoyer un RST TCP pour terminer la connexion                       |
| `redirect`        | Rediriger le trafic vers un honeypot ou un proxy d'analyse          |

---

## Section `deployment`

Paramètres techniques pour le déploiement via Ryu sur les switches OVS.

```json
{
  "target_switches": ["s1", "s2"],
  "ryu_controller_ip": "127.0.0.1",
  "ryu_controller_port": 6633,
  "openflow_version": "1.3",
  "table_id": 0,
  "idle_timeout": 300,
  "hard_timeout": 3600
}
```

| Champ                 | Type   | Obligatoire | Exemple            | Signification                                       |
|-----------------------|--------|-------------|--------------------|----------------------------------------------------|
| `target_switches`     | array  | Oui         | `["s1", "s2"]`     | Liste des switches OVS cibles                       |
| `ryu_controller_ip`   | string | Non         | `"127.0.0.1"`      | IP du contrôleur Ryu                                |
| `ryu_controller_port` | int    | Non         | `6633`             | Port OpenFlow du contrôleur                         |
| `openflow_version`    | string | Non         | `"1.3"`            | Version OpenFlow utilisée                           |
| `table_id`            | int    | Non         | `0`                | Table de flux OVS cible (0 = table principale)      |
| `idle_timeout`        | int    | Non         | `300`              | Expiration du flux après inactivité (secondes)      |
| `hard_timeout`        | int    | Non         | `3600`             | Expiration maximale du flux (secondes)              |

---

## Niveau de priorité

L'ordre d'application des règles suit cette hiérarchie (du plus prioritaire au moins prioritaire) :

```
1. IPS block_source / block_dest (priorité absolue, déclenchement temps réel)
2. Firewall BLOCK avec haute priorité (≥ 900)
3. Firewall BLOCK avec priorité standard (100–899)
4. Firewall LOG (observation sans blocage)
5. Firewall ALLOW explicite
6. Règle par défaut : BLOCK tout trafic non matché (politique restrictive)
```

### Plages de priorité recommandées

| Plage       | Usage                                                       |
|-------------|-------------------------------------------------------------|
| 900 – 1000  | Blocage immédiat (Tor, C2 connu, malware confirmé)          |
| 500 – 899   | Blocage conditionnel (IP suspecte, pays à risque)           |
| 200 – 499   | Limitation de débit (rate limiting)                         |
| 100 – 199   | Journalisation et monitoring                                |
| 10 – 99     | Autorisation de services légitimes                          |
| 1           | Règle par défaut (catch-all)                                |

---

## Bonnes pratiques

### Cohérence interne

1. **Chaque `ips_action.triggered_by` doit référencer un `sig_id` existant** dans `ids_signatures`. Une action sans signature associée ne sera jamais déclenchée.
2. **Les IPs bloquées au firewall ne nécessitent pas de signature IDS** — la détection IDS est réservée aux comportements dynamiques (fréquence, volume, patterns).
3. **Ne pas dupliquer les règles** : si une IP est déjà bloquée par une règle firewall de haute priorité, inutile de la cibler avec une signature IDS.

### Proportionnalité des réponses

4. **Score ≤ 3** : privilégier `alert` et `log` plutôt que `block_source`.
5. **Score 4–6** : `rate_limit` + `alert`, blocage sélectif des flux les plus suspects.
6. **Score ≥ 7** : `block_source` ou `quarantine`, notification immédiate.

### Gestion des faux positifs

7. **Toujours `allow` explicitement** les services légitimes identifiés dans l'automate avant la règle de blocage par défaut.
8. **Utiliser `idle_timeout`** plutôt que `hard_timeout` pour les règles dynamiques, afin de libérer les flux inactifs rapidement.
9. **Préférer des CIDR larges** pour les services légitimes (ex : `35.190.0.0/16` pour Google) plutôt que des IPs individuelles qui peuvent changer.

### Performance OVS

10. **Limiter le nombre de règles firewall** à moins de 500 par switch pour éviter la surcharge des tables de flux OpenFlow.
11. **Regrouper les IPs de même ASN** en un seul CIDR quand possible.
12. **Utiliser `table_id: 0`** pour les règles critiques et des tables secondaires pour le monitoring.
