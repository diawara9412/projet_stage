# Format JSON d'un Automate Réseau Enrichi

## Présentation

Un automate réseau enrichi représente le **comportement réseau observé** d'une application (mobile, desktop, web). Chaque état correspond à une phase fonctionnelle de l'application, et chaque transition décrit un appel réseau émis lors du passage d'un état à un autre.

Ce format est conçu pour être ingéré par le `ChainAnalyzer` afin de produire une chaîne de sécurité adaptée.

---

## Schéma JSON racine

```json
{
  "automate_id": "string",
  "app_name": "string",
  "app_version": "string",
  "platform": "string",
  "description": "string",
  "created_at": "string (ISO 8601)",
  "states": [ ... ],
  "transitions": [ ... ],
  "metadata": { ... }
}
```

---

## Champs racine

| Champ         | Type   | Obligatoire | Exemple                        | Signification                                   |
|---------------|--------|-------------|--------------------------------|-------------------------------------------------|
| `automate_id` | string | Oui         | `"pokemon_go_v1"`              | Identifiant unique de l'automate                |
| `app_name`    | string | Oui         | `"Pokemon GO"`                 | Nom de l'application analysée                   |
| `app_version` | string | Non         | `"1.245.0"`                    | Version de l'application                        |
| `platform`    | string | Oui         | `"android"` / `"ios"`         | Plateforme cible                                |
| `description` | string | Non         | `"Automate capturé via mitmproxy"` | Description libre                           |
| `created_at`  | string | Non         | `"2024-04-15T14:30:00Z"`      | Date de création (ISO 8601)                     |
| `states`      | array  | Oui         | voir ci-dessous                | Liste des états de l'automate                   |
| `transitions` | array  | Oui         | voir ci-dessous                | Liste des transitions entre états               |
| `metadata`    | object | Non         | voir ci-dessous                | Informations globales sur la capture            |

---

## Section `states`

Chaque état représente un **mode de fonctionnement** de l'application.

```json
{
  "id": "string",
  "label": "string",
  "is_initial": true,
  "is_final": false,
  "description": "string"
}
```

| Champ         | Type    | Obligatoire | Exemple          | Signification                                         |
|---------------|---------|-------------|------------------|-------------------------------------------------------|
| `id`          | string  | Oui         | `"login"`        | Identifiant unique de l'état (référencé dans transitions) |
| `label`       | string  | Oui         | `"Connexion"`    | Nom lisible de l'état                                 |
| `is_initial`  | boolean | Non         | `true`           | `true` si c'est l'état de départ (un seul par automate) |
| `is_final`    | boolean | Non         | `false`          | `true` si l'application peut s'arrêter dans cet état |
| `description` | string  | Non         | `"Authentification OAuth"` | Description fonctionnelle                  |

---

## Section `transitions`

Chaque transition représente **un ou plusieurs appels réseau** émis lors du passage d'un état source à un état cible.

```json
{
  "id": "string",
  "from": "string",
  "to": "string",
  "label": "string",
  "network_call": {
    "url": "string",
    "ip": "string",
    "port": 443,
    "protocol": "string",
    "method": "string",
    "hostname": "string"
  },
  "service": {
    "name": "string",
    "type": "string",
    "reputation": "string",
    "asn": "string",
    "asn_org": "string",
    "country": "string",
    "city": "string"
  },
  "behavior": {
    "probability": 0.95,
    "frequency_per_session": 1,
    "payload_size_bytes": 512,
    "is_encrypted": true,
    "is_authenticated": true,
    "triggers": "string"
  },
  "suspicion": {
    "score": 0,
    "flags": [],
    "notes": "string"
  }
}
```

### Champs `network_call`

| Champ      | Type   | Obligatoire | Exemple                              | Signification                          |
|------------|--------|-------------|--------------------------------------|----------------------------------------|
| `url`      | string | Non         | `"https://pgorelease.nianticlabs.com/plfe/version"` | URL complète appelée    |
| `ip`       | string | Oui         | `"35.190.0.100"`                     | Adresse IP de destination              |
| `port`     | int    | Oui         | `443`                                | Port de destination                    |
| `protocol` | string | Oui         | `"HTTPS"` / `"UDP"` / `"DNS"`       | Protocole réseau                       |
| `method`   | string | Non         | `"GET"` / `"POST"` / `"gRPC"`       | Méthode applicative                    |
| `hostname` | string | Non         | `"pgorelease.nianticlabs.com"`       | Nom d'hôte résolu                      |

### Champs `service`

| Champ      | Type   | Obligatoire | Exemple                    | Signification                                                   |
|------------|--------|-------------|----------------------------|-----------------------------------------------------------------|
| `name`     | string | Oui         | `"Niantic"`                | Nom du fournisseur de service                                   |
| `type`     | string | Oui         | `"CDN"` / `"API"` / `"analytics"` / `"payment"` / `"unknown"` | Catégorie du service |
| `reputation` | string | Oui       | `"trusted"` / `"neutral"` / `"suspicious"` / `"unknown"` | Réputation du service  |
| `asn`      | string | Non         | `"AS15169"`                | Numéro d'ASN (Autonomous System)                                |
| `asn_org`  | string | Non         | `"Google LLC"`             | Organisation propriétaire de l'ASN                              |
| `country`  | string | Non         | `"US"`                     | Code pays ISO 3166-1                                            |
| `city`     | string | Non         | `"Mountain View"`          | Ville (si connue)                                               |

**Valeurs de `reputation` :**
- `trusted` : service connu, légitime, appartenant à une organisation reconnue
- `neutral` : service existant mais sans réputation établie
- `suspicious` : service ou IP signalé comme malveillant (blacklists, Tor, bulletproof hosting)
- `unknown` : IP ou domaine non identifié, non référencé

### Champs `behavior`

| Champ                   | Type    | Obligatoire | Exemple    | Signification                                                    |
|-------------------------|---------|-------------|------------|------------------------------------------------------------------|
| `probability`           | float   | Oui         | `0.95`     | Probabilité d'observer cette transition (0.0 à 1.0)             |
| `frequency_per_session` | int/float | Non       | `1`        | Nombre moyen d'occurrences par session utilisateur              |
| `payload_size_bytes`    | int     | Non         | `512`      | Taille moyenne du payload (octets)                              |
| `is_encrypted`          | boolean | Non         | `true`     | Trafic chiffré (TLS/DTLS)                                       |
| `is_authenticated`      | boolean | Non         | `true`     | Requête authentifiée (token, cookie, cert)                      |
| `triggers`              | string  | Non         | `"Bouton 'Démarrer'"` | Action utilisateur qui déclenche la transition         |

### Champs `suspicion`

| Champ    | Type   | Obligatoire | Exemple                       | Signification                                         |
|----------|--------|-------------|-------------------------------|-------------------------------------------------------|
| `score`  | int    | Oui         | `0` à `10`                    | Score de suspicion (0 = légitime, 10 = très suspect)  |
| `flags`  | array  | Non         | `["tor_exit_node", "beaconing"]` | Liste des indicateurs de compromission (IoC)       |
| `notes`  | string | Non         | `"IP vue dans abuse.ch"`      | Commentaire libre sur la suspicion                    |

**Valeurs de `flags` disponibles :**

| Flag                  | Signification                                                    |
|-----------------------|------------------------------------------------------------------|
| `tor_exit_node`       | L'IP est un nœud de sortie Tor (Onion Router)                   |
| `beaconing`           | Appels répétitifs à intervalle régulier (C2 heartbeat)          |
| `data_exfiltration`   | Volume de données sortantes anormalement élevé                  |
| `known_c2`            | IP ou domaine répertorié comme C2 (Command & Control)           |
| `bulletproof_hosting` | Hébergeur connu pour ignorer les plaintes d'abus               |
| `dga_domain`          | Domaine généré algorithmiquement (Domain Generation Algorithm)  |
| `port_scan`           | Balayage de ports détecté                                       |
| `suspicious_path`     | Chemin URL avec patterns suspects (/cmd, /shell, /exec, etc.)   |
| `self_signed_cert`    | Certificat TLS auto-signé (pas d'autorité de certification)     |
| `geo_anomaly`         | Pays de destination inhabituel pour cette application           |

---

## Section `metadata`

Informations globales sur la session de capture.

```json
{
  "capture_tool": "string",
  "capture_duration_seconds": 3600,
  "sessions_analyzed": 10,
  "device_type": "string",
  "network_type": "string",
  "analyst": "string"
}
```

| Champ                      | Type   | Obligatoire | Exemple            | Signification                                  |
|----------------------------|--------|-------------|--------------------|-------------------------------------------------|
| `capture_tool`             | string | Non         | `"mitmproxy"`      | Outil utilisé pour capturer le trafic          |
| `capture_duration_seconds` | int    | Non         | `3600`             | Durée totale de capture                        |
| `sessions_analyzed`        | int    | Non         | `10`               | Nombre de sessions analysées                   |
| `device_type`              | string | Non         | `"smartphone"`     | Type d'appareil                                |
| `network_type`             | string | Non         | `"4G"` / `"WiFi"` | Type de réseau utilisé                         |
| `analyst`                  | string | Non         | `"RESIST-Lab"`     | Analyste ou équipe ayant produit l'automate    |

---

## Indices de suspicion

Le `ChainAnalyzer` doit examiner les éléments suivants pour détecter un comportement malveillant :

### 1. Réputation des services

- `reputation: "suspicious"` ou `"unknown"` → score de suspicion ≥ 5
- ASN appartenant à des opérateurs bulletproof (ex : AS209854, AS62317) → flag `bulletproof_hosting`
- Pays à haut risque sans justification applicative (RU, KP, IR pour une app commerciale française) → flag `geo_anomaly`

### 2. Comportements de beaconing (C2 heartbeat)

- `frequency_per_session` très élevée (> 100 pour une session d'1h) avec payload fixe
- `probability` proche de 1.0 sur une transition vers un service `unknown`
- Intervalle régulier et précis entre appels → flag `beaconing`

### 3. Exfiltration de données

- `payload_size_bytes` élevé (> 50 000) sur une transition sortante vers service `unknown`
- Protocoles non-standard ou non-chiffrés sur des ports inhabituels (80, 8080 vers IP externe)
- Flag `data_exfiltration`

### 4. Communication avec Tor

- IP dans les plages de nœuds Tor publics (185.220.101.x, 185.220.100.x, 199.249.230.x)
- Port 9001 ou 9030 (ports Tor par défaut)
- Flag `tor_exit_node`

### 5. Chemins URL suspects

- Segments `/cmd/`, `/exec/`, `/shell/`, `/upload/raw/`, `/.git/`, `/wp-admin/` dans une app non-web
- Paramètres encodés base64 non documentés
- Flag `suspicious_path`

### 6. Certificats non valides

- `is_encrypted: true` mais certificat auto-signé ou expiré
- Flag `self_signed_cert`

### 7. Domaines générés algorithmiquement (DGA)

- Hostnames avec séquences aléatoires longues (ex : `xkq7f2mra9.top`)
- Enregistrement très récent du domaine (< 7 jours)
- Flag `dga_domain`

---

## Score de suspicion global

Le score global de l'automate est la moyenne pondérée des scores de transitions, pondérée par la probabilité :

```
score_global = Σ (transition.suspicion.score × transition.behavior.probability) / Σ transition.behavior.probability
```

- **0 – 2** : Application légitime, chaîne de sécurité standard
- **3 – 5** : Comportements inhabituels, IDS renforcé requis
- **6 – 8** : Forte suspicion, IPS actif + blocage sélectif
- **9 – 10** : Malware confirmé, blocage total recommandé
