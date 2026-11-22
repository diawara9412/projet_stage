"""
tools/deployment_tools.py — Utilitaires REST pour le PolicyEnforcer.

Fournit 4 fonctions pour interagir avec l'API de sdn_executor.py :

- check_firewall_app_alive : vérifie si l'app os_ken est joignable
- install_chain_via_rest   : pousse une SecurityChain via POST /firewall/install
- fetch_deployment_stats   : récupère les statistiques via GET /firewall/stats
- verify_chain_installed   : compte les règles hardware_installed via GET /firewall/rules

Toutes gèrent proprement les erreurs réseau (ConnectionError, Timeout, JSON invalide).
"""

import logging

import requests

logger = logging.getLogger(__name__)


def check_firewall_app_alive(endpoint_url: str, timeout: int = 5) -> tuple[bool, str]:
    """Vérifie que sdn_executor.py est joignable et répond correctement.

    Args:
        endpoint_url: URL de base de l'API (ex: ``"http://127.0.0.1:8080/firewall"``).
        timeout: Délai maximum en secondes.

    Returns:
        ``(True, "alive")`` si le service répond HTTP 200,
        ``(False, raison_erreur)`` sinon.

    Examples:
        >>> ok, msg = check_firewall_app_alive("http://127.0.0.1:8080/firewall")
        >>> ok
        True
    """
    url = f"{endpoint_url.rstrip('/')}/stats"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            logger.debug("firewall_app joignable : %s", url)
            return True, "alive"
        return False, f"HTTP {resp.status_code} depuis {url}"
    except requests.exceptions.ConnectionError:
        return False, f"Connexion refusée sur {url} (firewall_app non lancé ?)"
    except requests.exceptions.Timeout:
        return False, f"Timeout ({timeout}s) sur {url}"
    except Exception as exc:
        return False, f"Erreur inattendue : {exc}"


def install_chain_via_rest(
    chain_dict: dict,
    endpoint_url: str,
    timeout: int = 30,
) -> tuple[bool, dict | str]:
    """Déploie une SecurityChain via POST /firewall/install.

    Args:
        chain_dict: Dictionnaire conforme au modèle SecurityChain.
        endpoint_url: URL de base de l'API (ex: ``"http://127.0.0.1:8080/firewall"``).
        timeout: Délai maximum pour la requête POST en secondes.

    Returns:
        ``(True, response_json)`` si HTTP 200 ou 201,
        ``(False, message_erreur)`` sinon.
    """
    url = f"{endpoint_url.rstrip('/')}/install"
    _fw = chain_dict.get("firewall_rules", [])
    logger.info("DÉPLOYEUR → contrôleur : envoi de la chaîne '%s' (%d firewall / %d IDS / %d IPS) → %s",
                chain_dict.get("chain_id", "?"), len(_fw),
                len(chain_dict.get("ids_signatures", [])),
                len(chain_dict.get("ips_actions", [])), url)
    try:
        resp = requests.post(url, json=chain_dict, timeout=timeout)
        if resp.status_code in (200, 201):
            try:
                return True, resp.json()
            except ValueError:
                return True, {"raw": resp.text}
        # Erreur HTTP
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        return False, f"HTTP {resp.status_code} : {body}"
    except requests.exceptions.ConnectionError as exc:
        return False, f"Connexion refusée : {exc}"
    except requests.exceptions.Timeout:
        return False, f"Timeout ({timeout}s) dépassé pour POST {url}"
    except Exception as exc:
        return False, f"Erreur inattendue lors du POST : {exc}"


def fetch_deployment_stats(endpoint_url: str, timeout: int = 5) -> dict:
    """Récupère les statistiques de déploiement depuis GET /firewall/stats.

    Args:
        endpoint_url: URL de base de l'API.
        timeout: Délai maximum en secondes.

    Returns:
        Dictionnaire JSON de réponse, ou ``{}`` si erreur.
        Champs attendus : ``connected_switches``, ``installed_flows``,
        ``active_chain_id``, ``ids_alerts``.
    """
    url = f"{endpoint_url.rstrip('/')}/stats"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("fetch_deployment_stats : HTTP %d depuis %s", resp.status_code, url)
        return {}
    except requests.exceptions.ConnectionError:
        logger.warning("fetch_deployment_stats : connexion refusée sur %s", url)
        return {}
    except requests.exceptions.Timeout:
        logger.warning("fetch_deployment_stats : timeout sur %s", url)
        return {}
    except Exception as exc:
        logger.warning("fetch_deployment_stats : erreur inattendue : %s", exc)
        return {}


def verify_chain_installed(chain_dict: dict, endpoint_url: str) -> tuple[int, int]:
    """Compte les règles confirmées installées sur le hardware via GET /firewall/rules.

    Args:
        chain_dict: La SecurityChain installée (pour compter les règles attendues).
        endpoint_url: URL de base de l'API.

    Returns:
        ``(nb_attempted, nb_installed)`` où ``nb_attempted`` est le nombre total
        de règles dans la chaîne et ``nb_installed`` est le nombre de règles
        avec ``hardware_installed=True`` selon firewall_app.
    """
    # Compter le nombre total de règles dans la chaîne
    nb_fw = len(chain_dict.get("firewall_rules", []))
    nb_ids = len(chain_dict.get("ids_signatures", []))
    nb_attempted = nb_fw + nb_ids

    url = f"{endpoint_url.rstrip('/')}/rules"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            logger.warning("verify_chain_installed : HTTP %d", resp.status_code)
            return nb_attempted, 0
        data = resp.json()
        rules = data.get("rules", [])
        nb_installed = sum(1 for r in rules if r.get("hardware_installed") is True)
        return nb_attempted, nb_installed
    except requests.exceptions.ConnectionError:
        return nb_attempted, 0
    except requests.exceptions.Timeout:
        return nb_attempted, 0
    except Exception as exc:
        logger.warning("verify_chain_installed : erreur : %s", exc)
        return nb_attempted, 0
