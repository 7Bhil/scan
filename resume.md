# 📝 Résumé technique : Module SCAN

**Rôle** : Le Diagnostiqueur (Audit, Scoring & Patching)
**État** : 100% Terminée (Jour 1-6 + Optimisations)

## 🚀 Fonctionnalités implémentées
- **Découverte Réseau** (`discovery.py`) : Scan ARP et Ping Sweep multi-threadé (50 threads) avec auto-détection de l'hôte.
- **Audit de Services** (`port_scanner.py`) : Identification des ports ouverts via OWASP Nettacker.
- **Détection de Failles** (`vulnerability_scanner.py`) : Scan des headers de sécurité, versions de CMS (WordPress, Joomla), et interfaces admin exposées.
- **Moteur de Résolution** (`resolution_engine.py`) : Génération de guides de remédiation (Apache, Nginx, SSH) et calcul d'un score de sécurité sur 100.
- **Auto-Patching** (`auto_patcher.py`) : Durcissement automatique de la config SSH, configuration Firewall (UFW) et arrêt des services dangereux.
- **Orchestration** (`scan_orchestrator.py`) : CLI professionnel avec modes `--full`, `--target` et `--continuous`.

## 🛠️ Stack Technique
- **Nettacker** (Moteur d'audit)
- **Scapy** (Découverte réseau)
- **Poetry/Pip** (Packaging)
- **JSON** (Format de communication Mirage)

## 📂 Fichiers clés
- `install.sh` : Installation automatisée.
- `pyproject.toml` : Dépendances et métadonnées.
- `discovery_results.json` : Sortie brute du scan.
