# 🔍 Mirage Scan Engine

> **Le Diagnostiqueur Intelligent.**  
> Partie intégrante de l'écosystème **MIRAGE**, ce module est un moteur d'audit réseau autonome capable de découvrir, scanner et patcher les vulnérabilités automatiquement.

## ✨ Fonctionnalités clés

- **Découverte Turbo** : Scan réseau multi-threadé (ARP/ICMP).
- **Audit de Vulnérabilités** : Intégration profonde avec OWASP Nettacker pour détecter + de 100 types de failles.
- **Moteur de Résolution** : Génère des guides étape par étape pour les administrateurs.
- **Score de Sécurité** : Évaluation instantanée de la posture de sécurité d'une machine.
- **Auto-Patching** : Correction automatique des mauvaises configurations (SSH, Firewall, Services).

## 🚀 Installation Rapide

```bash
git clone https://github.com/votre-compte/mirage-scan.git
cd mirage-scan
pip install .
```

## 🛠️ Utilisation CLI

```bash
# Lancer un audit complet du réseau local
mirage-scan --full

# Scanner une cible spécifique avec rapport de résolution
mirage-scan --target 192.168.1.50 --resolve
```

## 📊 Format de Sortie
Le moteur produit des rapports JSON standardisés compatibles avec le Mirage Unified Dashboard.

---
© 2026 Mirage Security - "L'illusion de la vulnérabilité s'arrête ici."
