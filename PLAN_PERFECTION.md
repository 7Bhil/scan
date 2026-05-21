# 🚀 Plan de Perfectionnement : Scanner de Soutenance

Ce document détaille la stratégie pour transformer le scanner actuel en un outil de niveau professionnel pour la soutenance.

## 1. Vision "Scanner en Cascade"
L'objectif est de passer d'un scan séquentiel lent à une analyse intelligente multiniveau.

### Flux Logique (Automatisé) :
1.  **Niveau 1 : Découverte (Ping/Arp)**
    *   Identification ultra-rapide des machines actives sur le réseau.
2.  **Niveau 2 : Empreinte (Port Scanning)**
    *   Dès qu'une IP est "vivante", scan des ports clés (21, 22, 80, 443, 8080, 3306).
3.  **Niveau 3 : Analyse de Services (Web Scan)**
    *   Si le port 80/443/8080 est ouvert -> Lancement automatique des modules :
        *   `subdomain_scan`
        *   `viewvc_vuln`
        *   `clickjacking_vuln`
        *   `admin_scan` (recherche de pages d'admin)
4.  **Niveau 4 : Synthèse & Vulgarisation**
    *   Agrégation des résultats par appareil avec le score de sécurité.

---

## 2. Améliorations de l'Interface (Streamlit)

### A. Dashboard Temps Réel Dynamique
*   **Cartes d'appareils "vivantes"** : Une carte par IP qui change de couleur selon l'avancement (Gris: Détecté, Bleu: Ports Scannés, Rouge: Failles trouvées).
*   **Timeline d'Audit** : Un flux d'événements précis (ex: "14:02:01 - Tentative d'accès admin sur 10.58.76.115...").

### B. Moteur de Vulgarisation Enrichi
Ajout de nouvelles fiches d'explication pour le jury :
*   **Brute Force SSH** : "Un pirate tente des milliers de mots de passe à la seconde."
*   **Répertoires Sensibles** : "Votre serveur laisse traîner des dossiers confidentiels accessibles à tous."

---

## 3. Modifications Techniques Prévues

### Fichier `app_soutenance.py` :
*   **Optimisation Nettacker** : Utilisation de profils personnalisés `-m` combinant `port_scan` et modules vuln.
*   **Multi-threading simulé** : Amélioration du parser de logs pour mettre à jour l'interface sans attendre la fin du scan complet.
*   **Gestion des erreurs** : Meilleure gestion des timeouts pour ne pas bloquer le dashboard si une IP ne répond plus.

### Fichier `scan.sh` :
*   Ajout d'une vérification des dépendances (Nettacker, Python, Streamlit) au démarrage.

---

## 4. Livrables finaux pour la Soutenance
1.  **Le Scanner "Parfait"** : Code source optimisé.
2.  **Rapport d'Audit Auto** : Génération d'un résumé structuré des découvertes.
3.  **Guide d'utilisation** : README clair pour le jury.

---
*Plan rédigé le 21 Mai 2026 par Gemini CLI pour Bhil.*
