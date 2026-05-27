#!/bin/bash

# --- Script de lancement automatique pour la Soutenance ---

# 1. Aller dans le dossier du projet
cd "$(dirname "$0")"

# 2. Activer l'environnement virtuel
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo " Erreur : Environnement virtuel 'venv' non trouvé."
    exit 1
fi

# 3. Arrêter les anciennes instances pour éviter les conflits
echo " Nettoyage des anciens processus..."
pkill -f streamlit 2>/dev/null
pkill -f nettacker 2>/dev/null

# 4. Lancer l'interface
echo " Lancement de l'interface de sécurité..."
echo "--------------------------------------------------"
echo "Lien d'accès : http://localhost:8501"
echo "--------------------------------------------------"

streamlit run app_soutenance.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
