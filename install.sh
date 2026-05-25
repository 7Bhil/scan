#!/bin/bash

# --- MIRAGE SCAN ENGINE INSTALLER ---
# Professional installation script for Linux

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}    MIRAGE SCAN ENGINE - INSTALLATION    ${NC}"
echo -e "${BLUE}==========================================${NC}"

# 1. Check for Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Erreur : Python3 n'est pas installé.${NC}"
    exit 1
fi

# 2. Check for Sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${BLUE}[*] Note : Certaines fonctionnalités (ARP scan, firewall) nécessiteront sudo plus tard.${NC}"
fi

# 3. Create Virtual Environment
echo -e "${BLUE}[*] Création de l'environnement virtuel...${NC}"
python3 -m venv venv
source venv/bin/activate

# 4. Install Dependencies
echo -e "${BLUE}[*] Installation des dépendances Python...${NC}"
pip install --upgrade pip
pip install scapy requests python-dotenv pandas streamlit nettacker

# 5. Fixing Scapy permissions
echo -e "${BLUE}[*] Configuration des permissions pour Scapy (Raw Sockets)...${NC}"
# Permet à Python d'utiliser les Raw Sockets sans être root (si possible sur le système)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3)) 2>/dev/null || echo -e "${RED}[!] Impossible de configurer setcap. Le scan ARP nécessitera 'sudo'.${NC}"

# 6. Final setup
echo -e "${GREEN}[+] Installation terminée avec succès !${NC}"
echo -e "${BLUE}==========================================${NC}"
echo -e "Pour lancer l'audit :"
echo -e "${GREEN}  source venv/bin/activate${NC}"
echo -e "${GREEN}  python3 scan_orchestrator.py --full${NC}"
echo -e "${BLUE}==========================================${NC}"
