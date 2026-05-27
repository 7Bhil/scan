import streamlit as st
import subprocess
import json
import os
import pandas as pd
import time
import re
from datetime import datetime

# --- CONFIGURATION ET STYLE ---
st.set_page_config(page_title="Scanner de Sécurité Réseau", layout="wide")

# Fonction de nettoyage automatique des anciens résultats (vieux de plus d'une heure)
def cleanup_old_results():
    now = time.time()
    for f in os.listdir("."):
        if f.startswith("result_") and f.endswith(".json"):
            if os.stat(f).st_mtime < now - 3600:
                try:
                    os.remove(f)
                except:
                    pass

cleanup_old_results()

# Dictionnaire de vulgarisation pour les non-informaticiens
EXPLICATIONS = {
    "port_scan": {
        "titre": "Port Ouvert Détecté",
        "description": "Une 'porte' d'entrée vers cet appareil a été trouvée. Si cette porte n'est pas censée être ouverte, un pirate pourrait l'utiliser pour s'introduire.",
        "conseil": "Vérifiez si le service qui utilise ce port est nécessaire."
    },
    "clickjacking_vuln": {
        "titre": "Faille de Détournement de Clic (Clickjacking)",
        "description": "Un pirate peut superposer une page invisible sur ce site pour tromper l'utilisateur et lui faire cliquer sur un bouton malveillant.",
        "conseil": "Configurez les headers de sécurité (X-Frame-Options)."
    },
    "dir_scan": {
        "titre": "Dossier Sensible Trouvé",
        "description": "Des dossiers (ex: /admin, /backup) qui devraient être privés sont accessibles publiquement.",
        "conseil": "Restreignez l'accès à ces dossiers avec un mot de passe ou un pare-feu."
    },
    "viewvc_vuln": {
        "titre": "Exposition d'Informations (ViewVC)",
        "description": "Le système révèle des détails sur sa configuration interne, aidant un pirate à préparer son attaque.",
        "conseil": "Désactivez les interfaces de gestion inutilisées."
    },
    "admin_scan": {
        "titre": "Interface d'Administration Détectée",
        "description": "Une page de connexion admin a été trouvée. C'est une cible prioritaire pour les pirates.",
        "conseil": "Utilisez un mot de passe complexe et une double authentification (2FA)."
    },
    "default": {
        "titre": "Alerte de Sécurité",
        "description": "Une vulnérabilité technique a été identifiée sur cet équipement.",
        "conseil": "Mettez à jour le logiciel concerné dès que possible."
    }
}

st.title(" Scanner de Sécurité Réseau Pro")
st.markdown("""
**Analyse intelligente en cascade** : Découverte  Scan de Ports  Analyse Web  Vulnérabilités.
""")

# --- BARRE LATÉRALE ---
st.sidebar.header(" Paramètres de l'Audit")

# Gestion de l'état du processus dans la session Streamlit
if 'proc' not in st.session_state:
    st.session_state.proc = None

scan_mode = st.sidebar.radio("Cible de l'audit :", ["Un seul appareil", "Réseau complet (10.58.76.0/24)"])

if scan_mode == "Un seul appareil":
    target_input = st.sidebar.text_input("Adresse(s) IP :", value="10.58.76.115")
    if not re.match(r"^[0-9., ]+$", target_input) and target_input != "localhost":
        st.sidebar.warning(" Format d'IP invalide")
    target = target_input
else:
    target = "10.58.76.0/24"
    st.sidebar.info("Audit complet du réseau local en cours.")

scan_type = st.sidebar.selectbox("Profondeur d'analyse :", ["Standard (Ports + Web)", "Expert (Toutes Vulnérabilités)"])
stealth_mode = st.sidebar.toggle(" Mode Furtif (Éviter le bannissement)", value=True)
force_scan = st.sidebar.checkbox("Bypass Ping (Plus lent mais exhaustif)", value=not stealth_mode)

# Boutons de contrôle
col1, col2 = st.sidebar.columns(2)
start_btn = col1.button(" Lancer l'Audit")
stop_btn = col2.button(" Arrêter")

if stop_btn:
    if st.session_state.proc:
        st.session_state.proc.terminate()
        st.session_state.proc = None
        st.sidebar.error("Audit interrompu par l'utilisateur.")
        st.rerun()

if start_btn:
    if st.session_state.proc:
        st.session_state.proc.terminate()
    
    st.info(f"Audit en cours sur {target}...")
    if stealth_mode:
        st.warning(" Mode Furtif activé : Le scan sera beaucoup plus lent pour ne pas alerter le pare-feu.")
    
    # Zone de logs et de découverte
    st.subheader(" Chronologie de l'Audit")
    log_area = st.empty()
    log_content = []
    
    progress_bar = st.progress(0)
    
    st.subheader(" Cartographie du Réseau")
    discovery_container = st.empty()
    # Structure : { IP: { 'ports': [], 'vulns': [], 'status': 'Discovery' } }
    devices_status = {}

    # Commande en Cascade
    modules = "port_scan,dir_scan,clickjacking_vuln,admin_scan"
    if "Expert" in scan_type:
        modules += ",subdomain_scan,viewvc_vuln"

    # Réglages de vitesse
    threads = "3" if stealth_mode else "20"
    timeout = "1.5" if stealth_mode else "0.2"
    
    cmd = [
        "python3", "nettacker.py", "-i", target,
        "-t", threads, "-M", threads, "-T", timeout,
        "-m", modules, "-v",
        "--set-hardware-usage", "low" if stealth_mode else "normal"
    ]
    if force_scan: cmd += ["-d"]
    # En mode furtif, on ajoute un petit délai entre les requêtes si possible via les threads/timeout

    output_file = f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    cmd += ["-o", output_file]

    try:
        # Lancement
        st.session_state.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        while True:
            line = st.session_state.proc.stdout.readline()
            if not line and st.session_state.proc.poll() is not None:
                break
            if line:
                # Parsing intelligent des logs
                if "|" in line:
                    parts = line.split('|')
                    if len(parts) > 3:
                        ip = parts[2].strip()
                        module = parts[3].strip()
                        
                        if ip not in devices_status:
                            devices_status[ip] = {'ports': [], 'vulns': [], 'status': 'En cours...'}
                            log_content.append(f" Appareil détecté : {ip}")

                        # Détection de ports
                        if "port_scan" in module:
                            port_match = re.search(r"'matched_regex': \['(\d+)'\]", line)
                            if port_match:
                                p = port_match.group(1)
                                if p not in devices_status[ip]['ports']:
                                    devices_status[ip]['ports'].append(p)
                                    log_content.append(f" Port {p} ouvert sur {ip}")

                        # Détection de vulnérabilités
                        elif "vuln" in module or "scan" in module:
                            if "matched_regex" in line or "VULNERABILITY" in line.upper():
                                if module not in devices_status[ip]['vulns']:
                                    devices_status[ip]['vulns'].append(module)
                                    log_content.append(f" Alerte : {module} sur {ip}")

                        # Mise à jour UI
                        with discovery_container.container():
                            cols = st.columns(min(len(devices_status), 4))
                            for idx, (ip_addr, data) in enumerate(list(devices_status.items())[-4:]):
                                label = f"IP: {ip_addr}"
                                val = f"{len(data['ports'])} ports | {len(data['vulns'])} alertes"
                                cols[idx].metric(label, val, delta=len(data['vulns']), delta_color="inverse")

                # Affichage des logs limités
                log_area.code("\n".join(log_content[-10:]))
                
                if "imported" in line: progress_bar.progress(10)
                if "process-" in line: progress_bar.progress(50)

        st.session_state.proc = None
        progress_bar.progress(100)
        
        # Résultats finaux
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            st.success(f"Audit terminé ! {len(data)} vulnérabilités identifiées.")
            
            # Score de Sécurité Global
            st.divider()
            total_vulns = len([d for d in data if "port_scan" not in d.get('module_name', '')])
            score_letter = "A" if total_vulns == 0 else "B" if total_vulns < 3 else "C" if total_vulns < 7 else "D"
            st.header(f" Score Global de Sécurité : {score_letter}")
            
            st.subheader(" Détails de l'Analyse")
            for item in data:
                m_name = item.get('module_name')
                info = EXPLICATIONS.get(m_name, EXPLICATIONS['default'])
                # On n'affiche pas les scans de ports simples dans le détail des failles sauf si demandé
                if "port_scan" not in m_name or "Expert" in scan_type:
                    with st.expander(f" {info['titre']} sur {item['target']} (Port {item['port']})"):
                        st.write(f"**Description :** {info['description']}")
                        st.write(f"**Conseil :** {info['conseil']}")
                        st.caption(f"Module technique : {m_name}")
        else:
            st.balloons()
            st.success("Félicitations ! Aucune faille majeure n'a été détectée.")
            
    except Exception as e:
        st.error(f"Erreur technique lors de l'audit : {e}")


st.sidebar.markdown("---")
st.sidebar.write(" Projet de Soutenance")
