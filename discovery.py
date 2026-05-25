import json
import socket
import os
import sys
from datetime import datetime
from scapy.all import ARP, Ether, srp
import subprocess
import logging

# Ajouter le chemin parent pour importer database_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

# Configuration du logging pro
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Scan.Discovery")

def get_local_ip():
# ... (rest of the file remains similar until run_discovery)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_network_prefix(ip):
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def arp_scan(network):
    logger.info(f"Démarrage du scan ARP sur {network}...")
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=3, verbose=False)
        devices = []
        for sent, received in ans:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': get_hostname(received.psrc),
                'method': 'ARP',
                'discovery_time': datetime.now().isoformat()
            })
        return devices
    except PermissionError:
        logger.warning("Permissions insuffisantes pour le scan ARP (root requis).")
        return []

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown-Device"

def ping_sweep(network):
    logger.info(f"Démarrage du Ping Sweep sur {network}...")
    devices = []
    prefix = '.'.join(network.split('.')[:-1]) + '.'
    
    # Optimisation: On pourrait utiliser des threads ici pour la perfection
    from concurrent.futures import ThreadPoolExecutor
    
    def check_ip(ip):
        res = subprocess.call(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res == 0:
            return {
                'ip': ip,
                'mac': 'Unknown',
                'hostname': get_hostname(ip),
                'method': 'ICMP',
                'discovery_time': datetime.now().isoformat()
            }
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        ips = [prefix + str(i) for i in range(1, 255)]
        results = executor.map(check_ip, ips)
        for r in results:
            if r: devices.append(r)
            
    return devices

def run_discovery():
    local_ip = get_local_ip()
    network = get_network_prefix(local_ip)
    
    devices = arp_scan(network)
    
    if not devices:
        devices = ping_sweep(network)
        
    # Toujours inclure la machine locale si elle n'y est pas
    if not any(d['ip'] == local_ip for d in devices):
        devices.append({
            'ip': local_ip,
            'mac': 'Self',
            'hostname': 'Mirage-Host',
            'method': 'Internal',
            'discovery_time': datetime.now().isoformat()
        })

    # Préparation du résultat
    timestamp = datetime.now().isoformat()
    result = {
        "version": "1.0",
        "component": "scan",
        "timestamp": timestamp,
        "type": "discovery",
        "network": network,
        "devices_count": len(devices),
        "devices": devices
    }
    
    # Sauvegarde locale
    output_path = "discovery_results.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=4)
    
    # --- SYNCHRO CLOUD ---
    if MongoAtlasManager:
        db = MongoAtlasManager()
        if db.db is not None:
            logger.info("Envoi des résultats vers MongoDB Atlas...")
            # 1. Logger l'événement global
            db.insert_event({
                "component": "scan",
                "type": "discovery",
                "severity": "info",
                "message": f"Scan réseau terminé sur {network}. {len(devices)} machines trouvées.",
                "devices_count": len(devices)
            })
            
            # 2. Mettre à jour chaque machine individuellement
            for device in devices:
                db.update_machine(device)
            logger.info("Cloud synchronisé avec succès.")
    
    logger.info(f"Scan terminé : {len(devices)} machines trouvées.")
    return result

if __name__ == "__main__":
    run_discovery()
