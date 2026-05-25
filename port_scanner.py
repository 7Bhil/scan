import json
import subprocess
import os
import sys
from datetime import datetime
import logging

# Ajouter le chemin parent pour importer database_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Scan.PortScanner")

def run_port_scan(target, threads=10):
    logger.info(f"Démarrage du scan de ports sur {target}...")
# ... (rest of the file remains similar until processing results)
    
    output_file = "temp_nettacker_results.json"
    if os.path.exists(output_file):
        os.remove(output_file)
        
    cmd = [
        "python3", "nettacker.py",
        "-i", target,
        "-m", "port_scan",
        "-t", str(threads),
        "-o", output_file
    ]
    
    try:
        # Run Nettacker
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        
        # Read results
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                raw_data = json.load(f)
            
            # Convert to Mirage format
            mirage_results = []
            open_ports = []
            
            for entry in raw_data:
                port = entry.get('port')
                if port:
                    open_ports.append(port)
                    mirage_results.append({
                        "version": "1.0",
                        "component": "scan",
                        "timestamp": datetime.now().isoformat(),
                        "type": "port_scan",
                        "target": {"ip": target},
                        "data": {
                            "port": port,
                            "service": "Unknown",
                            "status": "open"
                        }
                    })
            
            # --- SYNCHRO CLOUD ---
            if MongoAtlasManager and open_ports:
                db = MongoAtlasManager()
                if db.db is not None:
                    # 1. Logger l'événement
                    db.insert_event({
                        "component": "scan",
                        "type": "port_scan",
                        "severity": "info",
                        "target": {"ip": target},
                        "message": f"Scan de ports terminé pour {target}. {len(open_ports)} ports trouvés."
                    })
                    # 2. Mettre à jour la machine
                    db.add_machine_ports(target, open_ports)
                    logger.info("Résultats du scan de ports synchronisés avec MongoDB Atlas.")

            final_output = f"port_scan_{target.replace('/', '_')}.json"
            with open(final_output, "w") as f:
                json.dump(mirage_results, f, indent=4)
                
            logger.info(f"Scan de ports terminé pour {target}. {len(mirage_results)} ports ouverts trouvés.")
            return mirage_results
        else:
            print(f"[-] No results found for {target}.")
            return []
            
    except Exception as e:
        print(f"[!] Error during port scan: {e}")
        return []

if __name__ == "__main__":
    # Test on localhost or a target
    run_port_scan("127.0.0.1")
