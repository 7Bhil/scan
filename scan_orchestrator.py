import sys
import os
import time
import argparse
from datetime import datetime

# Add parent directory to path to import state_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state_manager import MirageState
from discovery import run_discovery
from port_scanner import run_port_scan
from vulnerability_scanner import run_vuln_scan
from resolution_engine import generate_resolutions

try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

class ScanOrchestrator:
    def __init__(self, silent=False):
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.silent = silent
        self.db = MongoAtlasManager() if MongoAtlasManager else None
        
    def log(self, message, cloud=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if not self.silent:
            print(f"[{timestamp}] [SCAN] {message}")
        if cloud and self.db and self.db.db is not None:
            self.db.insert_event({
                "component": "scan",
                "type": "audit_status",
                "severity": "info",
                "message": message
            })

    def run_full_audit(self):
        self.log("🚀 Lancement de l'audit complet du réseau...", cloud=True)
        
        # 1. Découverte
        self.log("🔍 Étape 1 : Découverte des machines actives...")
        discovery_results = run_discovery()
        devices = discovery_results.get("devices", [])
        
        for device in devices:
            ip = device['ip']
            self.state.update_machine(ip, "hostname", device['hostname'])
            self.state.update_machine(ip, "last_seen", str(datetime.now()))
            self.log(f"   found: {ip} ({device['hostname']})")

        # 2. Pour chaque machine, scanner ports et vulnérabilités
        for device in devices:
            ip = device['ip']
            self.log(f"🛠️ Étape 2 : Analyse approfondie de {ip}...")
            
            # Ports
            ports = run_port_scan(ip)
            self.state.update_machine(ip, "ports", [p['data']['port'] for p in ports])
            
            # Vulns
            vulns = run_vuln_scan(ip)
            
            # 3. Résolutions et Score
            temp_vuln_path = f"vuln_scan_{ip.replace('.', '_')}.json"
            if os.path.exists(temp_vuln_path):
                report = generate_resolutions(temp_vuln_path)
                self.state.update_machine(ip, "score", report['summary']['machine_score'])
                self.state.update_machine(ip, "status", report['summary']['status'])
                self.state.update_machine(ip, "findings", report['findings'])
                self.log(f"   ✅ Analyse terminée pour {ip}. Score: {report['summary']['machine_score']}/100")
            
        self.log("🏁 Audit Mirage terminé.", cloud=True)

    def start_daemon(self, interval=3600):
        self.log(f"🔄 Mode 'Mise à jour continue' activé (Intervalle: {interval}s)")
        try:
            # --- START COMMAND LISTENER IN BACKGROUND ---
            if self.db:
                import threading
                threading.Thread(target=self._command_listener, daemon=True).start()
                
            while True:
                self.run_full_audit()
                self.log(f"💤 Sommeil pendant {interval} secondes avant le prochain scan...")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.log("🛑 Mode continu arrêté par l'utilisateur.")
def _command_listener(self):
    """Vérifie si une demande de scan a été envoyée via MongoDB"""
    self.log("[*] Listener de scans distants activé.")
    while True:
        try:
            if self.db:
                self.db.send_heartbeat("scan")

            commands = self.db.get_pending_commands("scan")
# ...

                for cmd in commands:
                    action = cmd.get("action")
                    cmd_id = cmd.get("_id")
                    
                    if action == "run_full_audit":
                        self.log("[!] Commande reçue : Lancement audit complet immédiat.")
                        self.run_full_audit()
                        self.db.update_command_status(cmd_id, "executed")
                    
                    elif action == "scan_target":
                        target = cmd.get("target_ip")
                        if target:
                            self.log(f"[!] Commande reçue : Scan ciblé sur {target}")
                            run_port_scan(target)
                            run_vuln_scan(target)
                            self.db.update_command_status(cmd_id, "executed")
                            
                time.sleep(10)
            except Exception as e:
                self.log(f"Erreur Scan Command Listener : {e}")
                time.sleep(20)

def main():
    parser = argparse.ArgumentParser(description="Mirage Scan Engine - Professional Network Audit Tool")
    parser.add_argument("--target", help="Specific IP target to scan")
    parser.add_argument("--full", action="store_true", help="Run discovery and scan all active devices")
    parser.add_argument("--continuous", type=int, nargs='?', const=3600, help="Enable continuous update with interval in seconds (default: 3600)")
    parser.add_argument("--silent", action="store_true", help="Disable console output")
    
    args = parser.parse_args()
    
    orchestrator = ScanOrchestrator(silent=args.silent)
    
    if args.continuous:
        orchestrator.start_daemon(interval=args.continuous)
    elif args.full:
        orchestrator.run_full_audit()
    elif args.target:
        # Implementation simple pour une cible unique
        orchestrator.log(f"Starting targeted scan on {args.target}...")
        orchestrator.state.update_machine(args.target, "ip", args.target)
        run_port_scan(args.target)
        run_vuln_scan(args.target)
        temp_path = f"vuln_scan_{args.target.replace('.', '_')}.json"
        if os.path.exists(temp_path):
            generate_resolutions(temp_path)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
