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

class ScanOrchestrator:
    def __init__(self, silent=False):
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.silent = silent
        
    def log(self, message):
        if not self.silent:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [SCAN] {message}")

    def run_full_audit(self):
        self.log("🚀 Lancement de l'audit complet du réseau...")
        
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
            
        self.log("🏁 Audit Mirage terminé.")

    def start_daemon(self, interval=3600):
        self.log(f"🔄 Mode 'Mise à jour continue' activé (Intervalle: {interval}s)")
        try:
            while True:
                self.run_full_audit()
                self.log(f"💤 Sommeil pendant {interval} secondes avant le prochain scan...")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.log("🛑 Mode continu arrêté par l'utilisateur.")

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
