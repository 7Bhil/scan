import json
import subprocess
import os
from datetime import datetime

def run_port_scan(target, threads=10):
    print(f"[*] Starting port scan on {target} using Nettacker...")
    
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
            for entry in raw_data:
                mirage_results.append({
                    "version": "1.0",
                    "component": "scan",
                    "timestamp": datetime.now().isoformat(),
                    "type": "port_scan",
                    "target": {
                        "ip": entry.get('target', target),
                    },
                    "data": {
                        "port": entry.get('port'),
                        "service": "Unknown", # Nettacker's port_scan doesn't always give service name
                        "status": "open",
                        "module_name": entry.get('module_name')
                    }
                })
            
            final_output = f"port_scan_{target.replace('/', '_')}.json"
            with open(final_output, "w") as f:
                json.dump(mirage_results, f, indent=4)
                
            print(f"[+] Port scan finished for {target}. Found {len(mirage_results)} open ports.")
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
