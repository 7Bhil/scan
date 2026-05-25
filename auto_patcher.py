import subprocess
import os

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True, res.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def harden_ssh():
    print("[*] Hardening SSH configuration...")
    # This is a dangerous operation in a real environment, using a safe approach here
    ssh_config = "/etc/ssh/sshd_config"
    if not os.path.exists(ssh_config):
        print("[-] SSH config not found.")
        return False
    
    # Example: Disable root login and empty passwords
    commands = [
        "sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config",
        "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
        "sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config",
        "sudo systemctl restart ssh"
    ]
    
    success = True
    for cmd in commands:
        ok, err = run_cmd(cmd)
        if not ok:
            print(f"[!] Command failed: {cmd} - Error: {err}")
            success = False
    return success

def close_unused_ports(allowed_ports=[22, 80, 443]):
    print(f"[*] Closing all ports except: {allowed_ports}...")
    
    # Using UFW (Uncomplicated Firewall)
    commands = [
        "sudo ufw default deny incoming",
        "sudo ufw default allow outgoing"
    ]
    
    for port in allowed_ports:
        commands.append(f"sudo ufw allow {port}/tcp")
        
    commands.append("sudo ufw --force enable")
    
    success = True
    for cmd in commands:
        ok, err = run_cmd(cmd)
        if not ok:
            print(f"[!] Command failed: {cmd} - Error: {err}")
            success = False
    return success

def disable_dangerous_services():
    print("[*] Disabling potentially dangerous services (telnet, rsh, etc.)...")
    services = ["telnet", "rsh", "rlogin", "rexec"]
    
    for svc in services:
        run_cmd(f"sudo systemctl stop {svc}")
        run_cmd(f"sudo systemctl disable {svc}")
    return True

def run_auto_patch():
    print("=== MIRAGE AUTO-PATCHER ===")
    harden_ssh()
    close_unused_ports()
    disable_dangerous_services()
    print("[+] Patching complete.")

if __name__ == "__main__":
    # In a real scenario, this would be triggered by 'oracle'
    # For now, it's a standalone tool for Jour 6
    confirm = input("[!] WARNING: This script will modify system configuration and firewall rules. Continue? (y/N): ")
    if confirm.lower() == 'y':
        run_auto_patch()
    else:
        print("Aborted.")
