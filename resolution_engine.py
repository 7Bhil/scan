import json

RESOLUTION_GUIDES = {
    "admin_scan": {
        "title": "Interface d'administration exposée",
        "description": "Une page d'administration a été découverte publiquement.",
        "steps": [
            "Restreindre l'accès à l'IP de l'administrateur uniquement via le pare-feu.",
            "Utiliser une authentification forte (2FA/MFA).",
            "Changer le chemin par défaut de l'interface (ex: /admin -> /secret-gate)."
        ],
        "commands": [
            "# Exemple Apache (VirtualHost)\n<Location /admin>\n  Require ip 192.168.1.50\n</Location>",
            "# Exemple Nginx\nlocation /admin {\n  allow 192.168.1.50;\n  deny all;\n}"
        ]
    },
    "clickjacking_vuln": {
        "title": "Vulnérabilité au Clickjacking",
        "description": "Le site ne protège pas contre l'intégration dans des frames malveillantes.",
        "steps": [
            "Ajouter l'en-tête Content-Security-Policy: frame-ancestors 'self';",
            "OU ajouter l'en-tête X-Frame-Options: SAMEORIGIN."
        ],
        "commands": [
            "# Pour Apache (.htaccess)\nHeader always set X-Frame-Options \"SAMEORIGIN\"",
            "# Pour Nginx\nadd_header X-Frame-Options \"SAMEORIGIN\";"
        ]
    },
    "dir_scan": {
        "title": "Répertoire sensible découvert",
        "description": "Des dossiers (ex: /backup, /.git) sont accessibles.",
        "steps": [
            "Désactiver l'auto-indexation des fichiers.",
            "Supprimer les fichiers de backup ou les déplacer hors du répertoire web.",
            "Bloquer l'accès aux dossiers cachés (commençant par .)."
        ],
        "commands": [
            "# Pour Apache\nOptions -Indexes",
            "# Pour Nginx\nlocation ~ /\\. {\n  deny all;\n}"
        ]
    },
    "server_version_vuln": {
        "title": "Exposition de la version du serveur",
        "description": "Le serveur révèle sa version exacte, facilitant le choix d'un exploit.",
        "steps": [
            "Désactiver les jetons de signature du serveur dans la configuration."
        ],
        "commands": [
            "# Pour Apache\nServerTokens Prod\nServerSignature Off",
            "# Pour Nginx\nserver_tokens off;"
        ]
    }
}

def generate_resolutions(scan_results_path):
    with open(scan_results_path, 'r') as f:
        results = json.load(f)
        
    enriched_results = []
    total_score = 100
    
    for entry in results:
        module = entry['data'].get('module_name')
        guide = RESOLUTION_GUIDES.get(module, {
            "title": f"Alerte {module}",
            "description": "Une vulnérabilité a été détectée.",
            "steps": ["Analyser les logs pour comprendre l'exposition.", "Appliquer les patchs de sécurité."],
            "commands": ["# Pas de commande spécifique disponible."]
        })
        
        entry['data']['resolution'] = guide
        enriched_results.append(entry)
        
        # Simple scoring logic
        total_score -= 10 # Deduct 10 points per vuln
        
    total_score = max(0, total_score)
    
    output = {
        "summary": {
            "machine_score": total_score,
            "status": "Safe" if total_score > 80 else "At Risk" if total_score > 50 else "Critical",
            "findings_count": len(enriched_results)
        },
        "findings": enriched_results
    }
    
    output_path = scan_results_path.replace(".json", "_resolved.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=4)
        
    print(f"[+] Resolutions generated. Machine Score: {total_score}/100")
    print(f"[+] Detailed report saved to {output_path}")
    return output

if __name__ == "__main__":
    # Assuming a vuln file exists
    import sys
    if len(sys.argv) > 1:
        generate_resolutions(sys.argv[1])
    else:
        print("Usage: python3 resolution_engine.py <vuln_scan_result.json>")
