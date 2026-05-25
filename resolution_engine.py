import json
import os
import sys
import logging

# Ajouter le chemin parent pour importer database_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Scan.Resolution")

RESOLUTION_GUIDES = {
# ... (rest of the file remains similar until generate_resolutions)
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
        
    # Déterminer l'IP cible à partir du premier résultat
    target_ip = results[0]['target']['ip'] if results else "Unknown"
    
    total_score = max(0, total_score)
    status = "Safe" if total_score > 80 else "At Risk" if total_score > 50 else "Critical"
    
    output = {
        "summary": {
            "machine_score": total_score,
            "status": status,
            "findings_count": len(enriched_results)
        },
        "findings": enriched_results
    }
    
    # --- SYNCHRO CLOUD ---
    if MongoAtlasManager and target_ip != "Unknown":
        db = MongoAtlasManager()
        if db.db is not None:
            db.update_machine({
                "ip": target_ip,
                "score": total_score,
                "status": status,
                "findings": [f['data'] for f in enriched_results]
            })
            logger.info(f"Score ({total_score}/100) et résolutions envoyés sur MongoDB Atlas pour {target_ip}.")

    output_path = scan_results_path.replace(".json", "_resolved.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=4)
        
    logger.info(f"Résolutions générées. Score: {total_score}/100")
    return output

if __name__ == "__main__":
    # Assuming a vuln file exists
    import sys
    if len(sys.argv) > 1:
        generate_resolutions(sys.argv[1])
    else:
        print("Usage: python3 resolution_engine.py <vuln_scan_result.json>")
