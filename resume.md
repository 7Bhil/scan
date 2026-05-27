# Manuel de Reference Technique : Module SCAN (MIRAGE)

Ce document est le guide ultime du module SCAN. Il est conçu pour permettre a un utilisateur (expert ou debutant) de comprendre, d'utiliser et de defendre techniquement ce composant lors d'une presentation.

---

## Philosophie du Module
Le module SCAN n'est pas qu'un simple scanner de ports. C'est un Systeme Expert de Diagnostic. Son role est de voir le reseau comme un attaquant le verrait, d'evaluer les risques et de proposer (ou d'appliquer) des corrections immediates.

---

## Architecture et Fonctionnement Interne

Le code est divise en modules specialises. Voici comment chaque brique fonctionne :

### 1. La Decouverte (La Vue d'Ensemble) - discovery.py
- Ce qu'il fait : Il "crie" sur le reseau (ARP Request) pour voir qui repond.
- Pourquoi c'est malin : Il utilise Scapy pour forger ses propres paquets. Contrairement a un ping classique que certains pare-feu bloquent, l'ARP est obligatoire pour communiquer en reseau local, ce qui rend ce scan tres difficile a cacher.
- Donnees recoltees : IP, MAC, et Hostname (Nom de la machine).

### 2. L'Audit de Surface (L'Entree) - port_scanner.py
- Ce qu'il fait : Il teste les 65 535 ports possibles (ou une selection) pour trouver les "portes ouvertes".
- Le moteur : Il utilise Nettacker (OWASP) pour sa fiabilite industrielle.
- Le resultat : Une liste de services (ex: HTTP sur le port 80, SSH sur le port 22).

### 3. L'Analyse de Vulnerabilites (Le Diagnostic) - vulnerability_scanner.py
- Ce qu'il fait : Une fois les ports trouves, il regarde ce qu'il y a derriere.
- Tests effectues :
    - Versions de logiciels (ex: "Ton serveur Apache est en version 2.4.1, il est vieux !").
    - Fichiers oublies (ex: un dossier .git ou un fichier backup.zip).
    - Failles Web (ex: absence de protection contre le detournement de clic).

### 4. Le Moteur de Resolution (L'Intelligence) - resolution_engine.py
C'est ici que reside "l'intelligence" du projet.
- Le Systeme Expert : Il possede un dictionnaire de connaissances (RESOLUTION_GUIDES). Pour chaque faille, il connait la solution.
- La Securite "Fail-Safe" (Alerte Generique) : Si le scanner trouve une faille tres rare qu'il ne connait pas encore, il ne s'arrete pas. Il genere une Alerte Generique qui conseille a l'utilisateur d'analyser les logs manuellement. Cela garantit qu'aucune menace n'est ignoree.
- Le Score de Securite : 
    - Chaque machine part avec 100 points.
    - Chaque vulnerabilite trouvee retire 10 points (ou plus selon la gravite).
    - Classification : 
        - Safe (>80) : Reseau sain.
        - At Risk (50-80) : Corrections necessaires.
        - Critical (<50) : Danger immediat d'intrusion.

### 5. L'Auto-Patching (L'Action) - auto_patcher.py
- Ce qu'il fait : C'est le mode "Robot de Maintenance". 
- Actions concretes :
    - Il modifie les fichiers de configuration (ex: /etc/ssh/sshd_config) pour bloquer les acces dangereux.
    - Il configure le pare-feu UFW pour ne laisser ouvert que ce qui est strictement nécessaire.

---

## Interaction avec SENTINELLE (Le Binome)

C'est une question frequente : Quelle est la difference entre SCAN et SENTINELLE ?

| Caracteristique | Module SCAN | Module SENTINELLE |
| :--- | :--- | :--- |
| Mode | Proactif (Audit) | Reactif (Protection) |
| Temporalite | Se lance a la demande ou par intervalle. | Tourne en permanence (Temps reel). |
| Action sur les Ports | Identifie les ports ouverts et les ferme s'ils sont inutiles. | Detecte si quelqu'un essaie de scanner les ports depuis l'exterieur. |
| Analogie | C'est l'inspecteur qui verifie si les serrures sont solides. | C'est le vigile et la camera qui surveillent si quelqu'un touche a la porte. |

Exemple concret : Si SCAN oublie de fermer un port, SENTINELLE verra l'attaquant essayer de l'utiliser et bloquera son IP instantanement.

---

## Questions Frequentes (FAQ Soutenance)

Q : Pourquoi utiliser Nettacker et pas Nmap ?
R : Nmap est excellent pour le scan pur, mais Nettacker est oriente "Audit de vulnerabilites" et permet une integration plus facile avec des modules Web et des sorties JSON complexes que nous traitons dans notre moteur de resolution.

Q : Ton score de 100 est-il arbitraire ?
R : Il suit une logique de conformite. Dans MIRAGE, 100 signifie "Zero defaut detecte". C'est un indicateur de performance (KPI) pour l'administrateur.

Q : Est-ce que l'auto-patching est risque ?
R : Oui, c'est pourquoi il est conçu pour etre active par l'administrateur. Cependant, pour des serveurs critiques, l'automatisation permet de reduire le "temps d'exposition" entre la decouverte d'une faille et sa correction.

Q : Pourquoi le resume mentionne-t-il une "selection" de ports au lieu de toujours scanner les 65 535 ports ?
R : C'est une question de strategie. Scanner tous les ports est extremement lent et tres bruyant (facilement detectable). Par defaut, MIRAGE cible les ports les plus critiques pour rester rapide et discret. Cependant, le mode "Expert" permet de forcer un scan complet si l'on suspecte une menace cachee sur un port inhabituel.

Q : Si je lance un scan depuis le serveur, comment peut-il fermer un port sur une machine distante ?
R : MIRAGE utilise un systeme de "Command and Control" via le Cloud. Le module SCAN detecte la faille et publie l'alerte sur MongoDB Atlas. La machine cible, via le module Sentinelle, ecoute en permanence le Cloud. Des qu'un ordre de correction est publie, Sentinelle l'execute localement en utilisant l'Auto-Patcher. Cela permet de securiser des machines distantes sans avoir besoin d'ouvrir des acces dangereux comme SSH.

---
*Document redige pour une comprehension totale du code source du module SCAN.*