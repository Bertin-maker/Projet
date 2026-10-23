# Missions d'IA agentique en cybersécurité - Partie 3

Ce dossier accompagne le document Word « Partie 3 » et est indépendant du portail Flask des parties 1 et 2.

Toutes les données sont **fictives**. Les adresses 192.0.2.0/24 et 198.51.100.0/24 sont des plages réservées aux exemples, pas des cibles à contacter.

## Démarrer sous Windows 11

Décompressez le dossier et ouvrez PowerShell à sa racine. Aucune bibliothèque Python supplémentaire n'est requise pour les données fournies.

```powershell
py -3 .\scripts\verifier_lab.py
py -3 .\scripts\triage_initial.py
$env:OPENCODE_ENABLE_EXA = "1"
opencode
```

Sélectionnez dans `/models` votre modèle hébergé **DeepSeek V4.1 Flash** déjà accessible. La mise à disposition, les frais et les limites dépendent du fournisseur et de l'abonnement.

## Internet

Le fichier `opencode.json` autorise `webfetch` et `websearch`. L'outil `webfetch` permet de lire une URL connue. L'outil `websearch` effectue une recherche de pages et peut exiger un fournisseur ou une option d'activation selon la version d'OpenCode. L'environnement PowerShell ci-dessus active Exa pour les versions OpenCode V1 prises en charge. Si cet outil reste indisponible, lire une URL connue avec `webfetch` suffit pour le test, et les missions sur journaux restent disponibles hors recherche Web.

N'acceptez que des commandes nécessaires dans le périmètre du laboratoire. Ne donnez pas au modèle les secrets ou les vrais journaux de votre poste.

## Fichiers

- `donnees/authentification.csv` : journaux fictifs d'authentification.
- `donnees/acces_web.csv` : journaux fictifs du serveur Web.
- `donnees/processus.csv` : événements de processus fictifs.
- `donnees/flux_reseau.csv` : résumé de flux réseau fictifs.
- `donnees/inventaire.json` : contexte des actifs et deux informations permettant d'éviter les faux positifs.
- `scripts/triage_initial.py` : règles déterministes pour produire des signaux, et non un verdict.
- `configurations/deploiement_k8s.yaml` et `Dockerfile.demo` : configurations à analyser sans déployer.
- `rapports/` : emplacement conseillé pour les productions de l'agent.

Ne pas exécuter ni déployer les configurations vulnérables.
