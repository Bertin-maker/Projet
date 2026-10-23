"""Detection des exports HTTP volumineux sur des donnees fictives.

Lit uniquement donnees/acces_web.csv et donnees/inventaire.json.
N'ecrit ni ne modifie aucun fichier source. Bibliotheque standard uniquement.
"""
import csv
import json
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SEUIL_OCTETS = 100_000
RESEAUX_INTERNES = tuple(
    IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def charger_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def charger_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def est_interne(ip):
    try:
        adresse = IPv4Address(ip)
    except ValueError:
        return False
    return any(adresse in reseau for reseau in RESEAUX_INTERNES)


def extraire_scope(chemin):
    parametres = parse_qs(urlparse(chemin).query)
    valeurs = parametres.get("scope", [])
    return valeurs[0] if valeurs else ""


def analyser_export(ligne, actifs_par_ip, actifs_par_nom):
    ip = ligne["ip_source"]
    hote = ligne["hote"]
    chemin = ligne["chemin"]
    portee = extraire_scope(chemin)
    actif_ip = actifs_par_ip.get(ip)
    actif_hote = actifs_par_nom.get(hote)
    raisons = []

    if est_interne(ip):
        raisons.append("IP source interne")
        if actif_ip is None:
            raisons.append("IP source absente de l'inventaire")
    else:
        raisons.append("IP source externe absente de l'inventaire")

    if portee == "tous":
        raisons.append("perimetre global (scope=tous)")
    elif portee:
        raisons.append("perimetre limite (scope=%s)" % portee)
    else:
        raisons.append("perimetre non precise dans l'URL")

    if actif_hote:
        raisons.append(
            "hote %s de criticite %s" % (actif_hote["nom"], actif_hote["criticite"])
        )
    if actif_ip:
        raisons.append("actif source inventorie %s" % actif_ip["nom"])

    if not est_interne(ip) or portee == "tous":
        niveau = "PRIORITAIRE"
        conclusion = (
            "Signal a investiguer : source externe et/ou export global. "
            "L'inventaire ne fournit aucune autorisation pour ce perimetre ; "
            "cela ne prouve pas a soi seul un incident."
        )
    else:
        niveau = "A VERIFIER"
        conclusion = (
            "Export metier potentiel : source interne et perimetre restreint. "
            "Verifier les droits et le besoin metier ; ce n'est pas "
            "automatiquement un incident."
        )

    return niveau, "; ".join(raisons) + ". " + conclusion


def afficher_contexte(inventaire):
    print("Contexte inventaire :")
    for actif in inventaire.get("actifs", []):
        print(
            " - %s (%s) : %s, criticite %s"
            % (actif["nom"], actif["ip"], actif["type"], actif["criticite"])
        )
    for observation in inventaire.get("observations", []):
        print(" - Observation : %s" % observation)
    print(
        " - Une sauvegarde approuvee (POSTE-07 vers 198.51.100.20, "
        "volume eleve attendu) n'est pas un incident."
    )
    print(
        " - Cette approbation vise un flux reseau precis et ne couvre pas "
        "les exports HTTP d'autres actifs ou destinations."
    )
    print()


def main():
    base = Path(__file__).resolve().parents[1]
    lignes = charger_csv(base / "donnees" / "acces_web.csv")
    inventaire = charger_json(base / "donnees" / "inventaire.json")

    actifs_par_ip = {a["ip"]: a for a in inventaire.get("actifs", [])}
    actifs_par_nom = {a["nom"]: a for a in inventaire.get("actifs", [])}

    exports = []
    for ligne in lignes:
        try:
            octets = int(ligne["octets_reponse"])
        except (KeyError, TypeError, ValueError):
            continue
        if "/export" in ligne.get("chemin", "").lower() and octets >= SEUIL_OCTETS:
            exports.append(ligne)

    exports.sort(key=lambda r: r["horodatage_utc"])
    afficher_contexte(inventaire)
    print(
        "Exports HTTP volumineux (seuil %d octets) : %d"
        % (SEUIL_OCTETS, len(exports))
    )
    for ligne in exports:
        niveau, justification = analyser_export(
            ligne, actifs_par_ip, actifs_par_nom
        )
        print(
            "%s | %s | %s | %s | %s %s | %s octets | %s"
            % (
                ligne["horodatage_utc"],
                ligne["hote"],
                ligne["utilisateur"],
                ligne["ip_source"],
                ligne["methode"],
                ligne["chemin"],
                ligne["octets_reponse"],
                niveau,
            )
        )
        print("   Justification : %s" % justification)


if __name__ == "__main__":
    main()
