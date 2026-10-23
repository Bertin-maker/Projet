# Synthèse SOC — NordCampus (simulation)

- **Date de rédaction :** 2026-10-22
- **Périmètre :** journaux fictifs du laboratoire, fenêtre du 2026-10-19 de 08:45 à 10:15 UTC
- **Sources :** `donnees/authentification.csv`, `donnees/acces_web.csv`, `donnees/processus.csv`, `donnees/flux_reseau.csv`, `donnees/inventaire.json`, `rapports/triage_initial.json`
- **Statut :** analyse préliminaire. Aucune action à impact n'a été exécutée.

## 1. Résumé pour le responsable

- 155 événements ont été analysés ; le triage retient 7 signaux, dont 5 jugés prioritaires.
- Le faisceau le plus préoccupant associe 12 échecs d'authentification puis un succès pour `support.nora` depuis `192.0.2.47`, deux exports `scope=tous`, un PowerShell lancé par Python sur `WEB-01` et un flux sortant de 14,6 Mo.
- Aucune compromission n'est démontrée : les journaux sont corrélatifs, limités à la fenêtre observée et ne contiennent ni commande PowerShell ni attribution de l'IP.
- Deux signaux sont probablement légitimes : l'export de `agent.marc` (à confirmer) et la sauvegarde `POSTE-07` vers `198.51.100.20`, approuvée par l'inventaire.
- Les actions à impact — réinitialisation de compte, blocage d'IP, isolation de machine — ne sont pas exécutées et restent soumises à validation.

## 2. Chronologie UTC

| Heure UTC | Événement | Référence |
|---|---|---|
| 08:45–09:09 | Activité de référence : sessions internes `10.20.1.21/22/23`, pages web ~1,9 Ko, télémétrie sortante 25–31 Ko. | `donnees/authentification.csv:2-14`, `donnees/acces_web.csv:2-10`, `donnees/flux_reseau.csv:2-9` |
| 09:10:00–09:13:07 | 12 échecs d'authentification pour `support.nora` depuis `192.0.2.47`, à environ 17 secondes d'intervalle. | `donnees/authentification.csv:15-28` |
| 09:13:00 | Succès simultané de `support.nora` depuis l'IP interne habituelle `10.20.1.23`. | `donnees/authentification.csv:27` |
| 09:15:02 | Succès de `support.nora` depuis `192.0.2.47`, après la série d'échecs. | `donnees/authentification.csv:30` |
| 09:16:20 | `support.nora` depuis `192.0.2.47` : `GET /admin/export?type=notes` → HTTP 403, 580 octets. | `donnees/acces_web.csv:13` |
| 09:17:10 | `GET /api/exports?scope=tous` → HTTP 200, 166 200 octets, même IP externe. | `donnees/acces_web.csv:14` |
| 09:17:44 | Second `GET /api/exports?scope=tous` → HTTP 200, 172 800 octets, même IP externe. | `donnees/acces_web.csv:15` |
| 09:18:00 | `support.nora` depuis `10.20.1.23` : `GET /profil` → HTTP 200, 1 933 octets. | `donnees/acces_web.csv:16` |
| 09:18:25 | `WEB-01` : `powershell.exe` lancé par `python.exe` sous `service-web` ; commande non conservée. | `donnees/processus.csv:9` |
| 09:18:40 | `WEB-01` : `python.exe` lancé par `powershell.exe` ; intention non prouvée. | `donnees/processus.csv:10` |
| 09:19:05 | `10.20.2.15` (`WEB-01`) → `198.51.100.91:443`, 14 600 000 octets, destination externe non classée. | `donnees/flux_reseau.csv:11` |
| 09:22:00–09:22:10 | `agent.marc` : un échec puis un succès depuis `10.20.1.22`, contexte « erreur de frappe plausible ». | `donnees/authentification.csv:34-35` |
| 09:23:00 | `10.20.2.10` (`POSTE-07`) → `198.51.100.20:443`, 15 200 000 octets, sauvegarde approuvée. | `donnees/flux_reseau.csv:13` |
| 09:25:00 | `agent.marc` depuis `10.20.1.22` : `GET /api/exports?scope=departement` → HTTP 200, 152 000 octets. | `donnees/acces_web.csv:19` |
| 09:25:00 | Nouvelle session interne de `support.nora` depuis `10.20.1.23`. | `donnees/authentification.csv:37` |

## 3. Événements suspects et faux positifs possibles

### Événements suspects

1. **Séquence d'authentification anormale pour `support.nora`.** Douze échecs depuis `192.0.2.47`, puis un succès depuis la même IP. Les sessions habituelles de cet utilisateur viennent de `10.20.1.23`. Le faisceau est compatible avec une tentative de mot de passe répétée suivie d'une connexion réussie, mais ne prouve pas une prise de contrôle.
2. **Tentative d'accès à un export administrateur.** Le `403` sur `/admin/export?type=notes` précède de 50 secondes le premier export `scope=tous`. Cela peut indiquer une reconnaissance de privilèges ou une simple erreur de droits.
3. **Deux exports massifs `scope=tous`.** 166 200 et 172 800 octets, contre environ 1 900 octets pour les pages habituelles. Le périmètre « tous » et l'IP externe renforcent le caractère sensible.
4. **Exécution inhabituelle sur `WEB-01`.** `powershell.exe` enfant de `python.exe`, puis l'inverse. La commande n'est pas conservée ; l'intention reste inconnue.
5. **Flux sortant inhabituel depuis `WEB-01`.** 14,6 Mo vers `198.51.100.91`, destination absente du trafic de référence et non répertoriée dans l'inventaire. Le lien avec les exports est temporel, pas prouvé.
6. **Sessions concurrentes pour `support.nora`.** Des sessions internes existent à 09:13, 09:18 et 09:25, alors qu'une session externe est active. Cela peut être un usage légitime simultané ou une indication supplémentaire d'anomalie.

### Faux positifs possibles

- **Export de `agent.marc` à 09:25:00.** Source interne `10.20.1.22`, périmètre `departement`, événement isolé, sessions habituelles. Probable export métier, mais l'autorisation doit être confirmée.
- **Échec isolé de `agent.marc` à 09:22:00.** Un seul échec suivi d'un succès 10 secondes plus tard, avec un contexte d'erreur de frappe plausible. Le seuil de 8 échecs n'est pas atteint.
- **Sauvegarde `POSTE-07` → `198.51.100.20` à 09:23:00.** L'inventaire indique explicitement que ce volume est approuvé ; le couple source/destination figure aussi dans le trafic de référence.
- **Exports de `support.nora` potentiellement légitimes.** Un besoin métier de export global ne peut pas être exclu sans confirmation. Cependant, l'IP externe, les échecs préalables, le `403` et les événements suivants justifient une vérification prioritaire.
- **`403` sur `/admin/export`.** Peut résulter d'un rôle mal configuré ou d'une mauvaise manipulation, sans intention malveillante.
- **IP de documentation.** `192.0.2.0/24` et `198.51.100.0/24` sont réservées à la documentation. Dans cette simulation, elles représentent des adresses externes ; il ne faut pas les blanchir au seul motif qu'elles sont réservées.

## 4. Trois actions de vérification immédiate

1. **Valider ou invalider la légitimité de la session `support.nora`.**
   - Vérifier MFA, appareil, VPN, géolocalisation et horaires avec le responsable hiérarchique.
   - Comparer la session externe `192.0.2.47` et les sessions internes `10.20.1.23`.
   - Vérifier si les exports `scope=tous` étaient autorisés et quel volume de données était attendu.
   - **Recommandation soumise à validation :** si la session n'est pas légitime, réinitialiser le compte et révoquer les sessions. Ne pas exécuter cette action sans validation.

2. **Analyser `WEB-01` autour de 09:18.**
   - Examiner l'arbre de processus, les journaux PowerShell (4103/4104), la ligne de commande, les fichiers créés ou lus et les journaux du serveur web.
   - Rechercher ce qui a déclenché `powershell.exe` et si des données ont été lues ou copiées.
   - **Recommandation soumise à validation :** si l'exécution est confirmée malveillante, isoler la machine du réseau. Ne pas l'isoler sur la seule base des journaux actuels.

3. **Qualifier le flux vers `198.51.100.91` et l'export de `agent.marc`.**
   - Consulter les journaux firewall, proxy, DNS et TLS : destination, SNI, volume réel, durée et éventuel propriétaire.
   - Comparer avec le flux de sauvegarde approuvé vers `198.51.100.20`.
   - Confirmer avec le métier l'autorisation de l'export `scope=departement` de `agent.marc`.
   - **Recommandation soumise à validation :** si la destination est confirmée non autorisée, bloquer l'IP ou restreindre les sorties. Ne pas bloquer sur la seule corrélation temporelle.

## 5. Proposition de règle de détection

Règle de corrélation : **échecs répétés → succès → export volumineux**, avec les seuils observés dans le laboratoire (8 échecs en 6 minutes, export ≥ 100 000 octets dans les 15 minutes suivant le succès).

```kusto
let seuil_echecs = 8;
let fenetre_echecs = 6m;
let fenetre_correlation = 15m;
let seuil_export = 100000;

let echecs =
    SecurityEvent
    | where TimeGenerated > ago(24h)
    | where EventID == 4625
    | summarize
        NbEchecs = count(),
        PremierEchec = min(TimeGenerated),
        DernierEchec = max(TimeGenerated)
      by Utilisateur = tostring(TargetUserName),
         IpSource = tostring(IpAddress)
    | where NbEchecs >= seuil_echecs
    | where DernierEchec - PremierEchec <= fenetre_echecs;

let succes =
    SecurityEvent
    | where TimeGenerated > ago(24h)
    | where EventID == 4624
    | project HeureSucces = TimeGenerated,
              Utilisateur = tostring(TargetUserName),
              IpSource = tostring(IpAddress);

echecs
| join kind=inner succes on Utilisateur, IpSource
| where HeureSucces between (DernierEchec .. DernierEchec + fenetre_correlation)
| join kind=inner (
    WebAccess_CL
    | where TimeGenerated > ago(24h)
    | extend
        Utilisateur = tostring(Utilisateur_s),
        IpSource = tostring(IpSource_s),
        Chemin = tostring(Chemin_s),
        StatutHttp = toint(StatutHttp_d),
        OctetsReponse = tolong(OctetsReponse_d)
    | where Chemin has "/exports"
    | where StatutHttp == 200
    | where OctetsReponse >= seuil_export
    | project HeureExport = TimeGenerated,
              Utilisateur, IpSource, Chemin, OctetsReponse
) on Utilisateur, IpSource
| where HeureExport between (HeureSucces .. HeureSucces + fenetre_correlation)
| project PremierEchec, DernierEchec, HeureSucces, HeureExport,
          Utilisateur, IpSource, NbEchecs, Chemin, OctetsReponse
| order by HeureExport desc
```

Champs à mapper avant exécution :

- `SecurityEvent` : `TimeGenerated`, `EventID`, `TargetUserName`, `IpAddress`.
- `WebAccess_CL` : `TimeGenerated`, `Utilisateur_s`, `IpSource_s`, `Chemin_s`, `StatutHttp_d`, `OctetsReponse_d`.

La règle doit être complétée par une corrélation avec les processus (`powershell.exe` enfant de `python.exe` sur `WEB-01`) et les flux sortants supérieurs à 10 Mo vers une destination non approuvée. Une alerte fondée seulement sur le volume reste insuffisante.

## 6. Mesures défensives à envisager

- **Identité :** MFA et accès conditionnel pour les comptes à privilèges, détection des échecs répétés, alerte sur connexion depuis une IP inhabituelle, revue des sessions concurrentes.
- **Exports :** restriction de `scope=tous` aux rôles autorisés, validation métier ou double contrôle, limitation de débit, journalisation des exports et protection contre la fuite de données.
- **Poste et serveur :** journalisation PowerShell (script block et module), EDR, restriction des processus enfants pour le compte de service web, contrôle d'intégrité des fichiers.
- **Réseau :** filtrage des sorties, liste blanche des destinations connues, segmentation de `WEB-01`, blocage ou alerte sur LDAP/RMI/DNS sortants non nécessaires, inspection proxy/TLS.
- **Journalisation :** centralisation des journaux, synchronisation NTP, conservation suffisante, collecte des journaux firewall/proxy/DNS/EDR pour corréler les flux.
- **Sauvegarde :** vérifier que le flux `POSTE-07` → `198.51.100.20` reste dans le périmètre approuvé et que les sauvegardes ne sont pas accessibles depuis `WEB-01`.
- **Actions à impact :** réinitialisation de compte, blocage d'IP et isolation de machine restent des **recommandations soumises à validation** ; elles ne sont pas exécutées dans le cadre de ce rapport.

## 7. Points encore inconnus

- La session externe de `support.nora` était-elle légitime (MFA, appareil, VPN, déplacement, horaires) ?
- Les exports `scope=tous` étaient-ils autorisés, et quelles données contenaient-ils ?
- Qu'a exécuté `powershell.exe` sur `WEB-01` ? La ligne de commande n'est pas conservée.
- La destination `198.51.100.91` est-elle malveillante, compromise ou légitime ? Aucune attribution n'est disponible.
- Le flux de 14,6 Mo contient-il les données exportées ? La corrélation est temporelle, pas une preuve de causalité.
- L'export de `agent.marc` (`scope=departement`) était-il autorisé par le métier ?
- Les sessions internes de `support.nora` à 09:13, 09:18 et 09:25 sont-elles un usage légitime concurrent ou un signe supplémentaire d'anomalie ?
- Le flux de sauvegarde `POSTE-07` → `198.51.100.20` a-t-il été vérifié comme authentique et non détourné ?
- Existe-t-il d'autres comptes, actifs ou segments réseau concernés ? Les journaux ne couvrent que 155 événements sur une fenêtre limitée.
- Les journaux d'authentification ne fournissent ni identifiant de session, ni résultat MFA, ni détail sur le jeton utilisé.
- Aucune donnée du laboratoire n'établit de lien avec CVE-2021-44228 ; l'inventaire ne recense pas Java/Log4j, mais il n'est pas exhaustif. Les références Log4Shell ci-dessous sont donc citées comme contexte externe, pas comme preuve d'exposition.

## Références

### Données du laboratoire

- `donnees/authentification.csv`
- `donnees/acces_web.csv`
- `donnees/processus.csv`
- `donnees/flux_reseau.csv`
- `donnees/inventaire.json`
- `rapports/triage_initial.json`
- `detections/exports.py`

### Références Web réellement consultées

- NVD — CVE-2021-44228 : https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- NVD API 2.0 — CVE-2021-44228 : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
- CISA — AA21-356A : https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
- CISA — Apache Log4j Vulnerability Guidance : https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance
- Apache Logging Services — Security : https://logging.apache.org/log4j/2.x/security.html
