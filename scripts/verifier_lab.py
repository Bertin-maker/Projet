"""Verification des donnees de demonstration. Ne requiert aucun module externe."""
import csv, json
from pathlib import Path
from triage_initial import triage
root=Path(__file__).resolve().parents[1]
for name in ['authentification.csv','acces_web.csv','processus.csv','flux_reseau.csv']:
    with (root/'donnees'/name).open(encoding='utf-8-sig',newline='') as f:
        rows=list(csv.DictReader(f))
        assert len(rows)>=20, (name,len(rows))
assert json.loads((root/'donnees'/'inventaire.json').read_text(encoding='utf-8'))['organisation'].startswith('NordCampus')
r=triage(root)
assert r['nombre_evenements']>=140, r['nombre_evenements']
assert any(x['categorie']=='authentification' and x['utilisateur']=='support.nora' for x in r['signaux'])
assert any(x['categorie']=='processus' for x in r['signaux'])
assert sum(x['categorie']=='flux' for x in r['signaux'])>=2
assert sum(x['categorie']=='export_web' for x in r['signaux'])>=3
print('Validation OK :',r['nombre_evenements'],'evenements et',len(r['signaux']),'signaux ; simulation seulement.')
