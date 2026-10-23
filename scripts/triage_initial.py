"""Triage deterministe de donnees exclusivement fictives. Python standard uniquement."""
import argparse, csv, json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

def load(path):
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def dt(s):
    return datetime.fromisoformat(s.replace('Z','+00:00'))

def triage(base):
    d=base/'donnees'
    auth=load(d/'authentification.csv')
    web=load(d/'acces_web.csv')
    process=load(d/'processus.csv')
    flows=load(d/'flux_reseau.csv')
    signals=[]
    groups=defaultdict(list)
    for r in auth:
        groups[(r['utilisateur'], r['ip_source'])].append(r)
    for (user,ip), rows in groups.items():
        failures=sorted((x for x in rows if x['resultat']=='ECHEC'), key=lambda x:x['horodatage_utc'])
        for success in sorted((x for x in rows if x['resultat']=='SUCCES'),key=lambda x:x['horodatage_utc']):
            t=dt(success['horodatage_utc'])
            window=[x for x in failures if t-timedelta(minutes=6) <= dt(x['horodatage_utc']) < t]
            if len(window)>=8:
                signals.append({'categorie':'authentification','indice':'Plusieurs echecs suivis de succes','utilisateur':user,'ip':ip,'horodatage_utc':success['horodatage_utc'],'nombre_echecs':len(window),'interpretation':'Indicateur a investiguer ; ne prouve pas la compromission'})
                break
    for r in web:
        if int(r['octets_reponse']) >= 100000 and '/exports' in r['chemin']:
            signals.append({'categorie':'export_web','indice':'Export volumineux','utilisateur':r['utilisateur'],'ip':r['ip_source'],'horodatage_utc':r['horodatage_utc'],'octets':int(r['octets_reponse']),'chemin':r['chemin'],'interpretation':'Verification des droits et du contexte metier requise'})
    for r in process:
        if r['hote']=='WEB-01' and r['processus'].lower()=='powershell.exe' and r['parent'].lower()=='python.exe':
            signals.append({'categorie':'processus','indice':'Processus inhabituel depuis le service Web','hote':r['hote'],'horodatage_utc':r['horodatage_utc'],'interpretation':'Investigation necessaire ; preuve insuffisante'})
    for r in flows:
        if int(r['octets_sortants'])>=10000000:
            signals.append({'categorie':'flux','indice':'Flux sortant volumineux','source':r['source'],'destination':r['destination'],'horodatage_utc':r['horodatage_utc'],'octets':int(r['octets_sortants']),'contexte':r['service'],'interpretation':'Comparer a la sauvegarde autorisee et au role de l actif'})
    return {'simulation':True,'sources':['authentification.csv','acces_web.csv','processus.csv','flux_reseau.csv'],'nombre_evenements':sum(map(len,[auth,web,process,flows])),'signaux':signals}

def main():
    ap=argparse.ArgumentParser(description='Triage de logs fictifs, sans acces reseau ni modification des sources.')
    ap.add_argument('--racine',default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument('--sortie',default=None)
    args=ap.parse_args()
    root=Path(args.racine).resolve();result=triage(root)
    out=Path(args.sortie).resolve() if args.sortie else root/'rapports'/'triage_initial.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Evenements analyses :',result['nombre_evenements'])
    print('Signaux a verifier :',len(result['signaux']))
    for r in result['signaux']:
        print(' -',r['categorie'],r['indice'],r['horodatage_utc'])
    print('Rapport :',out)

if __name__=='__main__': main()
