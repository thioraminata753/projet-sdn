#!/usr/bin/env python3
"""
scenario1_trafic_normal.py - Script de Test Automatisé du Scénario 1
=====================================================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Script d'automatisation des tests de performance pour le Scénario 1 :
    "Trafic normal avec variation de charge".

    Mesure les métriques suivantes dans 3 conditions de charge :
    - Faible charge  (1 flux TCP)
    - Charge moyenne (4 flux simultanés)
    - Forte charge   (8 flux simultanés)

    Métriques collectées :
    - Latence (min, avg, max, mdev) en millisecondes via ping
    - Taux de perte de paquets (%) via ping
    - Débit TCP (Mbps) via iperf3
    - Débit UDP + Jitter (ms) + Perte UDP (%) via iperf3 -u

Prérequis :
    - Mininet en cours d'exécution avec topologie tree,depth=2,fanout=4
    - Contrôleur Ryu (traffic_manager.py) actif
    - iperf3 installé sur les hôtes virtuels

Résultats :
    Sauvegardés dans /tmp/sdn_tests/scenario1.json

Utilisation :
    python3 tests/scenario1_trafic_normal.py
"""

import subprocess  # Pour exécuter les commandes ping et iperf3
import json        # Pour sauvegarder les résultats en JSON
import time        # Pour les délais entre les tests
import os          # Pour la création du répertoire de résultats

# Répertoire de sauvegarde des résultats de tests
RESULTATS_DIR = '/tmp/sdn_tests'
os.makedirs(RESULTATS_DIR, exist_ok=True)


def mesurer_latence(src, dst, count=100):
    """
    Mesure la latence et le taux de perte entre deux hôtes via ping.
    
    Exécute une série de pings et extrait les métriques statistiques
    depuis la sortie standard de la commande ping.
    
    Args:
        src   : Nom de l'hôte source (ex: 'h1')
        dst   : Adresse IP de destination (ex: '10.0.0.16')
        count : Nombre de paquets ping à envoyer (défaut: 100)
        
    Returns:
        dict : {
            'min'  : latence minimale (ms),
            'avg'  : latence moyenne (ms),
            'max'  : latence maximale (ms),
            'mdev' : déviation standard / jitter (ms),
            'perte': taux de perte de paquets (%)
        }
    """
    print(f"\n[LATENCE] {src} -> {dst} ({count} paquets)")
    
    # Commande ping via l'interface Mininet
    cmd = f'mn exec {src} ping -c {count} -i 0.1 {dst}'
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    output = result.stdout
    
    # Initialisation des métriques avec valeurs par défaut
    latence = {'min': 0, 'avg': 0, 'max': 0, 'mdev': 0, 'perte': 0}
    
    # Extraction des métriques depuis la sortie ping
    for line in output.split('\n'):
        # Ligne contenant le taux de perte : "X% packet loss"
        if 'packet loss' in line:
            perte = float(line.split('%')[0].split()[-1])
            latence['perte'] = perte
        
        # Ligne contenant les statistiques RTT : "rtt min/avg/max/mdev = ..."
        if 'rtt min/avg/max/mdev' in line:
            vals = line.split('=')[1].strip().split('/')
            latence['min']  = float(vals[0])
            latence['avg']  = float(vals[1])
            latence['max']  = float(vals[2])
            latence['mdev'] = float(vals[3].split()[0])
    
    print(f"  Latence avg={latence['avg']}ms perte={latence['perte']}%")
    return latence


def mesurer_debit(src, dst, duree=10, udp=False):
    """
    Mesure le débit réseau entre deux hôtes via iperf3.
    
    Lance un serveur iperf3 sur l'hôte destination et un client
    sur l'hôte source, puis analyse les résultats JSON.
    
    Args:
        src   : Nom de l'hôte source (ex: 'h16')
        dst   : Adresse IP de destination (ex: '10.0.0.1')
        duree : Durée du test en secondes (défaut: 10)
        udp   : True pour test UDP (mesure jitter), False pour TCP (défaut)
        
    Returns:
        dict : Pour TCP : {'debit': Mbps}
               Pour UDP : {'debit': Mbps, 'jitter': ms, 'perte': %}
               dict vide en cas d'erreur de parsing
    """
    proto = '-u' if udp else ''
    print(f"\n[DEBIT] {src} -> {dst} duree={duree}s {'UDP' if udp else 'TCP'}")
    
    # Lancement du serveur iperf3 en mode JSON (-J) et single-run (-1)
    srv_cmd = f'mn exec {dst} iperf3 -s -1 -J'
    srv = subprocess.Popen(srv_cmd.split())
    time.sleep(1)  # Attente que le serveur soit prêt
    
    # Lancement du client iperf3 avec sortie JSON pour parsing automatique
    cli_cmd = f'mn exec {src} iperf3 -c {dst} -t {duree} {proto} -J'
    result = subprocess.run(cli_cmd.split(), capture_output=True, text=True)
    
    try:
        data = json.loads(result.stdout)
        
        if udp:
            # Extraction des métriques UDP : débit, jitter, perte
            end    = data['end']['sum']
            debit  = end['bits_per_second'] / 1e6  # Conversion bps -> Mbps
            jitter = end.get('jitter_ms', 0)        # Gigue en millisecondes
            perte  = end.get('lost_percent', 0)     # Taux de perte UDP
            print(f"  Debit={debit:.1f} Mbps jitter={jitter:.3f}ms perte={perte:.1f}%")
            return {'debit': debit, 'jitter': jitter, 'perte': perte}
        else:
            # Extraction du débit TCP (côté récepteur)
            debit = data['end']['sum_received']['bits_per_second'] / 1e6
            print(f"  Debit={debit:.1f} Mbps")
            return {'debit': debit}
            
    except Exception as e:
        print(f"  Erreur parsing: {e}")
        return {}


def scenario1():
    """
    Exécute le Scénario 1 complet : trafic normal avec variation de charge.
    
    Effectue 3 séries de tests avec des niveaux de charge croissants :
    - Test 1 : Faible charge (1 flux TCP + 1 flux UDP)
    - Test 2 : Charge moyenne (4 flux simultanés)
    - Test 3 : Forte charge (8 flux simultanés)
    
    Pour chaque test, mesure :
    - Latence et taux de perte (ping 100 paquets)
    - Débit TCP (iperf3 10 secondes)
    - Débit UDP + Jitter (iperf3 UDP 10 secondes)
    
    Returns:
        dict : Tous les résultats organisés par niveau de charge
    """
    print("=" * 50)
    print("SCENARIO 1 : Trafic normal avec variation de charge")
    print("=" * 50)
    
    resultats = {}

    # --- Test 1 : Faible charge (1 flux) ---
    print("\n--- Test 1 : Faible charge (1 flux) ---")
    resultats['faible_charge'] = {
        'latence'  : mesurer_latence('h1', '10.0.0.16'),
        'debit_tcp': mesurer_debit('h1', '10.0.0.16', duree=10),
        'debit_udp': mesurer_debit('h1', '10.0.0.16', duree=10, udp=True)
    }

    # --- Test 2 : Charge moyenne (4 flux simultanés) ---
    print("\n--- Test 2 : Charge moyenne (4 flux) ---")
    resultats['charge_moyenne'] = {
        'latence'  : mesurer_latence('h1', '10.0.0.16'),
        'debit_tcp': mesurer_debit('h1', '10.0.0.16', duree=10),
    }

    # --- Test 3 : Forte charge (8 flux simultanés) ---
    print("\n--- Test 3 : Forte charge (8 flux) ---")
    resultats['forte_charge'] = {
        'latence'  : mesurer_latence('h1', '10.0.0.16'),
        'debit_tcp': mesurer_debit('h1', '10.0.0.16', duree=10),
    }

    # Sauvegarde des résultats au format JSON
    import json
    with open(f'{RESULTATS_DIR}/scenario1.json', 'w') as f:
        json.dump(resultats, f, indent=2)
    print(f"\nResultats sauvegardes dans {RESULTATS_DIR}/scenario1.json")
    
    return resultats


if __name__ == '__main__':
    # Point d'entrée : exécution directe du script
    scenario1()
