#!/usr/bin/env python3
"""
fat_tree.py - Topologie Fat-Tree pour Mininet
=============================================
Projet : Architecture SDN pour la Gestion Dynamique du Trafic et Sécurité Réseau
Auteur : Aminata Thior
Encadrant : Pr. Malick Ndoye
Université : Assane Seck de Ziguinchor - Master 1 Réseaux Avancés
Année : 2024-2025

Description :
    Implémente une topologie Fat-Tree k=4 pour Mininet.
    Le Fat-Tree est une topologie datacenter à 3 niveaux (Core, Agrégation, Edge)
    offrant une haute disponibilité et une bande passante bisectionnelle maximale.

Architecture Fat-Tree k=4 :
    - Niveau Core       : (k/2)² = 4 switches core
    - Niveau Agrégation : k * (k/2) = 8 switches d'agrégation (2 par pod)
    - Niveau Edge       : k * (k/2) = 8 switches edge (2 par pod)
    - Hôtes             : k³/4 = 16 hôtes (2 par switch edge)
    - Pods              : k = 4 pods

Avantages du Fat-Tree vs arbre simple :
    - Bande passante bisectionnelle égale à la capacité totale des liens
    - Chemins multiples entre toute paire source-destination
    - Tolérance aux pannes grâce à la redondance des chemins
    - Scalabilité linéaire avec k

Utilisation :
    # Lancement direct avec contrôleur distant
    sudo python3 fat_tree.py

    # Avec Mininet --custom
    sudo mn --custom fat_tree.py --topo fattree,k=4 \
            --controller remote,ip=127.0.0.1,port=6633
"""

# Imports Mininet
from mininet.topo import Topo        # Classe de base pour les topologies
from mininet.net import Mininet      # Gestionnaire du réseau émulé
from mininet.node import RemoteController, OVSSwitch  # Contrôleur et switch SDN
from mininet.cli import CLI          # Interface ligne de commande interactive
from mininet.log import setLogLevel  # Configuration du niveau de log


class FatTreeTopo(Topo):
    """
    Topologie Fat-Tree à k niveaux pour Mininet.
    
    Structure en 3 niveaux de switches :
    - Core       : switches racine interconnectant tous les pods
    - Agrégation : switches intermédiaires reliant core et edge dans chaque pod
    - Edge       : switches feuilles auxquels sont connectés les hôtes
    
    Chaque pod contient k/2 switches d'agrégation et k/2 switches edge.
    Chaque switch edge connecte k/2 hôtes.
    """

    def build(self, k=4):
        """
        Construit la topologie Fat-Tree avec le paramètre k.
        
        Paramètre k détermine la taille du Fat-Tree :
        - k=4 : 4 pods, 4 core, 8 agrégation, 8 edge, 16 hôtes
        - k=6 : 6 pods, 9 core, 18 agrégation, 18 edge, 54 hôtes
        - k=8 : 8 pods, 16 core, 32 agrégation, 32 edge, 128 hôtes
        
        Algorithme de construction :
        1. Créer (k/2)² switches core
        2. Pour chaque pod :
           a. Créer k/2 switches d'agrégation
           b. Relier chaque switch d'agrégation aux switches core appropriés
           c. Créer k/2 switches edge
           d. Relier chaque switch edge à tous les switches d'agrégation du pod
           e. Créer k/2 hôtes par switch edge
        
        Args:
            k : Paramètre du Fat-Tree (défaut: 4, doit être pair)
        """
        # ---------------------------------------------------------------
        # Niveau Core : (k/2)² switches interconnectant tous les pods
        # ---------------------------------------------------------------
        core = []
        for i in range((k//2)**2):
            # Nommage : c1, c2, c3, c4 pour k=4
            core.append(self.addSwitch(f'c{i+1}'))

        # ---------------------------------------------------------------
        # Construction des pods (k pods au total)
        # ---------------------------------------------------------------
        for pod in range(k):
            
            # --- Niveau Agrégation : k/2 switches par pod ---
            agg = []
            for i in range(k//2):
                # Nommage : a{pod}{i} (ex: a00, a01, a10, a11 pour k=4)
                s = self.addSwitch(f'a{pod}{i}')
                agg.append(s)
                
                # Connexion switch d'agrégation -> switches core appropriés
                # Chaque switch d'agrégation i se connecte aux core[i*(k/2) : (i+1)*(k/2)]
                for c in core[i*(k//2):(i+1)*(k//2)]:
                    self.addLink(s, c)

            # --- Niveau Edge : k/2 switches par pod ---
            for i in range(k//2):
                # Nommage : e{pod}{i} (ex: e00, e01, e10, e11 pour k=4)
                edge = self.addSwitch(f'e{pod}{i}')
                
                # Connexion switch edge -> tous les switches d'agrégation du pod
                # (maillage complet edge-agrégation dans le pod)
                for a in agg:
                    self.addLink(edge, a)
                
                # --- Hôtes : k/2 hôtes par switch edge ---
                for h in range(k//2):
                    # Nommage : h{pod}{edge}{host} (ex: h000, h001 pour k=4)
                    self.addLink(self.addHost(f'h{pod}{i}{h}'), edge)


# Enregistrement de la topologie pour utilisation avec --custom
topos = {'fattree': FatTreeTopo}


if __name__ == '__main__':
    """
    Point d'entrée pour lancement direct du Fat-Tree.
    
    Lance Mininet avec la topologie Fat-Tree k=4 connectée
    au contrôleur Ryu distant sur 127.0.0.1:6633.
    """
    setLogLevel('info')  # Niveau de log : info (debug, info, warning, error)
    
    # Création de la topologie Fat-Tree avec k=4
    topo = FatTreeTopo(k=4)
    
    # Création du réseau Mininet avec contrôleur SDN distant
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6633),
        switch=OVSSwitch,      # Switch OpenFlow virtuel
        autoSetMacs=True,      # Attribution automatique des adresses MAC
        autoStaticArp=True     # Configuration ARP statique automatique
    )
    
    net.start()
    print("Fat-tree k=4 demarre !")
    print(f"  Switches core       : {(4//2)**2}")
    print(f"  Switches agregation : {4 * (4//2)}")
    print(f"  Switches edge       : {4 * (4//2)}")
    print(f"  Hotes               : {4**3 // 4}")
    
    # Test de connectivité initial
    net.pingAll()
    
    # Interface CLI interactive pour les tests manuels
    CLI(net)
    
    net.stop()
