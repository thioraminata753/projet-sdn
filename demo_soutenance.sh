#!/bin/bash
# ============================================================
# Script de Demonstration SDN - Soutenance Master 1
# Auteure : Aminata Thior
# Encadrant : Pr. Malick Ndoye
# Universite Assane Seck de Ziguinchor
# Annee : 2024-2025
# ============================================================

VERT='\033[0;32m'
ROUGE='\033[0;31m'
BLEU='\033[0;34m'
JAUNE='\033[1;33m'
BLANC='\033[1;37m'
NC='\033[0m'

afficher_titre() {
    echo ""
    echo -e "${BLEU}=============================================="
    echo -e "  $1"
    echo -e "==============================================${NC}"
    echo ""
}

afficher_etape() {
    echo -e "${JAUNE}>>> ETAPE $1 : $2${NC}"
    echo -e "${BLANC}$3${NC}"
    echo ""
}

afficher_commande() {
    echo -e "${VERT}  \$ $1${NC}"
}

afficher_resultat() {
    echo -e "${BLANC}  Resultat attendu : $1${NC}"
}

afficher_info() {
    echo -e "${ROUGE}  [INFO] $1${NC}"
}

clear
echo -e "${BLEU}"
echo "  =================================================="
echo "  DEMONSTRATION FONCTIONNELLE - ARCHITECTURE SDN"
echo "  Conception et Deploiement d'une Architecture SDN"
echo "  pour la Gestion Dynamique du Trafic et la Securite"
echo "  =================================================="
echo "  Auteure  : Aminata Thior"
echo "  Encadrant: Pr. Malick Ndoye"
echo "  Universite Assane Seck de Ziguinchor"
echo "  Master 1 Reseaux Avances - 2024-2025"
echo "  =================================================="
echo -e "${NC}"
echo ""
read -p "Appuyez sur ENTREE pour commencer la demonstration..."

# ============================================================
afficher_titre "PHASE 1 : PREPARATION DE L'ENVIRONNEMENT"
# ============================================================

afficher_etape "1.1" "Activation de l'environnement virtuel Python" \
"L'environnement virtuel isole les dependances du projet
(Ryu 4.34, matplotlib, numpy) du systeme."

afficher_commande "source ~/projet-sdn/venv/bin/activate"
afficher_commande "cd ~/projet-sdn"
afficher_resultat "(venv) aminata@aminata-HP-EliteBook-840-G4:~/projet-sdn\$"
echo ""

afficher_etape "1.2" "Verification de l'installation" \
"Verification que tous les outils sont disponibles."

afficher_commande "ryu-manager --version"
afficher_commande "mn --version"
afficher_commande "iperf3 --version"
afficher_commande "hping3 --version"
afficher_resultat "Tous les outils installes et prets"
echo ""

afficher_etape "1.3" "Structure du projet GitHub" \
"Le code source complet est disponible sur :
https://github.com/thioraminata753/projet-sdn

Modules developpes :
  - traffic_manager.py  : Gestion dynamique du trafic
  - ddos_detector.py    : Detection DDoS par entropie
  - firewall.py         : Pare-feu stateful ACL
  - security_manager.py : Module securite unifie
  - qos.py              : Qualite de service (QoS)
  - monitoring.py       : Surveillance du trafic
  - routing.py          : Routage dynamique
  - load_balancer.py    : Load balancing Round-Robin
  - mitigation.py       : Mitigation automatique"
echo ""
read -p "Phase 1 terminee. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 2 : LANCEMENT DE L'ARCHITECTURE SDN"
# ============================================================

afficher_etape "2.1" "Lancement du controleur Ryu" \
"Le controleur SDN Ryu est le cerveau du reseau.
Il dispose d'une vue globale et programme les switches
via le protocole OpenFlow 1.3.

OUVRIR UN NOUVEAU TERMINAL et lancer :"

afficher_commande "source ~/projet-sdn/venv/bin/activate"
afficher_commande "ryu-manager ~/projet-sdn/traffic_manager.py"
afficher_info "Observer : 'Switch connecte : 000000000000000X'"
afficher_info "Observer : 'METRIQUES switch' toutes les 5 secondes"
afficher_info "Observer : 'Route installee' lors du premier trafic"
echo ""

afficher_etape "2.2" "Lancement de l'emulateur Mininet" \
"Mininet emule une topologie arbre avec :
  - 1 switch racine (s1)
  - 4 switches intermediaires (s2, s3, s4, s5)
  - 16 hotes (h1 a h16), IP : 10.0.0.1 a 10.0.0.16

OUVRIR UN AUTRE TERMINAL et lancer :"

afficher_commande "sudo mn --controller=remote,ip=127.0.0.1,port=6633 \\"
afficher_commande "        --switch=ovsk,protocols=OpenFlow13 \\"
afficher_commande "        --topo=tree,depth=2,fanout=4 --mac"
afficher_resultat "*** Starting CLI:"
afficher_resultat "mininet>"
echo ""
read -p "Phase 2 terminee. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 3 : SCENARIO 1 - TRAFIC NORMAL"
# ============================================================

afficher_etape "3.1" "Test de connectivite - pingall" \
"Verification que tous les hotes se joignent.
Resultat attendu : 0% dropped (240/240 received)"

afficher_commande "mininet> pingall"
afficher_resultat "*** Results: 0% dropped (240/240 received)"
afficher_info "Le controleur SDN installe les regles de flux automatiquement"
echo ""

afficher_etape "3.2" "Mesure de latence - Faible charge" \
"Mesure de latence h1 -> h16 avec 100 paquets ping.
Metrique cle : latence moyenne < 0.2 ms"

afficher_commande "mininet> h1 ping -c 100 10.0.0.16"
afficher_resultat "rtt min/avg/max/mdev = 0.083/0.134/2.220/0.210 ms"
afficher_resultat "100 packets transmitted, 100 received, 0% packet loss"
afficher_info "Latence SDN = 0.134 ms vs Traditionnel = 0.279 ms (-52%)"
echo ""

afficher_etape "3.3" "Mesure de debit TCP - Faible charge (1 flux)" \
"Test de debit TCP avec iperf3 pendant 10 secondes."

afficher_commande "mininet> h1 iperf3 -s &"
afficher_commande "mininet> h16 iperf3 -c 10.0.0.1 -t 10"
afficher_resultat "Bitrate : 23.5 Gbits/sec"
afficher_resultat "Retransmissions : 0"
afficher_info "Debit excellent grace au routage dynamique SDN"
echo ""

afficher_etape "3.4" "Mesure de debit TCP - Charge moyenne (4 flux)" \
"Test de debit avec 4 flux TCP simultanees."

afficher_commande "mininet> h1 iperf3 -s &"
afficher_commande "mininet> h5 iperf3 -s &"
afficher_commande "mininet> h16 iperf3 -c 10.0.0.1 -t 10 &"
afficher_commande "mininet> h12 iperf3 -c 10.0.0.5 -t 10"
afficher_resultat "Bitrate : 24.2 Gbits/sec (charge moyenne)"
afficher_info "Load balancing Round-Robin distribue la charge equitablement"
echo ""

afficher_etape "3.5" "Mesure du jitter UDP" \
"Test de jitter avec iperf3 en mode UDP (1 Gbps)."

afficher_commande "mininet> h1 iperf3 -s &"
afficher_commande "mininet> h16 iperf3 -c 10.0.0.1 -u -b 1G -t 10"
afficher_resultat "Jitter : 0.001 ms"
afficher_resultat "Perte UDP : 1.2%"
afficher_info "Jitter quasi nul - excellent pour les applications temps reel"
echo ""
read -p "Scenario 1 termine. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 4 : SCENARIO 2 - ATTAQUE DDoS"
# ============================================================

afficher_etape "4.1" "Lancement du module de detection DDoS" \
"Arreter traffic_manager.py (Ctrl+C) et lancer ddos_detector.py
Ce module detecte les attaques par :
  - Entropie de Shannon des IPs source/destination
  - Taux de paquets/sec par IP source (seuil : 2 pkt/s)
  - Nombre de destinations par IP (seuil : 10)"

afficher_commande "ryu-manager ~/projet-sdn/ddos_detector.py"
afficher_info "Observer les analyses toutes les 5 secondes"
echo ""

afficher_etape "4.2" "Mesure latence avant attaque" \
"Etablissement de la baseline de latence normale."

afficher_commande "mininet> h1 ping -c 10 10.0.0.16"
afficher_resultat "rtt min/avg/max = 0.105/0.478/1.966 ms"
afficher_info "Latence normale avant attaque : 0.478 ms"
echo ""

afficher_etape "4.3" "Lancement de l'attaque SYN flood + UDP flood" \
"Simulation d'une attaque DDoS reelle avec hping3 :
  - SYN flood : paquets TCP SYN en mode flood
  - UDP flood : paquets UDP en mode flood"

afficher_commande "mininet> h1 hping3 -S -p 80 --flood 10.0.0.16 &"
afficher_commande "mininet> h1 hping3 -2 -p 53 --flood 10.0.0.16 &"
afficher_info "Observer dans Ryu :"
afficher_info "  [ALERTE DDoS] switch X : IP 10.0.0.1 = 446 pkt/s > seuil 2"
afficher_info "  [MITIGATION] BLOCAGE IP 10.0.0.1 switch X - regle DROP 60s"
echo ""

afficher_etape "4.4" "Impact sur le trafic legitime" \
"Mesure de la latence pendant l'attaque depuis h2."

afficher_commande "mininet> h2 ping -c 10 10.0.0.16"
afficher_resultat "rtt min/avg/max = 8633/12718/16833 ms"
afficher_resultat "Perte : 10%"
afficher_info "Impact severe de l'attaque SYN+UDP flood"
echo ""

afficher_etape "4.5" "Efficacite de la mitigation automatique" \
"Apres blocage de l'IP attaquante par le systeme SDN,
le trafic legitime retrouve des performances normales."

afficher_commande "mininet> h1 pkill hping3"
afficher_commande "mininet> h2 ping -c 10 10.0.0.16"
afficher_resultat "rtt min/avg/max = 0.053/2.389/28.498 ms"
afficher_resultat "Perte : 0%"
afficher_info "Mitigation efficace ! Latence retablie apres blocage DROP"
afficher_info "Temps detection : 5 secondes"
afficher_info "Temps mitigation : < 1 seconde"
echo ""
read -p "Scenario 2 termine. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 5 : SCENARIO 3 - PANNE D'UN LIEN"
# ============================================================

afficher_etape "5.1" "Lancement du module traffic_manager" \
"Relancer le module de gestion du trafic."

afficher_commande "ryu-manager ~/projet-sdn/traffic_manager.py"
echo ""

afficher_etape "5.2" "Latence normale avant panne" \
"Mesure de la latence de reference avant la panne."

afficher_commande "mininet> h1 ping -c 5 10.0.0.16"
afficher_resultat "rtt avg = 5.056 ms, perte = 0%"
echo ""

afficher_etape "5.3" "Simulation de la panne du lien s1-s2" \
"La commande 'link down' simule une panne physique du lien
entre le switch racine s1 et le switch s2."

afficher_commande "mininet> link s1 s2 down"
afficher_commande "mininet> h1 ping -c 10 10.0.0.16"
afficher_resultat "100% packet loss"
afficher_info "La topologie arbre n'a qu'un seul chemin -> panne totale"
afficher_info "Sur Fat-Tree : reroutage automatique possible"
echo ""

afficher_etape "5.4" "Retablissement du lien" \
"Simulation du retablissement du lien apres reparation."

afficher_commande "mininet> link s1 s2 up"
afficher_commande "mininet> h1 ping -c 5 10.0.0.16"
afficher_resultat "rtt avg = 6.086 ms, perte = 0%"
afficher_info "Connectivite retablie automatiquement par le controleur SDN"
echo ""
read -p "Scenario 3 termine. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 6 : SCENARIO 4 - QoS SOUS CONGESTION"
# ============================================================

afficher_etape "6.1" "Lancement du module QoS" \
"Le module QoS installe des regles de priorite sur tous
les switches des leur connexion :
  HAUTE (30) : iperf3 TCP 5201, SSH TCP 22
  MOYENNE (20): TCP general, ICMP (15)
  BASSE (10)  : UDP"

afficher_commande "ryu-manager ~/projet-sdn/qos.py"
afficher_resultat "QoS switch XXXX : regle HAUTE priorite (iperf3 TCP 5201)"
afficher_resultat "QoS switch XXXX : regle BASSE priorite (UDP)"
echo ""

afficher_etape "6.2" "Test QoS avec trafic mixte" \
"Generation simultanee de trafic TCP haute priorite
et UDP basse priorite pour observer la priorisation."

afficher_commande "mininet> h1 iperf3 -s &"
afficher_commande "mininet> h9 iperf3 -s &"
afficher_commande "mininet> h16 iperf3 -c 10.0.0.1 -t 10 &"
afficher_commande "mininet> h12 iperf3 -c 10.0.0.9 -u -b 100M -t 10 &"
afficher_commande "mininet> h1 ping -c 10 10.0.0.16"
afficher_resultat "TCP iperf3 : 19.7 Gbps (HAUTE priorite)"
afficher_resultat "ICMP latence : 0.219 ms (MOYENNE priorite)"
afficher_resultat "UDP 100M : limite (BASSE priorite)"
afficher_info "La QoS SDN garantit la bande passante pour le trafic critique"
echo ""
read -p "Scenario 4 termine. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 7 : RESULTATS ET GRAPHIQUES"
# ============================================================

afficher_etape "7.1" "Generation des graphiques de performance" \
"Script Python matplotlib generant 5 graphiques comparatifs."

afficher_commande "python3 ~/projet-sdn/graphiques_phase5.py"
afficher_resultat "5 graphiques generes dans resultats_graphiques/"
echo ""

afficher_etape "7.2" "Visualisation des graphiques" \
"Affichage des graphiques de performance."

afficher_commande "eog ~/projet-sdn/resultats_graphiques/ &"
afficher_info "Graphique 1 : Debit TCP selon la charge"
afficher_info "Graphique 2 : Impact DDoS sur la latence"
afficher_info "Graphique 3 : Panne de lien"
afficher_info "Graphique 4 : Comparaison SDN vs Traditionnel"
afficher_info "Graphique 5 : Overhead du controleur"
echo ""

afficher_etape "7.3" "Tableau comparatif final" \
"Resume des performances SDN vs Reseau Traditionnel :"

echo -e "${BLANC}"
echo "  Critere              | SDN (Ryu)      | Traditionnel"
echo "  ---------------------|----------------|-------------"
echo "  Latence avg          | 0.134 ms       | 0.279 ms"
echo "  Debit TCP (1 flux)   | 23.5 Gbps      | 23.9 Gbps"
echo "  Debit TCP (4 flux)   | 24.2 Gbps      | 22.0 Gbps"
echo "  Jitter UDP           | 0.001 ms       | Non mesure"
echo "  Detection DDoS       | 5 secondes     | Aucune"
echo "  Mitigation DDoS      | Auto (< 1s)    | Manuelle"
echo "  QoS dynamique        | 3 niveaux      | Non"
echo "  Reduction latence    | 52% vs trad.   | Reference"
echo -e "${NC}"
echo ""
read -p "Phase 7 terminee. Appuyez sur ENTREE pour continuer..."

# ============================================================
afficher_titre "PHASE 8 : CAPTURE WIRESHARK MESSAGES OPENFLOW"
# ============================================================

afficher_etape "8.1" "Analyse des messages OpenFlow" \
"Wireshark permet de visualiser les messages echanges
entre le controleur Ryu et les switches OVS."

afficher_commande "sudo wireshark &"
afficher_info "Interface : lo (loopback)"
afficher_info "Filtre : openflow_v4"
afficher_info "Messages observes :"
afficher_info "  - OFPT_MULTIPART_REQUEST : requetes stats (toutes les 5s)"
afficher_info "  - OFPT_MULTIPART_REPLY   : reponses avec compteurs"
afficher_info "  - OFPT_ECHO_REPLY        : keepalive controleur-switch"
afficher_info "  - OFPT_FLOW_MOD          : installation regles de flux"
echo ""

afficher_etape "8.2" "Mesure de l'overhead OpenFlow" \
"Comptage des messages OpenFlow en 10 secondes."

afficher_commande "sudo tshark -i lo -f 'tcp port 6633' -a duration:10 2>/dev/null | wc -l"
afficher_resultat "30 messages en 10 secondes = 3 messages/sec"
afficher_info "Overhead minimal du protocole OpenFlow"
echo ""
read -p "Phase 8 terminee. Appuyez sur ENTREE pour la conclusion..."

# ============================================================
afficher_titre "CONCLUSION DE LA DEMONSTRATION"
# ============================================================

echo -e "${VERT}"
echo "  BILAN DE LA DEMONSTRATION :"
echo "  ============================="
echo ""
echo "  Module Trafic :"
echo "    Debit TCP        : 23.5 Gbps (faible charge)"
echo "    Latence          : 0.134 ms (-52% vs traditionnel)"
echo "    Jitter UDP       : 0.001 ms"
echo "    Perte paquets    : 0%"
echo ""
echo "  Module Securite :"
echo "    Detection DDoS   : 5 secondes"
echo "    Mitigation auto  : < 1 seconde"
echo "    Pare-feu stateful: Telnet/FTP/RPC/TFTP bloques"
echo ""
echo "  Module QoS :"
echo "    TCP iperf3       : 19.7 Gbps (HAUTE priorite)"
echo "    ICMP latence     : 0.219 ms (MOYENNE priorite)"
echo ""
echo "  Code source : github.com/thioraminata753/projet-sdn"
echo -e "${NC}"
echo ""
echo -e "${BLEU}=============================================="
echo "  MERCI POUR VOTRE ATTENTION !"
echo "  Questions ?"
echo -e "==============================================${NC}"
echo ""

