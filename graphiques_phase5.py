#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os

OUTPUT_DIR = os.path.expanduser("~/projet-sdn/resultats_graphiques")
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams.update({'font.size': 11, 'axes.grid': True, 'grid.alpha': 0.3, 'figure.dpi': 150})

COLORS = {'sdn': '#2196F3', 'trad': '#FF5722', 'ddos': '#F44336', 'normal': '#4CAF50'}

# Graphique 1 : Debit TCP
charges = ['Faible\n(1 flux)', 'Moyenne\n(4 flux)', 'Forte\n(8 flux)']
debits_sdn = [23.5, 24.2, 21.5]
debits_trad = [23.9, 22.0, 19.0]
x = np.arange(len(charges))
width = 0.35
fig, ax = plt.subplots(figsize=(9, 5))
ax.bar(x - width/2, debits_sdn, width, label='SDN (Ryu)', color=COLORS['sdn'], alpha=0.85)
ax.bar(x + width/2, debits_trad, width, label='Traditionnel', color=COLORS['trad'], alpha=0.85)
ax.set_xlabel('Charge reseau')
ax.set_ylabel('Debit TCP (Gbits/sec)')
ax.set_title('Scenario 1 : Debit TCP - SDN vs Traditionnel')
ax.set_xticks(x); ax.set_xticklabels(charges); ax.legend(); ax.set_ylim(0, 30)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'graphique1_debit.png')); plt.close()
print("graphique1 OK")

# Graphique 2 : Impact DDoS
phases = ['Avant\nattaque', 'ICMP\nflood', 'SYN+UDP\nflood', 'Apres\nmitigation']
latences = [0.478, 4.793, 12718.0, 2.389]
pertes = [0, 0, 10, 0]
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
colors = [COLORS['normal'], COLORS['ddos'], COLORS['ddos'], COLORS['sdn']]
bars = ax1.bar(phases, latences, color=colors, alpha=0.85)
ax1.set_ylabel('Latence (ms) - echelle log')
ax1.set_title('Impact DDoS sur la latence')
ax1.set_yscale('log')
for bar, val in zip(bars, latences):
    ax1.annotate(f'{val}ms', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                 xytext=(0,3), textcoords="offset points", ha='center', fontsize=8)
colors2 = [COLORS['normal'], COLORS['normal'], COLORS['ddos'], COLORS['normal']]
bars2 = ax2.bar(phases, pertes, color=colors2, alpha=0.85)
ax2.set_ylabel('Taux de perte (%)')
ax2.set_title('Taux de perte pendant DDoS')
ax2.set_ylim(0, 15)
for bar, val in zip(bars2, pertes):
    ax2.annotate(f'{val}%', xy=(bar.get_x() + bar.get_width()/2, max(bar.get_height(), 0.3)),
                 xytext=(0,3), textcoords="offset points", ha='center', fontsize=10)
plt.suptitle('Scenario 2 : Attaque DDoS', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'graphique2_ddos.png')); plt.close()
print("graphique2 OK")

# Graphique 3 : Panne lien
phases3 = ['Avant panne', 'Pendant panne\n(s1-s2 down)', 'Apres\nretablissement']
latences3 = [5.056, 0, 6.086]
pertes3 = [0, 100, 0]
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5))
colors3 = [COLORS['normal'], COLORS['ddos'], COLORS['sdn']]
bars3 = ax1.bar(phases3, latences3, color=colors3, alpha=0.85, width=0.5)
ax1.set_ylabel('Latence (ms)')
ax1.set_title('Latence avant/pendant/apres panne')
for bar, val in zip(bars3, latences3):
    if val > 0:
        ax1.annotate(f'{val}ms', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     xytext=(0,3), textcoords="offset points", ha='center', fontsize=9)
    else:
        ax1.annotate('100% perte', xy=(bar.get_x() + bar.get_width()/2, 0.5),
                     ha='center', fontsize=9, color='red')
bars4 = ax2.bar(phases3, pertes3, color=colors3, alpha=0.85, width=0.5)
ax2.set_ylabel('Taux de perte (%)')
ax2.set_title('Taux de perte avant/pendant/apres panne')
ax2.set_ylim(0, 120)
for bar, val in zip(bars4, pertes3):
    ax2.annotate(f'{val}%', xy=(bar.get_x() + bar.get_width()/2, max(bar.get_height(), 2)),
                 xytext=(0,3), textcoords="offset points", ha='center', fontsize=10)
plt.suptitle('Scenario 3 : Panne de lien', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'graphique3_panne.png')); plt.close()
print("graphique3 OK")

# Graphique 4 : Comparaison SDN vs Traditionnel
fig, ax = plt.subplots(figsize=(13, 7))
ax.axis('off')
table_data = [
    ['Critere', 'SDN (Ryu)', 'Traditionnel', 'Avantage'],
    ['Latence avg (normal)', '0.134 ms', '0.279 ms', 'SDN'],
    ['Debit TCP (1 flux)', '23.5 Gbps', '23.9 Gbps', 'Comparable'],
    ['Debit TCP (4 flux)', '24.2 Gbps', '22.0 Gbps', 'SDN'],
    ['Jitter UDP', '0.001 ms', 'Non mesure', 'SDN'],
    ['Perte paquets (normal)', '0%', '0%', 'Egal'],
    ['Detection DDoS', '5 secondes', 'Aucune', 'SDN'],
    ['Mitigation DDoS', 'Auto (<1s)', 'Manuelle', 'SDN'],
    ['QoS dynamique', 'Oui (3 niveaux)', 'Non', 'SDN'],
    ['Overhead CPU', '21.5%', 'N/A', 'Info'],
    ['Overhead memoire', '65 MB', 'N/A', 'Info'],
    ['Messages OpenFlow', '3 msg/sec', 'N/A', 'Info'],
]
table = ax.table(cellText=table_data[1:], colLabels=table_data[0],
                 cellLoc='center', loc='center', colWidths=[0.28, 0.22, 0.22, 0.18])
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 1.7)
for (row, col), cell in table.get_celld().items():
    if row == 0:
        cell.set_facecolor('#1565C0')
        cell.set_text_props(color='white', fontweight='bold')
    elif col == 3 and row > 0:
        val = table_data[row][3]
        if val == 'SDN':
            cell.set_facecolor('#C8E6C9')
            cell.set_text_props(color='#1B5E20', fontweight='bold')
        elif val in ['Egal', 'Comparable']:
            cell.set_facecolor('#FFF9C4')
        else:
            cell.set_facecolor('#F5F5F5')
    elif row % 2 == 0:
        cell.set_facecolor('#F5F5F5')
ax.set_title('Tableau Comparatif : SDN vs Reseau Traditionnel\nProjet SDN Master 1 - Universite Assane Seck de Ziguinchor',
             fontsize=13, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'graphique4_comparaison.png'), bbox_inches='tight'); plt.close()
print("graphique4 OK")

# Graphique 5 : Overhead
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5))
categories = ['CPU (%)', 'Memoire\n(MB/10)']
values_idle = [2.0, 3.0]
values_load = [21.5, 6.5]
x = np.arange(len(categories))
width = 0.35
ax1.bar(x - width/2, values_idle, width, label='Idle', color='#81C784', alpha=0.85)
ax1.bar(x + width/2, values_load, width, label='Sous charge', color=COLORS['ddos'], alpha=0.85)
ax1.set_title('Overhead CPU et Memoire')
ax1.set_xticks(x); ax1.set_xticklabels(categories); ax1.legend()
types_msg = ['MULTIPART\nREQ', 'MULTIPART\nREPLY', 'ECHO\nREPLY', 'FLOW\nMOD']
nb_msg = [8, 10, 8, 4]
ax2.bar(types_msg, nb_msg, color=['#42A5F5','#1565C0','#81C784','#FF7043'], alpha=0.85)
ax2.set_ylabel('Nb messages (10s)')
ax2.set_title('Messages OpenFlow (30 total / 10s)')
plt.suptitle('Overhead du controleur Ryu', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'graphique5_overhead.png')); plt.close()
print("graphique5 OK")

print(f"\nTous les graphiques sont dans : {OUTPUT_DIR}")
