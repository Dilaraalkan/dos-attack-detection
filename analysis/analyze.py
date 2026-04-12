from scapy.all import rdpcap
from collections import Counter

packets = rdpcap("attack_traffic.pcap")

print("Toplam paket sayısı:", len(packets))

ips = []

for pkt in packets:
    if pkt.haslayer("IP"):
        ips.append(pkt["IP"].src)

counter = Counter(ips)

print("\nEn çok trafik gönderen IP'ler:")
for ip, count in counter.most_common(10):
    print(ip, "→", count)

# -------------------------
# 🚨 Saldırı tespit kısmı
# -------------------------

top_ip, top_count = counter.most_common(1)[0]

threshold = 1000

print("\n--- SONUÇ ---")

if top_count > threshold:
    print("🚨 DOĞS SALDIRISI TESPİT EDİLDİ!")
    print(f"Saldırgan IP: {top_ip}")
else:
    print("🟢 Normal trafik")