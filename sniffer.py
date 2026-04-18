from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto  = packet[IP].proto

        # Déterminer le protocole
        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{timestamp}] {protocol} | {src_ip}:{sport} → {dst_ip}:{dport}")

        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{timestamp}] {protocol} | {src_ip}:{sport} → {dst_ip}:{dport}")

        elif ICMP in packet:
            protocol = "ICMP"
            print(f"[{timestamp}] {protocol} | {src_ip} → {dst_ip}")

        else:
            print(f"[{timestamp}] OTHER (proto={proto}) | {src_ip} → {dst_ip}")

        # Afficher le payload si présent
        if Raw in packet:
            payload = packet[Raw].load[:50]  # premiers 50 bytes
            print(f"         Payload: {payload}")

print("Network Sniffer ")
print("Démarrage de la capture... (Ctrl+C pour arrêter)\n")

# Capturer 50 paquets sur l'interface eth0
sniff(iface="wlan0", prn=packet_callback, count=50, store=False)
