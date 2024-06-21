from scapy.all import IP, TCP, sniff
from database import insert_packet, block_entry
from classification import classify_packet

# Set to keep track of processed packets
processed_packets = set()

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        sport = packet.sport if TCP in packet else 0
        dport = packet.dport if TCP in packet else 0

        packet_id = (src_ip, dst_ip, sport, dport, proto)

        if packet_id in processed_packets:
            return

        processed_packets.add(packet_id)

        packet_info = {
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "payload": str(packet[IP].payload)
        }
        insert_packet(packet_info)

        if classify_packet(packet_info) == 1:  # Assuming 1 is the label for malicious
            block_entry({"ip": dst_ip})

def start_sniffing():
    # Capture all traffic
    sniff(prn=packet_handler, store=0)
