import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP

# Track start times and counts for each connection
connection_start_times = {}
connection_pkt_counts = defaultdict(lambda: {
    "spkts": 0, "dpkts": 0, "sbytes": 0, "dbytes": 0,
    "sinpkt_times": [], "dinpkt_times": [],
    "sjit_times": [], "djit_times": []
})
last_pkt_times = defaultdict(lambda: {"src": 0, "dst": 0})

def extract_features(packet):
    if IP not in packet:
        return {}

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet.sport if TCP in packet or UDP in packet else 0
    dport = packet.dport if TCP in packet or UDP in packet else 0
    conn_id = (src_ip, dst_ip, sport, dport, proto)

    if conn_id not in connection_start_times:
        connection_start_times[conn_id] = time.time()

    dur = time.time() - connection_start_times[conn_id]
    connection_pkt_counts[conn_id]["spkts"] += 1
    connection_pkt_counts[conn_id]["sbytes"] += len(packet[IP].payload)
    connection_pkt_counts[conn_id]["dpkts"] += 1
    connection_pkt_counts[conn_id]["dbytes"] += len(packet[IP].payload)

    if last_pkt_times[conn_id]["src"] != 0:
        sinpkt = time.time() - last_pkt_times[conn_id]["src"]
        connection_pkt_counts[conn_id]["sinpkt_times"].append(sinpkt)
        if len(connection_pkt_counts[conn_id]["sinpkt_times"]) > 1:
            sjit = abs(connection_pkt_counts[conn_id]["sinpkt_times"][-1] - connection_pkt_counts[conn_id]["sinpkt_times"][-2])
            connection_pkt_counts[conn_id]["sjit_times"].append(sjit)
    else:
        sinpkt = 0
    last_pkt_times[conn_id]["src"] = time.time()

    if last_pkt_times[conn_id]["dst"] != 0:
        dinpkt = time.time() - last_pkt_times[conn_id]["dst"]
        connection_pkt_counts[conn_id]["dinpkt_times"].append(dinpkt)
        if len(connection_pkt_counts[conn_id]["dinpkt_times"]) > 1:
            djit = abs(connection_pkt_counts[conn_id]["dinpkt_times"][-1] - connection_pkt_counts[conn_id]["dinpkt_times"][-2])
            connection_pkt_counts[conn_id]["djit_times"].append(djit)
    else:
        dinpkt = 0
    last_pkt_times[conn_id]["dst"] = time.time()

    service = "-"
    service_ports = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 443: "https"}
    if dport in service_ports:
        service = service_ports[dport]

    state = "CON"
    if TCP in packet:
        flags = packet[TCP].flags
        if flags & 0x02:
            state = "SYN"
        if flags & 0x10:
            state = "ACK"
        if flags & 0x01:
            state = "FIN"
        if flags & 0x04:
            state = "RST"

    smean = connection_pkt_counts[conn_id]["sbytes"] / connection_pkt_counts[conn_id]["spkts"]
    dmean = connection_pkt_counts[conn_id]["dbytes"] / connection_pkt_counts[conn_id]["dpkts"]

    features = {
        "dur": dur,
        "proto": packet[IP].proto if IP in packet else 0,
        "service": service,
        "state": state,
        "spkts": connection_pkt_counts[conn_id]["spkts"],
        "dpkts": connection_pkt_counts[conn_id]["dpkts"],
        "sbytes": connection_pkt_counts[conn_id]["sbytes"],
        "dbytes": connection_pkt_counts[conn_id]["dbytes"],
        "rate": connection_pkt_counts[conn_id]["sbytes"] / dur if dur > 0 else 0,
        "sttl": packet[IP].ttl if IP in packet else 0,
        "dttl": 0,
        "sload": 0,
        "dload": 0,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": sum(connection_pkt_counts[conn_id]["sjit_times"]) / len(connection_pkt_counts[conn_id]["sjit_times"]) if connection_pkt_counts[conn_id]["sjit_times"] else 0,
        "djit": sum(connection_pkt_counts[conn_id]["djit_times"]) / len(connection_pkt_counts[conn_id]["djit_times"]) if connection_pkt_counts[conn_id]["djit_times"] else 0,
        "swin": packet[TCP].window if TCP in packet else 0,
        "stcpb": packet[TCP].seq if TCP in packet else 0,
        "dtcpb": packet[TCP].ack if TCP in packet else 0,
        "dwin": packet[TCP].window if TCP in packet else 0,
        "tcprtt": 0,
        "synack": 0,
        "ackdat": 0,
        "smean": smean,
        "dmean": dmean,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 0,
        "ct_state_ttl": 0,
        "ct_dst_ltm": 0,
        "ct_src_dport_ltm": 0,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 0,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": 0,
        "ct_srv_dst": 0,
        "is_sm_ips_ports": 0
    }
    return features
