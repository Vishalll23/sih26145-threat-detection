"""
TRAFFIC SIMULATOR
==================
Ye script fake network traffic generate karta hai — normal traffic aur
attack traffic (port scan + DDoS) dono.

Output: ek list of "flow records" (dictionaries), jisme har record
ek network connection ko represent karta hai.

Real duniya mein ye data NetFlow/PCAP se aata, lekin humare "unidirectional
read-only" scenario ko simulate karne ke liye hum khud generate kar rahe hain.
"""

import random
import time
import json
from datetime import datetime, timedelta


def random_ip(prefix="192.168.1"):
    """Ek random local-network-style IP address banata hai."""
    return f"{prefix}.{random.randint(1, 254)}"


def random_public_ip():
    """Ek random public-internet-style IP address banata hai (spoofed IPs ke liye)."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_normal_traffic(num_flows=50, start_time=None):
    """
    NORMAL TRAFFIC generate karta hai.
    Jaise koi normal user browsing kar raha ho — chand connections,
    common ports (80, 443, 22), normal time-gaps ke saath.

    REALISM NOTE: Real-world traffic captures (jaise CIC-IDS2017 dataset)
    mein port-distribution bahut skewed hoti hai — zyadatar traffic
    HTTP/HTTPS (80/443) pe hota hai, thoda DNS (53), aur bahut kam
    SSH/DB jaise ports pe. Humne yahan weighted distribution use ki hai
    isi real-world pattern ko match karne ke liye, taaki demo mein
    "normal baseline" zyada authentic dikhe.
    """
    if start_time is None:
        start_time = datetime.now()

    flows = []
    # weighted distribution: HTTPS aur HTTP sabse common (real traffic capture jaisa),
    # DNS thoda kam, SSH/DB sabse kam (occasional admin/backend traffic)
    port_weights = [
        (443, 0.45),   # HTTPS — sabse zyada
        (80, 0.30),    # HTTP
        (53, 0.15),    # DNS
        (22, 0.06),    # SSH — occasional
        (3306, 0.04),  # MySQL — occasional
    ]
    ports, weights = zip(*port_weights)
    current_time = start_time

    for i in range(num_flows):
        flow = {
            "flow_id": f"N{i:04d}",
            "src_ip": random_ip(),
            "dst_ip": random_ip("10.0.0"),
            "dst_port": random.choices(ports, weights=weights, k=1)[0],
            "protocol": "TCP",
            "bytes": random.randint(200, 5000),
            "timestamp": current_time.isoformat(),
            "label": "normal"  # sirf testing/validation ke liye, asli system ye nahi dekhega
        }
        flows.append(flow)
        # normal traffic mein gaps thode random hote hain (0.1 - 2 second) —
        # ye "human browsing behaviour" jaisa irregular gap simulate karta hai
        current_time += timedelta(seconds=random.uniform(0.1, 2.0))

    return flows, current_time


def generate_port_scan_attack(start_time, attacker_ip=None, num_ports=45, window_seconds=3):
    """
    PORT SCAN ATTACK simulate karta hai.
    Ek hi source IP, bahut saare ALAG-ALAG destination ports try karta hai,
    bahut kam time (window_seconds) mein.

    REALISM NOTE: CIC-IDS2017 ke "PortScan" attack samples mein scanners
    aksar SEQUENTIAL ports try karte hain (1, 2, 3, 4...) na ki bilkul
    random — kyunki tools jaise Nmap default mein ports ko order mein
    scan karte hain (ya common well-known ports ki list follow karte hain).
    Humne yahan 70% sequential-style aur 30% random-style scanning mix
    ki hai, taaki dono tarah ke real scan-patterns cover ho.
    """
    if attacker_ip is None:
        attacker_ip = random_ip("192.168.1")  # attacker bhi internal network mein ho sakta hai

    victim_ip = random_ip("10.0.0")
    flows = []
    current_time = start_time

    # 70% ports: ek sequential block se (jaise real Nmap scan karta hai)
    # 30% ports: bilkul random (kuch scanners randomize bhi karte hain evasion ke liye)
    seq_count = int(num_ports * 0.7)
    seq_start = random.randint(1, 9000)
    sequential_ports = list(range(seq_start, seq_start + seq_count))
    random_ports = random.sample(
        [p for p in range(1, 10000) if p not in sequential_ports],
        num_ports - seq_count
    )
    scanned_ports = sequential_ports + random_ports
    random.shuffle(scanned_ports)  # thoda mix karo taaki bilkul predictable order na ho

    for i, port in enumerate(scanned_ports):
        flow = {
            "flow_id": f"PS{i:04d}",
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "dst_port": port,
            "protocol": "TCP",
            "bytes": random.randint(40, 60),  # scan packets chhote hote hain (SYN packets, no payload)
            "timestamp": current_time.isoformat(),
            "label": "port_scan"  # ground-truth label, validation ke liye
        }
        flows.append(flow)
        # attack mein gaps BAHUT chhote hote hain (0.01 - 0.08 sec) — isi se scan pakda jaata hai
        current_time += timedelta(seconds=random.uniform(0.01, 0.08))

    return flows, current_time, attacker_ip


def generate_ddos_attack(start_time, victim_ip=None, num_packets=800, window_seconds=1):
    """
    DDoS ATTACK simulate karta hai.
    Bahut saari ALAG-ALAG (spoofed) source IPs se, ek hi victim ko,
    bahut saare packets bahut kam time mein bheje jaate hain.

    REALISM NOTE: Real SYN-flood attacks (jaise CIC-IDS2018 ke DDoS
    samples mein dekha jaata hai) mein packet size bahut CONSISTENT
    hoti hai — kyunki attacker automated tool se ek fixed-size SYN
    packet baar-baar bhejta hai (payload nahi hota, sirf TCP header).
    Isliye humne bytes ka range bahut tight rakha hai (44-60 bytes,
    ek typical SYN packet ka size) instead of wide random range —
    ye "low variance" pattern hi ek strong DDoS indicator hota hai.
    """
    if victim_ip is None:
        victim_ip = random_ip("10.0.0")

    flows = []
    current_time = start_time

    for i in range(num_packets):
        flow = {
            "flow_id": f"DD{i:04d}",
            "src_ip": random_public_ip(),  # har packet ALAG spoofed IP se (high entropy)
            "dst_ip": victim_ip,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": random.randint(44, 60),  # tight range — real SYN-flood packets consistent size ke hote hain
            "timestamp": current_time.isoformat(),
            "label": "ddos"  # ground-truth label, validation ke liye
        }
        flows.append(flow)
        # bahut hi tez rate — packets almost ek saath aa rahe hain
        current_time += timedelta(seconds=random.uniform(0.0005, 0.002))

    return flows, current_time


def generate_mixed_scenario():
    """
    Ek poora scenario banata hai: normal traffic -> port scan -> normal -> DDoS
    Ye function tumhare detectors ko test karne ke liye "ground truth" data deta hai.
    """
    all_flows = []
    t = datetime.now()

    print("[*] Generating normal traffic (phase 1)...")
    normal1, t = generate_normal_traffic(num_flows=40, start_time=t)
    all_flows.extend(normal1)

    print("[*] Injecting PORT SCAN attack...")
    scan_flows, t, attacker = generate_port_scan_attack(start_time=t, num_ports=45)
    all_flows.extend(scan_flows)
    print(f"    -> Attacker IP: {attacker}")

    print("[*] Generating normal traffic (phase 2)...")
    normal2, t = generate_normal_traffic(num_flows=40, start_time=t)
    all_flows.extend(normal2)

    print("[*] Injecting DDoS attack...")
    ddos_flows, t = generate_ddos_attack(start_time=t, num_packets=800)
    all_flows.extend(ddos_flows)

    print(f"[*] Total flows generated: {len(all_flows)}")
    return all_flows


if __name__ == "__main__":
    # Ye chalega jab tum "python traffic_simulator.py" run karoge
    flows = generate_mixed_scenario()

    # Sab flows ko ek JSON file mein save kar do — ye file baaki detectors use karenge
    output_file = "simulated_traffic.json"
    with open(output_file, "w") as f:
        json.dump(flows, f, indent=2)

    print(f"\n[✓] Saved {len(flows)} flow records to '{output_file}'")
    