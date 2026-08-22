"""
DDoS DETECTOR
==============
Do cheezein check karta hai:
1. RATE: kitni packets/sec aa rahi hain (normal se zyada tez toh suspicious)
2. ENTROPY: source IPs kitni "random/spread out" hain (spoofed traffic mein
   bahut saari ALAG-ALAG fake IPs use hoti hain — ye entropy badhata hai)

Entropy simple shabdon mein: agar sab traffic 2-3 IPs se aa raha hai, entropy
KAM hai (normal). Agar traffic 500 alag IPs se aa raha hai, entropy ZYADA hai
(suspicious — spoofing ka sign).
"""

import json
import math
from datetime import datetime
from collections import defaultdict, Counter

# ---- TUNABLE THRESHOLDS ----
TIME_WINDOW_SECONDS = 1        # kitni der ka window dekhna hai (DDoS bahut fast hota hai)
PACKET_RATE_THRESHOLD = 100    # is window mein itne se zyada packets = suspicious
MIN_UNIQUE_IPS_FOR_SPOOFING = 20  # itni alag source IPs ek hi victim ko = spoofing sign


def load_flows(filepath="simulated_traffic.json"):
    with open(filepath, "r") as f:
        return json.load(f)


def calculate_entropy(ip_list):
    """
    Shannon Entropy formula — batata hai IPs kitni 'random/spread' hain.
    0 = sab ek hi IP se (bilkul predictable)
    High value = bahut saari alag IPs, equally distributed (random/spoofed)
    """
    if not ip_list:
        return 0.0
    counts = Counter(ip_list)
    total = len(ip_list)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def detect_ddos(flows):
    """
    Har destination IP ke liye ek sliding time-window maintain karta hai.
    Window ke andar: kitne packets aaye, aur kitni ALAG source IPs se aaye.
    """
    # Har destination ke liye: list of (timestamp, src_ip)
    dst_activity = defaultdict(list)
    alerts = []
    already_alerted = set()

    sorted_flows = sorted(flows, key=lambda x: x["timestamp"])

    for flow in sorted_flows:
        dst = flow["dst_ip"]
        src = flow["src_ip"]
        ts = datetime.fromisoformat(flow["timestamp"])

        dst_activity[dst].append((ts, src))

        # window ke bahar ki purani entries hata do
        cutoff = ts.timestamp() - TIME_WINDOW_SECONDS
        dst_activity[dst] = [(t, s) for (t, s) in dst_activity[dst] if t.timestamp() >= cutoff]

        packet_count = len(dst_activity[dst])
        source_ips = [s for (t, s) in dst_activity[dst]]
        unique_sources = len(set(source_ips))

        if packet_count >= PACKET_RATE_THRESHOLD and dst not in already_alerted:
            entropy = calculate_entropy(source_ips)
            is_spoofed = unique_sources >= MIN_UNIQUE_IPS_FOR_SPOOFING

            # confidence: rate aur entropy dono se milke banti hai
            rate_factor = min(packet_count / PACKET_RATE_THRESHOLD, 3.0) / 3.0
            entropy_factor = min(entropy / 5.0, 1.0)  # entropy ~5 ke aas-paas high maana
            confidence = round(min(0.4 + 0.35 * rate_factor + 0.25 * entropy_factor, 0.99), 2)

            alert = {
                "timestamp": flow["timestamp"],
                "flow_id": flow["flow_id"],
                "threat_class": "DDoS",
                "confidence_score": confidence,
                "evidence": f"{packet_count} packets to {dst} within {TIME_WINDOW_SECONDS}s "
                             f"from {unique_sources} unique source IPs "
                             f"(entropy={entropy:.2f}, spoofing_likely={is_spoofed})",
                "target_ip": dst
            }
            alerts.append(alert)
            already_alerted.add(dst)

    return alerts


if __name__ == "__main__":
    print("[*] Loading simulated traffic...")
    flows = load_flows()
    print(f"[*] Loaded {len(flows)} flow records")

    print("[*] Running DDoS detection...\n")
    alerts = detect_ddos(flows)

    if alerts:
        print(f"[!] {len(alerts)} DDoS ALERT(S) DETECTED:\n")
        for a in alerts:
            print(json.dumps(a, indent=2))
            print()
    else:
        print("[✓] No DDoS attacks detected.")

    with open("ddos_alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[✓] Alerts saved to 'ddos_alerts.json'")
