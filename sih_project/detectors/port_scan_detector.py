"""
PORT SCAN DETECTOR
====================
Logic simple hai: agar EK source IP, THODE time-window mein,
BAHUT SAARE alag-alag destination ports try karta hai — to ye scan hai.

Real-world mein normal user 1-2 ports use karta hai (jaise 443 for HTTPS).
Ek scanner 10-50+ unique ports try karta hai seconds ke andar.
"""

import json
from datetime import datetime
from collections import defaultdict

# ---- TUNABLE THRESHOLDS (inko tune kar sakte ho testing ke baad) ----
TIME_WINDOW_SECONDS = 5       # kitni der ka window dekhna hai
UNIQUE_PORT_THRESHOLD = 15    # kitne unique ports = suspicious


def load_flows(filepath="simulated_traffic.json"):
    """Traffic simulator se generate hui JSON file padhta hai."""
    with open(filepath, "r") as f:
        return json.load(f)


def detect_port_scans(flows):
    """
    Sab flows ko time-order mein process karta hai, aur har source IP ke liye
    ek 'sliding window' maintain karta hai — us window mein kitne UNIQUE ports
    contact hue, wo track karta hai.

    Jaise hi koi IP threshold cross karta hai, ek alert generate hoti hai.
    """
    # Har source IP ke liye: list of (timestamp, port) jo abhi tak dekhe
    ip_activity = defaultdict(list)
    alerts = []
    already_alerted = set()  # taaki ek hi IP ke liye baar-baar alert na bane

    # timestamp ke hisaab se sort karo (real duniya mein data waise hi order mein aata hai)
    sorted_flows = sorted(flows, key=lambda x: x["timestamp"])

    for flow in sorted_flows:
        src = flow["src_ip"]
        port = flow["dst_port"]
        ts = datetime.fromisoformat(flow["timestamp"])

        # is IP ki activity list mein add karo
        ip_activity[src].append((ts, port))

        # sirf TIME_WINDOW_SECONDS ke andar wali entries rakho, purani hata do
        cutoff = ts.timestamp() - TIME_WINDOW_SECONDS
        ip_activity[src] = [(t, p) for (t, p) in ip_activity[src] if t.timestamp() >= cutoff]

        # is window mein kitne UNIQUE ports the, check karo
        unique_ports = set(p for (t, p) in ip_activity[src])

        if len(unique_ports) >= UNIQUE_PORT_THRESHOLD and src not in already_alerted:
            # confidence score: jitne zyada ports threshold se upar, utni zyada confidence
            confidence = min(0.5 + (len(unique_ports) - UNIQUE_PORT_THRESHOLD) * 0.02, 0.99)

            alert = {
                "timestamp": flow["timestamp"],
                "flow_id": flow["flow_id"],
                "threat_class": "PORT_SCAN",
                "confidence_score": round(confidence, 2),
                "evidence": f"Source {src} contacted {len(unique_ports)} unique ports "
                             f"within {TIME_WINDOW_SECONDS} seconds (threshold: {UNIQUE_PORT_THRESHOLD})",
                "source_ip": src
            }
            alerts.append(alert)
            already_alerted.add(src)  # is IP ke liye ek hi alert kaafi hai (demo ke liye)

    return alerts


if __name__ == "__main__":
    print("[*] Loading simulated traffic...")
    flows = load_flows()
    print(f"[*] Loaded {len(flows)} flow records")

    print("[*] Running port scan detection...\n")
    alerts = detect_port_scans(flows)

    if alerts:
        print(f"[!] {len(alerts)} PORT SCAN ALERT(S) DETECTED:\n")
        for a in alerts:
            print(json.dumps(a, indent=2))
            print()
    else:
        print("[✓] No port scans detected.")

    # Alerts ko file mein save karo taaki dashboard/aggregator use kar sake
    with open("port_scan_alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[✓] Alerts saved to 'port_scan_alerts.json'")
