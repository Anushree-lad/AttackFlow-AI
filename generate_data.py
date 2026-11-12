"""
generate_data.py
-----------------
Creates a synthetic network-event dataset for AttackFlow AI to run against.

Why synthetic data for the prototype:
  Public IDS datasets (CICIDS2017, UNSW-NB15, NSL-KDD) label individual
  flows, not multi-step attack CAMPAIGNS -- which is exactly the thing
  AttackFlow AI is trying to reconstruct. So for a first prototype we
  simulate normal background traffic plus a handful of injected multi-stage
  campaigns (recon -> exploit -> lateral movement -> exfiltration) with
  known ground truth. This lets us validate the correlation/reconstruction
  logic against a known answer before ever touching real traffic.

Swap this file out for a real data loader once you have actual traffic/logs
-- everything downstream just expects a CSV with these columns.
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)

OUT_PATH = "data/events.csv"
N_NORMAL_EVENTS = 4000
N_CAMPAIGNS = 4
START_TIME = datetime(2026, 9, 1, 0, 0, 0)


def random_ip(internal=False):
    if internal:
        return f"10.0.{random.randint(0, 20)}.{random.randint(2, 254)}"
    return f"{random.randint(20, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def normal_event(t):
    return {
        "timestamp": t.isoformat(),
        "src_ip": random_ip(internal=True),
        "dst_ip": random_ip(internal=random.random() < 0.5),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 443, 443, 53, 22, 3389, 8080]),
        "protocol": random.choice(["TCP", "TCP", "UDP", "TCP"]),
        "bytes_sent": int(random.gauss(4000, 2000)).__abs__(),
        "bytes_received": int(random.gauss(8000, 4000)).__abs__(),
        "duration_ms": int(random.gauss(300, 150)).__abs__(),
        "failed_logins": 0,
        "true_label": "benign",
        "true_campaign": "",
    }


def make_campaign(campaign_id, start_time, attacker_ip, victim_ip):
    """
    Simulates one multi-stage attack campaign against a single internal
    victim host, spread out over a realistic time window. Each stage has
    feature signatures loosely modeled on real attacker behavior so the
    anomaly detector has something genuine to latch onto.
    """
    events = []
    t = start_time

    # Stage 1: Reconnaissance -- port scan, many dst ports, tiny payloads
    for _ in range(random.randint(15, 25)):
        events.append({
            "timestamp": t.isoformat(),
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.randint(1, 1024),
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(0, 60),
            "duration_ms": random.randint(1, 20),
            "failed_logins": 0,
            "true_label": "malicious",
            "true_campaign": campaign_id,
        })
        t += timedelta(seconds=random.uniform(0.5, 3))

    t += timedelta(minutes=random.uniform(5, 15))

    # Stage 2: Initial access / brute force -- repeated failed logins, then one success
    for _ in range(random.randint(8, 14)):
        events.append({
            "timestamp": t.isoformat(),
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": 22,
            "protocol": "TCP",
            "bytes_sent": random.randint(200, 400),
            "bytes_received": random.randint(100, 200),
            "duration_ms": random.randint(50, 150),
            "failed_logins": 1,
            "true_label": "malicious",
            "true_campaign": campaign_id,
        })
        t += timedelta(seconds=random.uniform(1, 4))

    t += timedelta(minutes=random.uniform(2, 8))

    # Stage 3: Lateral movement -- internal-to-internal, unusual admin ports
    for _ in range(random.randint(5, 10)):
        events.append({
            "timestamp": t.isoformat(),
            "src_ip": victim_ip,
            "dst_ip": random_ip(internal=True),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([445, 3389, 5985]),
            "protocol": "TCP",
            "bytes_sent": random.randint(1000, 5000),
            "bytes_received": random.randint(500, 2000),
            "duration_ms": random.randint(200, 800),
            "failed_logins": 0,
            "true_label": "malicious",
            "true_campaign": campaign_id,
        })
        t += timedelta(seconds=random.uniform(5, 20))

    t += timedelta(minutes=random.uniform(3, 10))

    # Stage 4: Exfiltration -- large outbound transfer to an external IP
    external_dst = random_ip(internal=False)
    for _ in range(random.randint(3, 6)):
        events.append({
            "timestamp": t.isoformat(),
            "src_ip": victim_ip,
            "dst_ip": external_dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(500000, 3000000),
            "bytes_received": random.randint(1000, 5000),
            "duration_ms": random.randint(3000, 9000),
            "failed_logins": 0,
            "true_label": "malicious",
            "true_campaign": campaign_id,
        })
        t += timedelta(seconds=random.uniform(10, 40))

    return events, t


def main():
    rows = []
    t = START_TIME
    for _ in range(N_NORMAL_EVENTS):
        t += timedelta(seconds=random.uniform(1, 8))
        rows.append(normal_event(t))

    campaign_span = (rows[-1]["timestamp"], )
    total_minutes = N_NORMAL_EVENTS * 4 / 60  # rough total duration span

    for i in range(N_CAMPAIGNS):
        campaign_start = START_TIME + timedelta(minutes=random.uniform(20, total_minutes - 30))
        attacker_ip = random_ip(internal=False)
        victim_ip = random_ip(internal=True)
        campaign_events, _ = make_campaign(f"campaign_{i+1}", campaign_start, attacker_ip, victim_ip)
        rows.extend(campaign_events)

    rows.sort(key=lambda r: r["timestamp"])

    fieldnames = list(rows[0].keys())
    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    n_malicious = sum(1 for r in rows if r["true_label"] == "malicious")
    print(f"Generated {len(rows)} events -> {OUT_PATH}")
    print(f"  benign:    {len(rows) - n_malicious}")
    print(f"  malicious: {n_malicious} (across {N_CAMPAIGNS} campaigns)")


if __name__ == "__main__":
    main()
