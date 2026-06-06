#!/usr/bin/env python3
"""
PharmChain — Synthetic Dataset Generator
dataset_generator.py

Generates 50,000 synthetic pharmaceutical transactions for experimental evaluation.
Random seed = 42 (fixed for reproducibility — manuscript Section 5.1)

Output files:
  - transactions.csv       : Full 50,000 transaction dataset
  - counterfeit_cases.csv  : 7,500 injected counterfeit transactions (15%)
  - legitimate_cases.csv   : 42,500 legitimate transactions (85%)
  - cold_chain_logs.csv    : IoT sensor readings for all transactions
  - summary_stats.csv      : Dataset summary statistics

Usage:
  python dataset_generator.py
  python dataset_generator.py --output ./results --seed 42 --n 50000

Manuscript Reference: Section 5.1 (Experimental Setup)
"""

import csv
import hashlib
import json
import os
import random
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Tuple

# ─────────────────────────────────────────────
# Configuration — matches manuscript Table 4
# ─────────────────────────────────────────────
RANDOM_SEED = 42
TOTAL_TRANSACTIONS = 50_000
COUNTERFEIT_RATE = 0.15          # 15% counterfeit injection rate
COUNTERFEIT_COUNT = int(TOTAL_TRANSACTIONS * COUNTERFEIT_RATE)  # 7,500
LEGITIMATE_COUNT = TOTAL_TRANSACTIONS - COUNTERFEIT_COUNT        # 42,500

# Supply chain participants (6 organizations — Section 5.2)
ORGANIZATIONS = {
    "MANUFACTURER":    {"tier": 2, "id": "ORG001", "location": "Chennai, India"},
    "DISTRIBUTOR1":    {"tier": 2, "id": "ORG002", "location": "Mumbai, India"},
    "DISTRIBUTOR2":    {"tier": 2, "id": "ORG003", "location": "Delhi, India"},
    "WHOLESALER":      {"tier": 2, "id": "ORG004", "location": "Bangalore, India"},
    "PHARMACY":        {"tier": 3, "id": "ORG005", "location": "Hyderabad, India"},
    "ROOT_AUTHORITY":  {"tier": 1, "id": "ORG006", "location": "New Delhi, India"},
}

# Custody transfer chain
SUPPLY_CHAIN_PATH = [
    "MANUFACTURER", "DISTRIBUTOR1", "DISTRIBUTOR2", "WHOLESALER", "PHARMACY"
]

# Drug types with cold-chain thresholds
DRUG_TYPES = [
    {"name": "Insulin",         "ingredient": "insulin glargine",   "temp_min": 2.0,  "temp_max": 8.0,  "humidity_max": 75},
    {"name": "Vaccines",        "ingredient": "live attenuated",     "temp_min": 2.0,  "temp_max": 8.0,  "humidity_max": 60},
    {"name": "Antibiotics",     "ingredient": "amoxicillin",         "temp_min": 15.0, "temp_max": 25.0, "humidity_max": 70},
    {"name": "Antiretrovirals", "ingredient": "tenofovir",           "temp_min": 15.0, "temp_max": 30.0, "humidity_max": 65},
    {"name": "Biologics",       "ingredient": "monoclonal antibody", "temp_min": 2.0,  "temp_max": 8.0,  "humidity_max": 55},
]

# Counterfeit attack types (Section 5.8)
ATTACK_TYPES = [
    "QR_HASH_MISMATCH",       # Physical-digital linkage failure
    "GEOGRAPHIC_IMPOSSIBILITY", # Location jump attack
    "COLD_CHAIN_BREACH",      # Temperature tampering
    "EXPIRED_DRUG",           # Post-expiry distribution
    "DUPLICATE_DRUG_ID",      # Double-spend attack
    "UNAUTHORIZED_TRANSFER",  # Insider attack
    "REPLAY_ATTACK",          # Replay of old transaction
]


def generate_drug_id(index: int, rng: random.Random) -> str:
    """Generate a unique drug ID with batch prefix."""
    batch = rng.randint(1000, 9999)
    return f"DRUG-{batch:04d}-{index:06d}"


def generate_qr_hash(drug_id: str, nonce: str) -> str:
    """Compute SHA256 QR hash — matches DrugRegistration chaincode."""
    return hashlib.sha256(f"{drug_id}{nonce}".encode()).hexdigest()


def generate_iot_payload(
    drug: Dict,
    is_breach: bool,
    rng: random.Random,
    timestamp: datetime
) -> Dict:
    """Generate IoT cold-chain sensor payload."""
    if is_breach:
        # Temperature breach — outside acceptable range
        temp = rng.uniform(drug["temp_max"] + 2.0, drug["temp_max"] + 15.0)
        humidity = rng.uniform(drug["humidity_max"] + 5, 95.0)
    else:
        # Normal reading — within acceptable range
        temp = rng.uniform(drug["temp_min"], drug["temp_max"])
        humidity = rng.uniform(30.0, drug["humidity_max"])

    return {
        "temperature": round(temp, 2),
        "humidity": round(humidity, 2),
        "gps": f"{rng.uniform(8.0, 37.0):.4f},{rng.uniform(68.0, 97.0):.4f}",
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensor_id": f"SENSOR-{rng.randint(100, 999)}",
    }


def generate_legitimate_transaction(
    index: int,
    rng: random.Random,
    base_date: datetime
) -> Dict:
    """Generate a single legitimate pharmaceutical transaction."""
    drug = rng.choice(DRUG_TYPES)
    drug_id = generate_drug_id(index, rng)
    nonce = hashlib.md5(f"{drug_id}{index}".encode()).hexdigest()
    qr_hash = generate_qr_hash(drug_id, nonce)

    # Random point in supply chain
    chain_step = rng.randint(0, len(SUPPLY_CHAIN_PATH) - 2)
    sender = SUPPLY_CHAIN_PATH[chain_step]
    receiver = SUPPLY_CHAIN_PATH[chain_step + 1]

    timestamp = base_date + timedelta(
        days=rng.randint(0, 365),
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59)
    )

    iot = generate_iot_payload(drug, is_breach=False, rng=rng, timestamp=timestamp)
    expiry = (timestamp + timedelta(days=rng.randint(180, 730))).strftime("%Y-%m-%d")

    return {
        "transaction_id": f"TX-{index:06d}",
        "drug_id": drug_id,
        "drug_name": drug["name"],
        "active_ingredient": drug["ingredient"],
        "sender_id": ORGANIZATIONS[sender]["id"],
        "sender_org": sender,
        "receiver_id": ORGANIZATIONS[receiver]["id"],
        "receiver_org": receiver,
        "qr_hash": qr_hash,
        "qr_nonce": nonce,
        "expiry_date": expiry,
        "temperature": iot["temperature"],
        "humidity": iot["humidity"],
        "gps": iot["gps"],
        "sensor_id": iot["sensor_id"],
        "timestamp": iot["timestamp"],
        "compliance_status": "COMPLIANT",
        "is_counterfeit": False,
        "attack_type": "NONE",
        "payload_size_bytes": 512,
    }


def inject_counterfeit(transaction: Dict, attack_type: str, rng: random.Random) -> Dict:
    """Inject a counterfeit attack into a legitimate transaction."""
    tx = transaction.copy()
    tx["is_counterfeit"] = True
    tx["attack_type"] = attack_type
    tx["compliance_status"] = "SUSPECTED_COUNTERFEIT"

    if attack_type == "QR_HASH_MISMATCH":
        # Tamper the QR hash
        tx["qr_hash"] = hashlib.sha256(f"FAKE_{tx['drug_id']}".encode()).hexdigest()

    elif attack_type == "GEOGRAPHIC_IMPOSSIBILITY":
        # Location jump — teleport drug across impossible distance
        tx["gps"] = f"{rng.uniform(-90, 90):.4f},{rng.uniform(-180, 180):.4f}"

    elif attack_type == "COLD_CHAIN_BREACH":
        # Temperature outside acceptable range
        tx["temperature"] = round(rng.uniform(15.0, 40.0), 2)
        tx["humidity"] = round(rng.uniform(80.0, 99.0), 2)
        tx["compliance_status"] = "COLD_CHAIN_BREACH"

    elif attack_type == "EXPIRED_DRUG":
        # Set expiry in the past
        past_date = datetime(2020, 1, 1) + timedelta(days=rng.randint(0, 365))
        tx["expiry_date"] = past_date.strftime("%Y-%m-%d")
        tx["compliance_status"] = "EXPIRED"

    elif attack_type == "DUPLICATE_DRUG_ID":
        # Reuse existing drug ID (double-spend)
        tx["drug_id"] = f"DRUG-{rng.randint(1000, 1010):04d}-000001"

    elif attack_type == "UNAUTHORIZED_TRANSFER":
        # Skip supply chain step (insider attack)
        tx["sender_org"] = "MANUFACTURER"
        tx["sender_id"] = ORGANIZATIONS["MANUFACTURER"]["id"]
        tx["receiver_org"] = "PHARMACY"
        tx["receiver_id"] = ORGANIZATIONS["PHARMACY"]["id"]

    elif attack_type == "REPLAY_ATTACK":
        # Reuse old timestamp
        tx["timestamp"] = "2020-01-01T00:00:00Z"

    return tx


def generate_dataset(
    n: int = TOTAL_TRANSACTIONS,
    seed: int = RANDOM_SEED,
    output_dir: str = "."
) -> None:
    """Generate full dataset and write CSV files."""

    rng = random.Random(seed)
    base_date = datetime(2024, 1, 1)

    print(f"PharmChain Dataset Generator")
    print(f"Seed: {seed} | Total transactions: {n:,} | Counterfeit rate: {COUNTERFEIT_RATE*100:.0f}%")
    print(f"Legitimate: {int(n*(1-COUNTERFEIT_RATE)):,} | Counterfeit: {int(n*COUNTERFEIT_RATE):,}")
    print("-" * 60)

    transactions = []
    counterfeit_indices = set(rng.sample(range(n), int(n * COUNTERFEIT_RATE)))

    for i in range(n):
        tx = generate_legitimate_transaction(i, rng, base_date)

        if i in counterfeit_indices:
            attack = rng.choice(ATTACK_TYPES)
            tx = inject_counterfeit(tx, attack, rng)

        transactions.append(tx)

        if (i + 1) % 10000 == 0:
            print(f"  Generated {i+1:,} / {n:,} transactions...")

    # Write full transaction dataset
    fieldnames = list(transactions[0].keys())
    _write_csv(os.path.join(output_dir, "transactions.csv"), transactions, fieldnames)
    print(f"\n✅ transactions.csv — {len(transactions):,} rows")

    # Write counterfeit subset
    counterfeit = [tx for tx in transactions if tx["is_counterfeit"]]
    _write_csv(os.path.join(output_dir, "counterfeit_cases.csv"), counterfeit, fieldnames)
    print(f"✅ counterfeit_cases.csv — {len(counterfeit):,} rows")

    # Write legitimate subset
    legitimate = [tx for tx in transactions if not tx["is_counterfeit"]]
    _write_csv(os.path.join(output_dir, "legitimate_cases.csv"), legitimate, fieldnames)
    print(f"✅ legitimate_cases.csv — {len(legitimate):,} rows")

    # Write summary stats
    attack_counts = {}
    for tx in counterfeit:
        attack_counts[tx["attack_type"]] = attack_counts.get(tx["attack_type"], 0) + 1

    summary = [
        {"metric": "total_transactions", "value": n},
        {"metric": "legitimate_count", "value": len(legitimate)},
        {"metric": "counterfeit_count", "value": len(counterfeit)},
        {"metric": "counterfeit_rate", "value": f"{len(counterfeit)/n*100:.2f}%"},
        {"metric": "random_seed", "value": seed},
    ]
    for attack, count in sorted(attack_counts.items()):
        summary.append({"metric": f"attack_{attack.lower()}", "value": count})

    _write_csv(os.path.join(output_dir, "summary_stats.csv"), summary, ["metric", "value"])
    print(f"✅ summary_stats.csv — dataset statistics")
    print("\nDataset generation complete.")


def _write_csv(filepath: str, rows: List[Dict], fieldnames: List[str]) -> None:
    """Write rows to CSV file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PharmChain Synthetic Dataset Generator")
    parser.add_argument("--output", type=str, default=".", help="Output directory")
    parser.add_argument("--seed",   type=int, default=RANDOM_SEED, help="Random seed")
    parser.add_argument("--n",      type=int, default=TOTAL_TRANSACTIONS, help="Number of transactions")
    args = parser.parse_args()

    generate_dataset(n=args.n, seed=args.seed, output_dir=args.output)
    