"""
Main data generator orchestrator.
Produces benign_only.jsonl, mixed.jsonl, and ground_truth.json.
Fixed random seed for reproducibility.
"""
import json
import random
from datetime import datetime
from pathlib import Path

from app.config import settings
from app.simulation.entities import generate_entities
from app.simulation.benign import generate_benign_events
from app.simulation.attacks import (
    inject_insider_data_theft,
    inject_external_compromise,
    inject_slow_credential_abuse,
    inject_service_account_compromise,
)
from app.simulation.hard_negatives import inject_hard_negatives


def generate_all_datasets(output_dir: Path = None):
    """
    Generate all synthetic datasets:
    - benign_only.jsonl: Clean logs, must yield ZERO incidents
    - mixed.jsonl: Benign + attacks + hard negatives, interleaved
    - ground_truth.json: Labels for evaluation

    Returns paths to generated files.
    """
    if output_dir is None:
        output_dir = settings.GENERATED_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(settings.RANDOM_SEED)
    start_date = datetime(2025, 1, 1, 0, 0, 0)

    print("[*] Generating corporate environment entities...")
    entities = generate_entities(rng, settings.NUM_USERS, settings.NUM_HOSTS)
    print(f"    Users: {len(entities['users'])}, Hosts: {len(entities['hosts'])}")

    # --- Benign events ---
    print("[*] Generating benign baseline events...")
    benign_events = generate_benign_events(rng, entities, start_date, settings.NUM_DAYS)
    print(f"    Benign events: {len(benign_events)}")

    # --- Write benign_only.jsonl ---
    benign_only_path = output_dir / "benign_only.jsonl"
    with open(benign_only_path, "w") as f:
        for event in benign_events:
            f.write(json.dumps(event) + "\n")
    print(f"[+] Written {benign_only_path} ({len(benign_events)} events)")

    # --- Generate attacks ---
    print("[*] Generating attack scenarios...")
    all_attack_events = []
    ground_truths = []

    # Attack 1: Insider data theft
    atk_events, gt = inject_insider_data_theft(rng, entities, start_date, day_offset=12)
    all_attack_events.extend(atk_events)
    ground_truths.append(gt)
    print(f"    Attack 1 (Insider theft): {len(atk_events)} events")

    # Attack 2: External compromise
    atk_events, gt = inject_external_compromise(rng, entities, start_date, day_offset=15)
    all_attack_events.extend(atk_events)
    ground_truths.append(gt)
    print(f"    Attack 2 (External compromise): {len(atk_events)} events")

    # Attack 3: Slow credential abuse
    atk_events, gt = inject_slow_credential_abuse(rng, entities, start_date, day_offset=5)
    all_attack_events.extend(atk_events)
    ground_truths.append(gt)
    print(f"    Attack 3 (Slow credential abuse): {len(atk_events)} events")

    # Attack 4: Service account compromise
    atk_events, gt = inject_service_account_compromise(rng, entities, start_date, day_offset=20)
    all_attack_events.extend(atk_events)
    ground_truths.append(gt)
    print(f"    Attack 4 (Service account compromise): {len(atk_events)} events")

    # --- Hard negatives ---
    print("[*] Generating hard negative scenarios...")
    hard_neg_events = inject_hard_negatives(rng, entities, start_date)
    print(f"    Hard negatives: {len(hard_neg_events)} events")

    # --- Mix everything together and sort by timestamp ---
    mixed_events = benign_events + all_attack_events + hard_neg_events
    mixed_events.sort(key=lambda e: e["timestamp"])

    # --- Write mixed.jsonl ---
    mixed_path = output_dir / "mixed.jsonl"
    with open(mixed_path, "w") as f:
        for event in mixed_events:
            f.write(json.dumps(event) + "\n")
    print(f"[+] Written {mixed_path} ({len(mixed_events)} events)")

    # --- Write ground_truth.json ---
    gt_path = output_dir / "ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump({
            "generated_at": datetime.utcnow().isoformat(),
            "seed": settings.RANDOM_SEED,
            "num_users": len(entities["users"]),
            "num_hosts": len(entities["hosts"]),
            "num_days": settings.NUM_DAYS,
            "benign_event_count": len(benign_events),
            "attack_event_count": len(all_attack_events),
            "hard_negative_count": len(hard_neg_events),
            "total_mixed_count": len(mixed_events),
            "attacks": ground_truths,
        }, f, indent=2, default=str)
    print(f"[+] Written {gt_path}")

    # --- Save entities for reference ---
    entities_path = output_dir / "entities.json"
    with open(entities_path, "w") as f:
        serializable = {
            "users": [{"username": u.username, "department": u.department, "role": u.role,
                        "is_admin": u.is_admin, "is_service_account": u.is_service_account,
                        "typical_hosts": u.typical_hosts, "typical_geo": u.typical_geo}
                       for u in entities["users"]],
            "hosts": [{"hostname": h.hostname, "host_type": h.host_type, "ip": h.ip}
                       for h in entities["hosts"]],
        }
        json.dump(serializable, f, indent=2)

    print(f"\n[✓] Data generation complete!")
    print(f"    Benign only: {len(benign_events)} events")
    print(f"    Mixed: {len(mixed_events)} events")
    print(f"    Attacks: {len(ground_truths)} scenarios, {len(all_attack_events)} events")
    print(f"    Hard negatives: {len(hard_neg_events)} events")

    return {
        "benign_only": str(benign_only_path),
        "mixed": str(mixed_path),
        "ground_truth": str(gt_path),
        "entities": str(entities_path),
    }


if __name__ == "__main__":
    generate_all_datasets()
