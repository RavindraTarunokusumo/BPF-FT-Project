#!/usr/bin/env python3
"""
Updates gold_candidate_id in task.json for every task in batch-001 based on final validation results.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = PROJECT_ROOT / "data" / "inbox" / "batch-001"
VAL_DIR = PROJECT_ROOT / "data" / "validation" / "batch-001"

GOLD_MAP = {
    "xdp_b01_t01_drop_tcp_port": "xdp_b01_t01_drop_tcp_port_c00_r01",
    "xdp_b01_t02_drop_udp_port": "xdp_b01_t02_drop_udp_port_c00_r02",
    "xdp_b01_t03_drop_icmp": "xdp_b01_t03_drop_icmp_c00_r01",
    "xdp_b01_t04_drop_syn_fin": "xdp_b01_t04_drop_syn_fin_c00_r01",
    "xdp_b01_t05_drop_oversized": "xdp_b01_t05_drop_oversized_c00",
    "xdp_b01_t06_vlan_drop_http": "xdp_b01_t06_vlan_drop_http_c00_r02",
    "xdp_b01_t07_src_ip_denylist_map": "xdp_b01_t07_src_ip_denylist_map_c00_r01",
    "xdp_b01_t08_count_packets_map": "xdp_b01_t08_count_packets_map_c00_r01",
    "xdp_b01_t09_drop_udp_dns_amplification": "xdp_b01_t09_drop_udp_dns_amplification_c00_r02",
    "xdp_b01_t10_allow_only_ssh": "xdp_b01_t10_allow_only_ssh_c00_r01",
}


def main() -> None:
    for task_id, gold_id in GOLD_MAP.items():
        task_json_file = BATCH_DIR / task_id / "task.json"
        if task_json_file.exists():
            data = json.loads(task_json_file.read_text(encoding="utf-8"))
            data["gold_candidate_id"] = gold_id
            task_json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[+] Set {task_id} -> gold_candidate_id: {gold_id}")

    print("Gold candidate IDs updated successfully.")


if __name__ == "__main__":
    main()
