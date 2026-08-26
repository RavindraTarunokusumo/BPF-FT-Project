#!/usr/bin/env python3
"""
Relocates tasks from data/inbox/batch-*/<task_id> to data/inbox/<category>/<level>/<task_id>
and validation files from data/validation/batch-*/ to data/validation/<category>/<level>/
according to the BPF-Guardian 4-category and 3-difficulty taxonomy.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
VAL_DIR = PROJECT_ROOT / "data" / "validation"

# Map task_id -> (category, level)
TASK_TAXONOMY = {
    # Batch-001
    "xdp_b01_t01_drop_tcp_port": ("packet_filtering_security", "level_1"),
    "xdp_b01_t02_drop_udp_port": ("packet_filtering_security", "level_1"),
    "xdp_b01_t03_drop_icmp": ("packet_filtering_security", "level_1"),
    "xdp_b01_t04_drop_syn_fin": ("packet_filtering_security", "level_2"),
    "xdp_b01_t05_drop_oversized": ("packet_filtering_security", "level_1"),
    "xdp_b01_t06_vlan_drop_http": ("packet_filtering_security", "level_2"),
    "xdp_b01_t07_src_ip_denylist_map": ("packet_filtering_security", "level_2"),
    "xdp_b01_t08_count_packets_map": ("packet_inspection_telemetry", "level_1"),
    "xdp_b01_t09_drop_udp_dns_amplification": ("packet_filtering_security", "level_2"),
    "xdp_b01_t10_allow_only_ssh": ("packet_filtering_security", "level_1"),

    # Batch-002 (Port filters)
    "xdp_b02_t01_drop_udp_tftp": ("packet_filtering_security", "level_1"),
    "xdp_b02_t02_drop_tcp_mysql": ("packet_filtering_security", "level_1"),
    "xdp_b02_t03_drop_tcp_redis": ("packet_filtering_security", "level_1"),
    "xdp_b02_t04_drop_udp_ntp": ("packet_filtering_security", "level_1"),
    "xdp_b02_t05_drop_udp_snmp": ("packet_filtering_security", "level_1"),
    "xdp_b02_t06_drop_tcp_smb": ("packet_filtering_security", "level_1"),
    "xdp_b02_t07_pass_web_only": ("packet_filtering_security", "level_2"),
    "xdp_b02_t08_drop_ephemeral_udp": ("packet_filtering_security", "level_2"),
    "xdp_b02_t09_drop_tcp_range_6000_6005": ("packet_filtering_security", "level_2"),
    "xdp_b02_t10_drop_udp_mdns": ("packet_filtering_security", "level_1"),

    # Batch-003 (TCP Flags & Scans)
    "xdp_b03_t01_drop_null_scan": ("packet_filtering_security", "level_2"),
    "xdp_b03_t02_drop_xmas_scan": ("packet_filtering_security", "level_2"),
    "xdp_b03_t03_drop_fin_no_ack": ("packet_filtering_security", "level_2"),
    "xdp_b03_t04_drop_syn_rst": ("packet_filtering_security", "level_2"),
    "xdp_b03_t05_drop_rst_no_ack": ("packet_filtering_security", "level_2"),
    "xdp_b03_t06_pass_syn_only_web": ("packet_filtering_security", "level_2"),
    "xdp_b03_t07_drop_all_urg": ("packet_filtering_security", "level_2"),
    "xdp_b03_t08_drop_syn_ack_unsolicited": ("packet_filtering_security", "level_2"),
    "xdp_b03_t09_drop_invalid_tcp_flags_zero_window": ("packet_filtering_security", "level_2"),
    "xdp_b03_t10_drop_psh_without_ack": ("packet_filtering_security", "level_2"),

    # Batch-004 (IP Protocols & ICMP)
    "xdp_b04_t01_drop_icmp_echo_request": ("packet_filtering_security", "level_1"),
    "xdp_b04_t02_drop_icmp_unreachable": ("packet_filtering_security", "level_1"),
    "xdp_b04_t03_drop_gre_protocol": ("packet_filtering_security", "level_1"),
    "xdp_b04_t04_drop_ipsec_esp": ("packet_filtering_security", "level_1"),
    "xdp_b04_t05_drop_ipsec_ah": ("packet_filtering_security", "level_1"),
    "xdp_b04_t06_drop_igmp": ("packet_filtering_security", "level_1"),
    "xdp_b04_t07_drop_low_ttl": ("packet_filtering_security", "level_1"),
    "xdp_b04_t08_drop_dscp_cs6": ("packet_filtering_security", "level_1"),
    "xdp_b04_t09_drop_ip_fragments": ("packet_filtering_security", "level_2"),
    "xdp_b04_t10_pass_only_tcp_udp_icmp": ("packet_filtering_security", "level_1"),

    # Batch-005 (BPF Maps)
    "xdp_b05_t01_map_src_ip_denylist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t02_map_dst_ip_denylist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t03_map_tcp_dport_denylist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t04_map_udp_dport_denylist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t05_map_ip_proto_denylist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t06_map_packet_byte_counter": ("packet_inspection_telemetry", "level_1"),
    "xdp_b05_t07_map_proto_counter_array": ("packet_inspection_telemetry", "level_2"),
    "xdp_b05_t08_map_ip_allowlist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t09_map_tcp_allowlist": ("packet_filtering_security", "level_2"),
    "xdp_b05_t10_map_drop_counter": ("packet_inspection_telemetry", "level_2"),

    # Batch-006 (VLAN & Packet Lengths)
    "xdp_b06_t01_vlan_drop_all_tagged": ("packet_filtering_security", "level_1"),
    "xdp_b06_t02_vlan_allow_specific_id": ("packet_filtering_security", "level_2"),
    "xdp_b06_t03_vlan_drop_udp_dns": ("packet_filtering_security", "level_3"),
    "xdp_b06_t04_drop_small_packets_64": ("packet_filtering_security", "level_1"),
    "xdp_b06_t05_drop_large_packets_1500": ("packet_filtering_security", "level_1"),
    "xdp_b06_t06_drop_large_udp_payload": ("packet_filtering_security", "level_2"),
    "xdp_b06_t07_drop_tiny_ip_payload": ("packet_filtering_security", "level_2"),
    "xdp_b06_t08_vlan_drop_icmp": ("packet_filtering_security", "level_3"),
    "xdp_b06_t09_drop_tcp_payload_http_post": ("packet_filtering_security", "level_3"),
    "xdp_b06_t10_double_vlan_drop_all": ("packet_filtering_security", "level_1"),
}


def main() -> None:
    print("=== Starting Relocation to New Taxonomy ===")

    # 1. Relocate inbox tasks
    for batch_dir in list(INBOX_DIR.glob("batch-*")):
        if not batch_dir.is_dir():
            continue

        for task_dir in list(batch_dir.iterdir()):
            if not task_dir.is_dir():
                continue

            task_id = task_dir.name
            if task_id not in TASK_TAXONOMY:
                print(f"[-] Unknown task_id: {task_id}")
                continue

            cat, level = TASK_TAXONOMY[task_id]
            target_dir = INBOX_DIR / cat / level / task_id
            target_dir.parent.mkdir(parents=True, exist_ok=True)

            if target_dir.exists():
                shutil.rmtree(target_dir)

            shutil.move(str(task_dir), str(target_dir))

            # Update task.json with application_category and difficulty
            task_json_file = target_dir / "task.json"
            if task_json_file.exists():
                data = json.loads(task_json_file.read_text(encoding="utf-8"))
                data["application_category"] = cat
                data["difficulty"] = level
                task_json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            print(f"[+] Moved {batch_dir.name}/{task_id} -> {cat}/{level}/{task_id}")

        # Remove empty batch directory
        shutil.rmtree(batch_dir, ignore_errors=True)

    # 2. Relocate validation records
    for val_batch_dir in list(VAL_DIR.glob("batch-*")):
        if not val_batch_dir.is_dir():
            continue

        for val_file in list(val_batch_dir.glob("*.json")):
            # Parse candidate_id and deduce task_id
            stem = val_file.stem
            # Find matching task_id in TASK_TAXONOMY
            matched_task_id = None
            for t_id in TASK_TAXONOMY:
                if stem.startswith(t_id):
                    matched_task_id = t_id
                    break

            if not matched_task_id:
                print(f"[-] Cannot match validation file: {val_file.name}")
                continue

            cat, level = TASK_TAXONOMY[matched_task_id]
            target_val_dir = VAL_DIR / cat / level
            target_val_dir.mkdir(parents=True, exist_ok=True)
            target_val_file = target_val_dir / val_file.name

            # Update validation content if needed
            val_data = json.loads(val_file.read_text(encoding="utf-8"))
            val_data["application_category"] = cat
            val_data["difficulty"] = level
            if "batch_id" in val_data:
                del val_data["batch_id"]

            if "source_path" in val_data and "/data/inbox/batch-" in val_data["source_path"]:
                val_data["source_path"] = val_data["source_path"].replace(
                    f"/data/inbox/{val_batch_dir.name}/",
                    f"/data/inbox/{cat}/{level}/"
                )

            target_val_file.write_text(json.dumps(val_data, indent=2), encoding="utf-8")
            val_file.unlink()

        shutil.rmtree(val_batch_dir, ignore_errors=True)

    print("\n[+] Relocation completed.")


if __name__ == "__main__":
    main()
