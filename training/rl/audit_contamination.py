"""
BPF-Guardian RLVR Phase 2: Semantic Contamination Audit
Audits RL task datasets against protected benchmarks (calibration, synthesis, repair),
prior development splits (RL v1 dev), and between splits within RL v2.

Fingerprints verified:
1. Normalized task instruction (exact hash + token Jaccard similarity)
2. Normalized requirements (exact hash + normalized token set Jaccard similarity)
3. Protocol and feature tuple (L2/L3/L4 protocols, map types, actions, features)
4. Task-family identifier
5. Fixture schema fingerprint (counts, test types, payload shapes, actions)
6. Public prompt fingerprint (exact hash of rendered model input prompt)
7. Complete task manifest fingerprint (exact hash of canonical task JSON)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("bpf_guardian_rl.contamination")

# Allowlisted generic terms and phrases that appear across all BPF tasks
# without indicating task-specific semantic overlap
STOPWORDS = {
    "a", "an", "the", "and", "or", "of", "to", "in", "for", "with", "on", "at",
    "by", "from", "up", "about", "into", "over", "after", "all", "other", "any",
    "write", "an", "xdp", "ebpf", "bpf", "program", "c", "source", "code",
    "complete", "self", "contained", "linux", "kernel", "using", "must", "should",
    "will", "be", "is", "are", "that", "which", "this", "these", "packets",
    "packet", "traffic", "incoming", "outgoing", "return", "returns",
}

GENERIC_REQUIREMENT_PATTERNS = [
    r"\bgpl\s+license\b",
    r"\bsec\s*\(\s*[\"']xdp[\"']\s*\)",
    r"\breturn\s+xdp_pass\b",
    r"\breturn\s+xdp_drop\b",
    r"\breturn\s+xdp_tx\b",
    r"\bcomplete\s+c\s+source\s+code\b",
    r"\bverifier-safe\b",
    r"\bcompilation-ready\b",
    r"\bself-contained\b",
    r"\bentry\s+point\b",
]



SYNONYMS = {
    "dest": "destination",
    "dst": "destination",
    "src": "source",
    "req": "request",
    "resp": "response",
    "len": "length",
    "pkt": "packet",
    "pkts": "packet",
    "drops": "drop",
    "dropping": "drop",
    "dropped": "drop",
    "passes": "pass",
    "passing": "pass",
    "passed": "pass",
    "inspects": "inspect",
    "inspecting": "inspect",
}


def normalize_text(text: str) -> str:
    """Lowercases, strips punctuation, normalizes common abbreviations and collapses whitespace."""
    t = text.lower()
    t = re.sub(r"[^\w\s]", " ", t)
    words = [SYNONYMS.get(w, w) for w in t.split()]
    return " ".join(words).strip()


def extract_semantic_tokens(text: str) -> Set[str]:
    """Extracts non-stopword tokens from normalized text."""
    norm = normalize_text(text)
    tokens = {w for w in norm.split() if len(w) > 1 and w not in STOPWORDS}
    return tokens


def normalize_requirements(reqs: List[str]) -> List[str]:
    """Cleans and standardizes a list of requirement statements, removing boilerplate."""
    cleaned = []
    for r in reqs:
        c = r
        # Strip generic requirement patterns first (before stripping punctuation)
        for pat in GENERIC_REQUIREMENT_PATTERNS:
            c = re.sub(pat, " ", c, flags=re.IGNORECASE)
        norm = normalize_text(c)
        tokens = [w for w in norm.split() if w not in STOPWORDS and len(w) > 1]
        if tokens:
            cleaned.append(" ".join(tokens))
    return sorted(cleaned)


def extract_protocol_feature_tuple(task: Dict[str, Any]) -> Tuple[str, ...]:
    """Extracts high-level protocol and feature descriptors from task specification."""
    text = (
        task.get("instruction", "")
        + " "
        + " ".join(task.get("requirements", []))
        + " "
        + task.get("semantic_signature", "")
    ).lower()

    features = []
    # L2
    if "qinq" in text or "802.1ad" in text:
        features.append("proto:qinq")
    elif "vlan" in text or "802.1q" in text:
        features.append("proto:vlan")
    if "arp" in text:
        features.append("proto:arp")
    if "ethernet" in text or "eth" in text:
        features.append("proto:eth")

    # L3
    if "ipv6" in text:
        features.append("proto:ipv6")
    if "ipv4" in text or "ip" in text:
        features.append("proto:ipv4")
    if "icmp" in text:
        features.append("proto:icmp")

    # L4
    if "tcp" in text:
        features.append("proto:tcp")
    if "udp" in text:
        features.append("proto:udp")

    # Maps
    if "lpm_trie" in text or "lpm" in text:
        features.append("map:lpm_trie")
    if "lru_hash" in text:
        features.append("map:lru_hash")
    elif "hash" in text and "map" in text:
        features.append("map:hash")
    if "array" in text and "map" in text:
        features.append("map:array")
    if "devmap" in text:
        features.append("map:devmap")
    if "cpumap" in text:
        features.append("map:cpumap")

    # Operations
    if "csum" in text or "checksum" in text:
        features.append("op:csum")
    if "encap" in text:
        features.append("op:encap")
    if "decap" in text:
        features.append("op:decap")
    if "token_bucket" in text or "rate_limit" in text:
        features.append("op:rate_limit")

    return tuple(sorted(features))


def compute_task_fingerprints(task: Dict[str, Any]) -> Dict[str, Any]:
    """Computes stable multi-dimensional fingerprints for a single task."""
    task_id = task.get("task_id", "")
    instruction = task.get("instruction", "")
    reqs = task.get("requirements", [])
    task_family = task.get("task_family", "")
    tests = task.get("tests") or task.get("test_fixtures", [])

    # 1. Instruction fingerprint and semantic tokens
    norm_inst = normalize_text(instruction)
    inst_hash = hashlib.sha256(norm_inst.encode("utf-8")).hexdigest()
    inst_tokens = sorted(list(extract_semantic_tokens(instruction)))

    # 2. Requirements fingerprint and normalized tokens
    norm_reqs = normalize_requirements(reqs)
    reqs_str = "\n".join(norm_reqs)
    reqs_hash = hashlib.sha256(reqs_str.encode("utf-8")).hexdigest()
    reqs_tokens = sorted(list(extract_semantic_tokens(reqs_str)))

    # 3. Protocol and feature tuple
    proto_tuple = extract_protocol_feature_tuple(task)

    # 4. Fixture schema fingerprint
    fixture_summary = []
    for t in tests:
        act = t.get("expected_action", "")
        pkt_len = len(t.get("packet_hex", "")) // 2 if "packet_hex" in t else 0
        w = float(t.get("weight", 1.0))
        fixture_summary.append(f"{act}:{pkt_len}:{w}")
    fixture_schema_str = ",".join(sorted(fixture_summary))
    fixture_schema_hash = hashlib.sha256(fixture_schema_str.encode("utf-8")).hexdigest()

    # 5. Public prompt fingerprint
    prompt_str = f"Task ID: {task_id}\nInstruction: {instruction}\nRequirements:\n" + "\n".join(reqs)
    prompt_hash = hashlib.sha256(normalize_text(prompt_str).encode("utf-8")).hexdigest()

    # 6. Canonical task manifest hash
    core_manifest = {
        "task_id": task_id,
        "category": task.get("application_category", ""),
        "difficulty": task.get("difficulty", ""),
        "instruction": instruction,
        "requirements": reqs,
        "expected_fixture_count": task.get("expected_fixture_count", len(tests)),
    }
    manifest_hash = hashlib.sha256(
        json.dumps(core_manifest, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return {
        "task_id": task_id,
        "task_family": task_family,
        "instruction_hash": inst_hash,
        "instruction_tokens": inst_tokens,
        "requirements_hash": reqs_hash,
        "requirements_tokens": reqs_tokens,
        "protocol_features": list(proto_tuple),
        "fixture_schema_hash": fixture_schema_hash,
        "prompt_hash": prompt_hash,
        "manifest_hash": manifest_hash,
    }


def compute_jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Computes Jaccard similarity |A & B| / |A | B|."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


class ContaminationViolation:
    def __init__(
        self,
        task_id_a: str,
        split_a: str,
        task_id_b: str,
        split_b: str,
        violation_type: str,
        similarity_score: float,
        detail: str,
    ):
        self.task_id_a = task_id_a
        self.split_a = split_a
        self.task_id_b = task_id_b
        self.split_b = split_b
        self.violation_type = violation_type
        self.similarity_score = round(similarity_score, 4)
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id_a": self.task_id_a,
            "split_a": self.split_a,
            "task_id_b": self.task_id_b,
            "split_b": self.split_b,
            "violation_type": self.violation_type,
            "similarity_score": self.similarity_score,
            "detail": self.detail,
        }


def check_task_pair_contamination(
    task_a: Dict[str, Any],
    fp_a: Dict[str, Any],
    split_a: str,
    task_b: Dict[str, Any],
    fp_b: Dict[str, Any],
    split_b: str,
    jaccard_instruction_threshold: float = 0.80,
    jaccard_requirements_threshold: float = 0.85,
) -> List[ContaminationViolation]:
    """Compares two tasks and flags any exact or near-duplicate semantic overlap."""
    violations: List[ContaminationViolation] = []
    id_a = fp_a["task_id"]
    id_b = fp_b["task_id"]

    # Skip comparison of identical task to itself within the same split
    if split_a == split_b and id_a == id_b:
        return violations

    # 1. Exact Task ID match across different tasks or splits
    if id_a == id_b:
        violations.append(
            ContaminationViolation(
                task_id_a=id_a,
                split_a=split_a,
                task_id_b=id_b,
                split_b=split_b,
                violation_type="exact_task_id_match",
                similarity_score=1.0,
                detail=f"Duplicate task ID '{id_a}' across {split_a} and {split_b}",
            )
        )

    # 2. Exact Manifest Hash match
    if fp_a["manifest_hash"] == fp_b["manifest_hash"]:
        violations.append(
            ContaminationViolation(
                task_id_a=id_a,
                split_a=split_a,
                task_id_b=id_b,
                split_b=split_b,
                violation_type="exact_manifest_match",
                similarity_score=1.0,
                detail="Canonical task manifests are byte-identical",
            )
        )

    # 3. Exact Instruction Hash match (prohibited everywhere)
    if fp_a["instruction_hash"] == fp_b["instruction_hash"]:
        violations.append(
            ContaminationViolation(
                task_id_a=id_a,
                split_a=split_a,
                task_id_b=id_b,
                split_b=split_b,
                violation_type="exact_instruction_match",
                similarity_score=1.0,
                detail="Normalized instruction text is identical",
            )
        )

    # Cross-split contamination checks (split_a != split_b)
    if split_a != split_b:
        # 4. Near-duplicate instruction across splits via Jaccard similarity
        if fp_a["instruction_hash"] != fp_b["instruction_hash"]:
            tokens_a = set(fp_a["instruction_tokens"])
            tokens_b = set(fp_b["instruction_tokens"])
            j_inst = compute_jaccard_similarity(tokens_a, tokens_b)
            if j_inst >= jaccard_instruction_threshold:
                violations.append(
                    ContaminationViolation(
                        task_id_a=id_a,
                        split_a=split_a,
                        task_id_b=id_b,
                        split_b=split_b,
                        violation_type="instruction_near_duplicate",
                        similarity_score=j_inst,
                        detail=f"Semantic instruction token Jaccard similarity {j_inst:.3f} exceeds threshold {jaccard_instruction_threshold}",
                    )
                )

        # 5. Exact Requirements Hash match across splits
        if fp_a["requirements_hash"] == fp_b["requirements_hash"] and fp_a["requirements_hash"] != hashlib.sha256(b"").hexdigest():
            violations.append(
                ContaminationViolation(
                    task_id_a=id_a,
                    split_a=split_a,
                    task_id_b=id_b,
                    split_b=split_b,
                    violation_type="exact_requirements_match",
                    similarity_score=1.0,
                    detail="Normalized requirements list is identical across splits",
                )
            )
        else:
            # Near-duplicate requirements across splits
            req_tokens_a = set(fp_a["requirements_tokens"])
            req_tokens_b = set(fp_b["requirements_tokens"])
            j_req = compute_jaccard_similarity(req_tokens_a, req_tokens_b)
            if j_req >= jaccard_requirements_threshold and len(req_tokens_a) >= 4 and len(req_tokens_b) >= 4:
                violations.append(
                    ContaminationViolation(
                        task_id_a=id_a,
                        split_a=split_a,
                        task_id_b=id_b,
                        split_b=split_b,
                        violation_type="requirements_near_duplicate",
                        similarity_score=j_req,
                        detail=f"Normalized requirements token Jaccard similarity {j_req:.3f} exceeds threshold {jaccard_requirements_threshold}",
                    )
                )


    # 5. Shared Task Family between Training and Protected/Dev splits
    fam_a = fp_a.get("task_family")
    fam_b = fp_b.get("task_family")
    if fam_a and fam_b and fam_a == fam_b:
        is_train_a = "train" in split_a
        is_train_b = "train" in split_b
        if is_train_a != is_train_b:
            violations.append(
                ContaminationViolation(
                    task_id_a=id_a,
                    split_a=split_a,
                    task_id_b=id_b,
                    split_b=split_b,
                    violation_type="task_family_overlap",
                    similarity_score=1.0,
                    detail=f"Shared task family '{fam_a}' between training split ({split_a if is_train_a else split_b}) and evaluation split ({split_b if is_train_a else split_a})",
                )
            )

    return violations


def load_task_dir_records(task_dir: Path, split_name: str) -> List[Tuple[Dict[str, Any], str]]:
    """Loads all task specifications from a split directory."""
    records = []
    index_file = task_dir / "index.jsonl"
    if index_file.is_file():
        for line in index_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                task_spec = json.loads(line)
                tid = task_spec["task_id"]
                cat = task_spec.get("application_category", "")
                diff = task_spec.get("difficulty", "")
                task_json = task_dir / cat / diff / tid / "task.json"
                if task_json.is_file():
                    loaded = json.loads(task_json.read_text(encoding="utf-8"))
                    task_spec.update(loaded)
                records.append((task_spec, split_name))
    else:
        for task_json in task_dir.glob("*/*/*/task.json"):
            loaded = json.loads(task_json.read_text(encoding="utf-8"))
            records.append((loaded, split_name))
    return records


def run_contamination_audit(
    rl_splits: Dict[str, Path],
    protected_splits: Dict[str, Path],
    jaccard_instruction_threshold: float = 0.80,
    jaccard_requirements_threshold: float = 0.85,
) -> Dict[str, Any]:
    """Runs a full cross-split semantic contamination audit.

    Args:
        rl_splits: Dict mapping split name ('train', 'dev', 'confirmation', 'canary') to Path
        protected_splits: Dict mapping protected split name ('protected_calibration', 'protected_synthesis', 'protected_repair', 'rl_v1_dev') to Path
        jaccard_instruction_threshold: Threshold for flagging near-duplicate instructions
        jaccard_requirements_threshold: Threshold for flagging near-duplicate requirements

    Returns:
        Audit report dict
    """
    all_tasks: List[Tuple[Dict[str, Any], str]] = []

    # Load RL splits
    for name, path in rl_splits.items():
        if path.is_dir():
            loaded = load_task_dir_records(path, name)
            all_tasks.extend(loaded)

    # Load protected splits
    for name, path in protected_splits.items():
        if path.is_dir():
            loaded = load_task_dir_records(path, name)
            all_tasks.extend(loaded)

    logger.info("Computing fingerprints for %d total tasks across all splits...", len(all_tasks))
    task_fingerprints = []
    for task, split in all_tasks:
        fp = compute_task_fingerprints(task)
        task_fingerprints.append((task, fp, split))

    violations: List[ContaminationViolation] = []
    n = len(task_fingerprints)

    for i in range(n):
        task_a, fp_a, split_a = task_fingerprints[i]
        for j in range(i + 1, n):
            task_b, fp_b, split_b = task_fingerprints[j]

            # Only check if at least one of the tasks belongs to an RL split
            is_rl_a = split_a in rl_splits
            is_rl_b = split_b in rl_splits
            if not (is_rl_a or is_rl_b):
                continue

            pair_violations = check_task_pair_contamination(
                task_a=task_a,
                fp_a=fp_a,
                split_a=split_a,
                task_b=task_b,
                fp_b=fp_b,
                split_b=split_b,
                jaccard_instruction_threshold=jaccard_instruction_threshold,
                jaccard_requirements_threshold=jaccard_requirements_threshold,
            )
            violations.extend(pair_violations)

    split_counts = {}
    for _, _, split in task_fingerprints:
        split_counts[split] = split_counts.get(split, 0) + 1

    report = {
        "audit_passed": len(violations) == 0,
        "total_tasks_audited": len(task_fingerprints),
        "task_counts_by_split": split_counts,
        "total_violations": len(violations),
        "violations": [v.to_dict() for v in violations],
        "audit_config": {
            "jaccard_instruction_threshold": jaccard_instruction_threshold,
            "jaccard_requirements_threshold": jaccard_requirements_threshold,
        },
    }

    return report


def main():
    parser = argparse.ArgumentParser(description="Audit RL v2 tasks for benchmark and cross-split contamination")
    parser.add_argument("--v2-dir", type=str, default="data/rl/v2", help="Path to data/rl/v2 directory")
    parser.add_argument("--output", type=str, default="data/rl/v2/contamination_audit.json", help="Output audit report path")
    parser.add_argument("--fail-on-overlap", action="store_true", help="Exit with code 1 if any contamination is detected")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    v2_base = Path(args.v2_dir)
    rl_splits = {
        "rl_v2_canary": v2_base / "canary",
        "rl_v2_train": v2_base / "train",
        "rl_v2_dev": v2_base / "dev",
        "rl_v2_confirmation": v2_base / "confirmation",
    }

    protected_splits = {
        "protected_calibration": Path("data/calibration"),
        "protected_synthesis": Path("data/benchmark/synthesis"),
        "protected_repair": Path("data/benchmark/repair"),
        "rl_v1_dev": Path("data/rl/v1/dev"),
    }

    report = run_contamination_audit(rl_splits, protected_splits)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Contamination audit report saved to %s", out_path)

    if not report["audit_passed"]:
        logger.error("CONTAMINATION AUDIT FAILED! Found %d violations:", report["total_violations"])
        for v in report["violations"]:
            logger.error("  - [%s] %s (%s) vs %s (%s): %s", v["violation_type"], v["task_id_a"], v["split_a"], v["task_id_b"], v["split_b"], v["detail"])
        if args.fail_on_overlap:
            sys.exit(1)
    else:
        logger.info("CONTAMINATION AUDIT PASSED! All tasks are strictly disjoint and uncontaminated.")


if __name__ == "__main__":
    main()
