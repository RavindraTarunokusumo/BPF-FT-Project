"""
BPF-Guardian RLVR Phase 1: VPS Kernel Reward Executor
Executes untrusted candidate BPF C code inside the Hostinger Linux VPS kernel verification harness:
1. Structural output compliance validation
2. Clang BPF compilation
3. Linux kernel verifier loading via bpftool
4. Behavioral packet testing via BPF_PROG_TEST_RUN (bpftool prog run)
5. Strict fail-closed cleanup and audit logging
"""

from __future__ import annotations

import asyncio
import binascii
import dataclasses
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("bpf_guardian_rl.executor")

ACTION_NAME_TO_INT = {
    "XDP_ABORTED": 0,
    "XDP_DROP": 1,
    "XDP_PASS": 2,
    "XDP_TX": 3,
    "XDP_REDIRECT": 4,
}
ACTION_INT_TO_NAME = {v: k for k, v in ACTION_NAME_TO_INT.items()}


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_output_compliance(raw_text: str) -> Dict[str, Any]:
    """Validates structural compliance of the candidate output."""
    # Remove thinking tags and ChatML tokens if present
    text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|.*?\|>", "", text).strip()

    has_fences = "```" in text
    has_include = "#include" in text
    has_sec = "SEC(" in text
    has_license = "char _license[]" in text or "char LICENSE[]" in text or "LICENSE" in text
    has_xdp = "xdp" in text.lower() or "XDP_" in text
    has_fault_markers = bool(
        re.search(r"(\bFAULT:\b|\/\/\s*FAULT:|\/\*\s*FAULT:|\bTODO:\b|\bFIXME:\b)", text, re.IGNORECASE)
    )
    starts_with_code = text.startswith("#include") or text.startswith("/*") or text.startswith("//")

    compliant = (
        not has_fences
        and starts_with_code
        and has_include
        and has_sec
        and has_license
        and has_xdp
        and not has_fault_markers
    )

    return {
        "compliant": compliant,
        "has_fences": has_fences,
        "starts_with_code": starts_with_code,
        "has_include": has_include,
        "has_sec": has_sec,
        "has_license": has_license,
        "has_xdp": has_xdp,
        "has_fault_markers": has_fault_markers,
    }


def extract_c_source(raw_text: str) -> str:
    """Extracts raw C source from candidate completion."""
    text = raw_text.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|im_end\|>.*$", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|.*?\|>", "", text).strip()

    # Markdown fence extraction
    match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        return code + "\n"

    # Start from first include
    include_match = re.search(r"((?:/\*.*?\*/\s*|//.*?\n\s*)*#include\s+<.*)", text, re.DOTALL)
    if include_match:
        return include_match.group(1).strip() + "\n"

    # Start from SEC("xdp")
    sec_match = re.search(r"(SEC\s*\(\s*\"xdp\"\s*\).*)", text, re.DOTALL)
    if sec_match:
        return sec_match.group(1).strip() + "\n"

    return text + "\n"


@dataclasses.dataclass
class VerificationResult:
    rollout_id: str
    task_id: str
    source_sha256: str
    task_sha256: str
    output_compliance: Dict[str, Any]
    compile: Dict[str, Any]
    verifier: Dict[str, Any]
    behavioral: Dict[str, Any]
    cleanup_passed: bool
    infrastructure_error: bool
    error_message: Optional[str]
    timeout_stage: Optional[str]
    raw_log_path: str
    timing: Dict[str, float]
    passed: bool
    diagnostic: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class KernelExecutor:
    """Executes BPF candidate compilation, verification, and packet tests."""

    def __init__(
        self,
        records_dir: Path,
        clang_path: str = "clang",
        bpftool_path: str = "bpftool",
        include_paths: Optional[List[str]] = None,
        max_concurrency: int = 2,
    ):
        self.records_dir = records_dir
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.clang_path = clang_path
        self.bpftool_path = bpftool_path
        self.include_paths = include_paths or [
            "/usr/include/x86_64-linux-gnu",
            "/usr/include",
        ]
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def evaluate_candidate(
        self,
        task: Dict[str, Any],
        raw_completion: str,
        rollout_id: str,
    ) -> VerificationResult:
        """Evaluates a single generated candidate with strict concurrency and isolation."""
        async with self._semaphore:
            return await asyncio.to_thread(
                self._evaluate_sync,
                task,
                raw_completion,
                rollout_id,
            )

    def _evaluate_sync(
        self,
        task: Dict[str, Any],
        raw_completion: str,
        rollout_id: str,
    ) -> VerificationResult:
        t0 = time.perf_counter()
        task_id = task.get("task_id", "unknown_task")
        task_sha256 = task.get("task_sha256", "")
        if not task_sha256:
            task_sha256 = compute_sha256_str(json.dumps(task, sort_keys=True))

        source_code = extract_c_source(raw_completion)
        source_sha256 = compute_sha256_str(source_code)
        compliance = check_output_compliance(raw_completion)

        rollout_record_dir = self.records_dir / rollout_id
        rollout_record_dir.mkdir(parents=True, exist_ok=True)

        source_path = rollout_record_dir / "candidate.c"
        source_path.write_text(source_code, encoding="utf-8")

        raw_completion_path = rollout_record_dir / "completion.raw.txt"
        raw_completion_path.write_text(raw_completion, encoding="utf-8")

        timing: Dict[str, float] = {}
        pin_path = Path(f"/sys/fs/bpf/bpf_rlvr_{rollout_id}_{os.getpid()}")

        result = VerificationResult(
            rollout_id=rollout_id,
            task_id=task_id,
            source_sha256=source_sha256,
            task_sha256=task_sha256,
            output_compliance=compliance,
            compile={"attempted": False, "pass": False, "stdout": "", "stderr": "", "returncode": -1},
            verifier={"attempted": False, "pass": False, "stdout": "", "stderr": "", "log": ""},
            behavioral={
                "attempted": False,
                "pass": False,
                "passed_tests": 0,
                "total_tests": 0,
                "details": [],
            },
            cleanup_passed=True,
            infrastructure_error=False,
            error_message=None,
            timeout_stage=None,
            raw_log_path=str(rollout_record_dir / "result.json").replace("\\", "/"),
            timing=timing,
            passed=False,
            diagnostic=None,
        )

        # Fail-closed check: Ensure Clang and bpftool are installed
        if not shutil.which(self.clang_path):
            result.infrastructure_error = True
            result.error_message = f"Clang binary not found at '{self.clang_path}'"
            self._persist_result(result, rollout_record_dir)
            return result

        if not shutil.which(self.bpftool_path):
            result.infrastructure_error = True
            result.error_message = f"bpftool binary not found at '{self.bpftool_path}'"
            self._persist_result(result, rollout_record_dir)
            return result

        obj_path = rollout_record_dir / "candidate.o"

        try:
            # 1. Compilation
            t_comp_start = time.perf_counter()
            result.compile["attempted"] = True
            compile_cmd = [
                self.clang_path,
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-target",
                "bpf",
            ]
            for inc in self.include_paths:
                compile_cmd.extend(["-I", inc])
            compile_cmd.extend(["-c", str(source_path), "-o", str(obj_path)])

            try:
                proc_c = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                )
                timing["compile_seconds"] = round(time.perf_counter() - t_comp_start, 4)
                result.compile["stdout"] = proc_c.stdout[:10000]
                result.compile["stderr"] = proc_c.stderr[:10000]
                result.compile["returncode"] = proc_c.returncode
                result.compile["pass"] = proc_c.returncode == 0 and obj_path.is_file()
            except subprocess.TimeoutExpired:
                timing["compile_seconds"] = round(time.perf_counter() - t_comp_start, 4)
                result.compile["stderr"] = "Compilation timed out after 30s"
                result.timeout_stage = "compile"
                result.diagnostic = "Compilation timed out"
                self._persist_result(result, rollout_record_dir)
                return result
            except Exception as e:
                result.infrastructure_error = True
                result.error_message = f"Compilation execution error: {e}"
                self._persist_result(result, rollout_record_dir)
                return result

            if not result.compile["pass"]:
                result.passed = False
                result.diagnostic = f"Compilation failed:\n{proc_c.stderr.strip()}"
                self._persist_result(result, rollout_record_dir)
                return result

            # 2. Verifier Loading
            t_ver_start = time.perf_counter()
            result.verifier["attempted"] = True
            if pin_path.exists():
                try:
                    pin_path.unlink()
                except Exception:
                    pass

            load_cmd = [self.bpftool_path, "-d", "prog", "load", str(obj_path), str(pin_path)]
            try:
                proc_v = subprocess.run(
                    load_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                )
                timing["verifier_seconds"] = round(time.perf_counter() - t_ver_start, 4)
                v_pass = proc_v.returncode == 0 and pin_path.exists()
                result.verifier["stdout"] = proc_v.stdout[:10000]
                result.verifier["stderr"] = proc_v.stderr[:10000]
                result.verifier["log"] = proc_v.stderr if not v_pass else ""
                result.verifier["pass"] = v_pass
            except subprocess.TimeoutExpired:
                timing["verifier_seconds"] = round(time.perf_counter() - t_ver_start, 4)
                result.verifier["stderr"] = "Verifier loading timed out after 30s"
                result.timeout_stage = "verifier"
                result.diagnostic = "Kernel verifier loading timed out"
                self._persist_result(result, rollout_record_dir)
                return result
            except Exception as e:
                result.infrastructure_error = True
                result.error_message = f"Verifier execution error: {e}"
                self._persist_result(result, rollout_record_dir)
                return result

            if not result.verifier["pass"]:
                result.passed = False
                err_text = proc_v.stderr.strip() or proc_v.stdout.strip()
                result.diagnostic = f"Kernel verifier rejected program:\n{err_text}"
                self._persist_result(result, rollout_record_dir)
                return result

            # 3. Behavioral Packet Testing
            t_test_start = time.perf_counter()
            result.behavioral["attempted"] = True
            test_cases = task.get("tests") or task.get("test_cases", [])
            expected_count = task.get("expected_fixture_count", len(test_cases))

            if len(test_cases) == 0:
                result.diagnostic = "Task has no fixtures"
                self._persist_result(result, rollout_record_dir)
                return result

            passed_tests = 0
            details: List[Dict[str, Any]] = []
            behavioral_failures: List[str] = []

            pkt_in = rollout_record_dir / "pkt_in.bin"
            pkt_out = rollout_record_dir / "pkt_out.bin"

            for test_case in test_cases:
                t_name = test_case.get("name", "unnamed")
                t_desc = test_case.get("description", "")
                pkt_hex = test_case.get("packet_hex", "")
                expected_action = test_case.get("expected_action", "XDP_PASS")
                weight = float(test_case.get("weight", 1.0))

                expected_int = (
                    ACTION_NAME_TO_INT.get(expected_action)
                    if isinstance(expected_action, str)
                    else int(expected_action)
                )

                try:
                    pkt_bytes = bytes.fromhex(pkt_hex)
                except ValueError as e:
                    details.append({
                        "name": t_name,
                        "pass": False,
                        "weight": weight,
                        "error": f"Invalid packet hex: {e}",
                    })
                    behavioral_failures.append(f"Test '{t_name}': invalid packet hex")
                    continue

                pkt_in.write_bytes(pkt_bytes)
                if pkt_out.exists():
                    pkt_out.unlink()

                run_cmd = [
                    self.bpftool_path,
                    "prog",
                    "run",
                    "pinned",
                    str(pin_path),
                    "data_in",
                    str(pkt_in),
                    "data_out",
                    str(pkt_out),
                ]
                try:
                    proc_r = subprocess.run(
                        run_cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        shell=False,
                    )
                except subprocess.TimeoutExpired:
                    details.append({
                        "name": t_name,
                        "pass": False,
                        "weight": weight,
                        "error": "Packet test timed out after 10s",
                    })
                    behavioral_failures.append(f"Test '{t_name}' timed out")
                    result.timeout_stage = "behavioral"
                    continue
                except Exception as e:
                    result.infrastructure_error = True
                    result.error_message = f"Packet execution error: {e}"
                    self._persist_result(result, rollout_record_dir)
                    return result

                actual_int: Optional[int] = None
                if proc_r.returncode == 0:
                    match = re.search(r"Return value:\s*(\d+)", proc_r.stdout)
                    if match:
                        actual_int = int(match.group(1))

                actual_name = ACTION_INT_TO_NAME.get(actual_int, f"UNKNOWN({actual_int})") if actual_int is not None else "ERROR"
                test_passed = actual_int == expected_int

                if test_passed:
                    passed_tests += 1
                    details.append({
                        "name": t_name,
                        "description": t_desc,
                        "pass": True,
                        "weight": weight,
                        "expected": expected_action,
                        "actual": actual_name,
                    })
                else:
                    details.append({
                        "name": t_name,
                        "description": t_desc,
                        "pass": False,
                        "weight": weight,
                        "expected": expected_action,
                        "actual": actual_name,
                        "stderr": proc_r.stderr[:2000],
                    })
                    behavioral_failures.append(
                        f"Test '{t_name}': expected {expected_action}, got {actual_name}"
                    )

            timing["behavioral_seconds"] = round(time.perf_counter() - t_test_start, 4)
            b_pass = len(test_cases) > 0 and passed_tests == len(test_cases)

            result.behavioral["total_tests"] = len(test_cases)
            result.behavioral["passed_tests"] = passed_tests
            result.behavioral["pass"] = b_pass
            result.behavioral["details"] = details

            if b_pass:
                result.passed = True
                result.diagnostic = None
            else:
                result.passed = False
                result.diagnostic = "Behavioral tests failed:\n" + "\n".join(behavioral_failures)

        finally:
            # 4. Cleanup path (guaranteed)
            if pin_path.exists():
                try:
                    pin_path.unlink()
                except Exception as e:
                    result.cleanup_passed = False
                    result.infrastructure_error = True
                    result.error_message = f"Failed to unpin {pin_path}: {e}"
                    logger.error("Cleanup failure: %s", e)

            # Cleanup transient files
            for p in [rollout_record_dir / "pkt_in.bin", rollout_record_dir / "pkt_out.bin", obj_path]:
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass

            timing["total_seconds"] = round(time.perf_counter() - t0, 4)
            self._persist_result(result, rollout_record_dir)

        return result

    def _persist_result(self, result: VerificationResult, rollout_dir: Path) -> None:
        """Persists the complete empirical verification record to JSON."""
        record_path = rollout_dir / "result.json"

        def _sanitize(val: Any) -> Any:
            if isinstance(val, str):
                return val.replace("\x00", "\\x00")
            elif isinstance(val, dict):
                return {k: _sanitize(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_sanitize(v) for v in val]
            return val

        data = _sanitize(result.to_dict())
        record_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
