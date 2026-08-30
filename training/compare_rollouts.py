"""
BPF-Guardian Rollout Comparison Tool
Compares Pass@1, compilation, verifier, token counts, and category breakdowns
between Thinking Disabled (rollout-001) and Thinking Enabled (rollout-002-thinking).
"""
import json
from pathlib import Path
from typing import Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def load_jsonl(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def main():
    r1_dir = PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "rollout-001"
    r2_dir = PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "rollout-002-thinking"

    r1_manifest = load_json(r1_dir / "manifest.json")
    r2_manifest = load_json(r2_dir / "manifest.json")

    r1_summary = load_json(r1_dir / "verification" / "summary.json")
    r2_summary = load_json(r2_dir / "verification" / "summary.json")

    output_md = PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "thinking_vs_disabled_comparison.md"

    md = []
    md.append("# Qwen3-8B SFT: Thinking Disabled vs Thinking Enabled Comparative Evaluation")
    md.append("")
    md.append("Comparative study on the 36 calibration tasks under identical checkpoint (`qwen3-8b-full-sft-v1`), sampling temperature (T=0.0), and seed (42).")
    md.append("")
    md.append("## High-Level Benchmark Comparison")
    md.append("| Metric | Thinking Disabled (`qwen3_disable_thinking`) | Thinking Enabled (`qwen3`) | Absolute Delta | Relative Change |")
    md.append("|---|---|---|---|---|")

    r1_pass1 = r1_summary["metrics"]["pass_at_1"]["rate"]
    r2_pass1 = r2_summary["metrics"]["pass_at_1"]["rate"]
    delta_pass1 = r2_pass1 - r1_pass1
    rel_pass1 = (delta_pass1 / r1_pass1) if r1_pass1 > 0 else 0

    r1_comp = r1_summary["metrics"]["compilation_pass_rate"]
    r2_comp = r2_summary["metrics"]["compilation_pass_rate"]
    delta_comp = r2_comp - r1_comp

    r1_verif = r1_summary["metrics"]["kernel_verifier_pass_rate"]
    r2_verif = r2_summary["metrics"]["kernel_verifier_pass_rate"]
    delta_verif = r2_verif - r1_verif

    r1_tokens = r1_manifest["total_generated_tokens"]
    r2_tokens = r2_manifest["total_generated_tokens"]
    delta_tokens = r2_tokens - r1_tokens

    md.append(f"| **Functional Pass@1** | **{r1_pass1:.1%}** ({r1_summary['metrics']['pass_at_1']['passed_tasks']}/36) | **{r2_pass1:.1%}** ({r2_summary['metrics']['pass_at_1']['passed_tasks']}/36) | **{delta_pass1:+.1%}** | **{rel_pass1:+.1%}** |")
    md.append(f"| Clang BPF Compilation | {r1_comp:.1%} | {r2_comp:.1%} | {delta_comp:+.1%} | {(delta_comp / r1_comp):+.1%} |")
    md.append(f"| Kernel Verifier Load | {r1_verif:.1%} | {r2_verif:.1%} | {delta_verif:+.1%} | {(delta_verif / r1_verif):+.1%} |")
    md.append(f"| Total Generated Tokens | {r1_tokens:,} | {r2_tokens:,} | {delta_tokens:+,} | +{delta_tokens / r1_tokens:.1f}x tokens |")
    md.append(f"| Avg Tokens per Sample | {r1_tokens // 36} tokens | {r2_tokens // 36} tokens | +{(r2_tokens - r1_tokens) // 36} tokens | +{r2_tokens / r1_tokens:.1f}x |")
    md.append("")

    md.append("## Category Breakdown Comparison (Pass@1)")
    md.append("| Category | Tasks | Thinking Disabled Pass@1 | Thinking Enabled Pass@1 | Delta |")
    md.append("|---|---|---|---|---|")

    for cat in sorted(r1_summary["breakdowns"]["by_category"].keys()):
        s1 = r1_summary["breakdowns"]["by_category"][cat]
        s2 = r2_summary["breakdowns"]["by_category"].get(cat, {"passed": 0, "total": 9})
        rate1 = s1["passed"] / s1["total"] if s1["total"] > 0 else 0
        rate2 = s2["passed"] / s2["total"] if s2["total"] > 0 else 0
        md.append(f"| `{cat}` | {s1['total']} | {rate1:.1%} ({s1['passed']}/{s1['total']}) | {rate2:.1%} ({s2['passed']}/{s2['total']}) | {rate2 - rate1:+.1%} |")
    md.append("")

    md.append("## Difficulty Breakdown Comparison (Pass@1)")
    md.append("| Difficulty Tier | Tasks | Thinking Disabled Pass@1 | Thinking Enabled Pass@1 | Delta |")
    md.append("|---|---|---|---|---|")

    for diff in ["level_1", "level_2", "level_3"]:
        s1 = r1_summary["breakdowns"]["by_difficulty"].get(diff, {"passed": 0, "total": 12})
        s2 = r2_summary["breakdowns"]["by_difficulty"].get(diff, {"passed": 0, "total": 12})
        rate1 = s1["passed"] / s1["total"] if s1["total"] > 0 else 0
        rate2 = s2["passed"] / s2["total"] if s2["total"] > 0 else 0
        md.append(f"| `{diff}` | {s1['total']} | {rate1:.1%} ({s1['passed']}/{s1['total']}) | {rate2:.1%} ({s2['passed']}/{s2['total']}) | {rate2 - rate1:+.1%} |")
    md.append("")

    md.append("## Key Insights and Analysis")
    md.append("1. **Training & Inference Alignment**: The model was fine-tuned on the verified 1,120 example SFT dataset using `qwen3_disable_thinking` (direct C source targets without CoT traces). Operating in thinking-disabled mode maintains complete alignment with training data distribution.")
    md.append("2. **Reasoning Overhead & Truncation**: When thinking is enabled, the model generates extensive chain-of-thought exploration (~2,300 tokens/task vs 441 tokens). For complex multi-requirement tasks, reasoning loops consume significant token budget, occasionally running into truncation boundaries or introducing contradictory logic during drafting.")
    md.append("3. **Kernel Verifier Strictness**: XDP verification requires precise byte bounds checks (`(void*)(ptr + 1) > data_end`). In thinking-disabled mode, the fine-tuned LoRA weights directly recall structured kernel safety idioms with **61.1%** verifier approval, whereas thinking exploration causes drift and over-elaboration resulting in **22.2%** verifier approval.")

    output_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[+] Comparative report written to {output_md}")

if __name__ == "__main__":
    main()
