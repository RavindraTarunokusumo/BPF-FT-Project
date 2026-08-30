# Qwen3-8B SFT: Thinking Disabled vs Thinking Enabled Comparative Evaluation

Comparative study on the 36 calibration tasks under identical checkpoint (`qwen3-8b-full-sft-v1`), sampling temperature (T=0.0), and seed (42).

## High-Level Benchmark Comparison
| Metric | Thinking Disabled (`qwen3_disable_thinking`) | Thinking Enabled (`qwen3`) | Absolute Delta | Relative Change |
|---|---|---|---|---|
| **Functional Pass@1** | **55.6%** (20/36) | **22.2%** (8/36) | **-33.3%** | **-60.0%** |
| Clang BPF Compilation | 69.4% | 27.8% | -41.7% | -60.0% |
| Kernel Verifier Load | 61.1% | 22.2% | -38.9% | -63.6% |
| Total Generated Tokens | 15,878 | 82,802 | +66,924 | +4.2x tokens |
| Avg Tokens per Sample | 441 tokens | 2300 tokens | +1859 tokens | +5.2x |

## Category Breakdown Comparison (Pass@1)
| Category | Tasks | Thinking Disabled Pass@1 | Thinking Enabled Pass@1 | Delta |
|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 33.3% (3/9) | 0.0% (0/9) | -33.3% |
| `packet_filtering_security` | 9 | 44.4% (4/9) | 0.0% (0/9) | -44.4% |
| `packet_inspection_telemetry` | 9 | 88.9% (8/9) | 55.6% (5/9) | -33.3% |
| `protocol_transformation` | 9 | 55.6% (5/9) | 33.3% (3/9) | -22.2% |

## Difficulty Breakdown Comparison (Pass@1)
| Difficulty Tier | Tasks | Thinking Disabled Pass@1 | Thinking Enabled Pass@1 | Delta |
|---|---|---|---|---|
| `level_1` | 12 | 75.0% (9/12) | 33.3% (4/12) | -41.7% |
| `level_2` | 12 | 66.7% (8/12) | 16.7% (2/12) | -50.0% |
| `level_3` | 12 | 25.0% (3/12) | 16.7% (2/12) | -8.3% |

## Key Insights and Analysis
1. **Training & Inference Alignment**: The model was fine-tuned on the verified 1,120 example SFT dataset using `qwen3_disable_thinking` (direct C source targets without CoT traces). Operating in thinking-disabled mode maintains complete alignment with training data distribution.
2. **Reasoning Overhead & Truncation**: When thinking is enabled, the model generates extensive chain-of-thought exploration (~2,300 tokens/task vs 441 tokens). For complex multi-requirement tasks, reasoning loops consume significant token budget, occasionally running into truncation boundaries or introducing contradictory logic during drafting.
3. **Kernel Verifier Strictness**: XDP verification requires precise byte bounds checks (`(void*)(ptr + 1) > data_end`). In thinking-disabled mode, the fine-tuned LoRA weights directly recall structured kernel safety idioms with **61.1%** verifier approval, whereas thinking exploration causes drift and over-elaboration resulting in **22.2%** verifier approval.
