#!/usr/bin/env python3
"""
Assemble the updated index.html with:
1. Full-size 4-Panel Suite Breakdown and Domain panel beneath it.
2. Interactive SVG main chart with on-hover effects and tooltips.
3. Removed chart emoji and Matplotlib Generated Visualizations tag.
4. Added Copy codeblock button for Python snippet.
"""

from pathlib import Path
from generate_interactive_chart import build_svg_chart

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCS_HTML = PROJECT_ROOT / "docs" / "index.html"
ROOT_HTML = PROJECT_ROOT / "index.html"

raw_html = DOCS_HTML.read_text(encoding="utf-8")

# 1. Update CSS styles in <head>
css_addition = """    /* Interactive Hero Chart Styles */
    .chart-bar-item {
      cursor: pointer;
      outline: none;
    }
    .chart-bar {
      transform-box: fill-box;
      transform-origin: bottom center;
      transition: transform 0.22s cubic-bezier(0.34, 1.56, 0.64, 1), filter 0.22s ease, opacity 0.2s ease;
    }
    .chart-bar-label {
      pointer-events: none;
      transition: transform 0.22s cubic-bezier(0.34, 1.56, 0.64, 1), fill 0.2s ease, font-weight 0.2s ease, opacity 0.2s ease;
    }
    .chart-bar-item:hover .chart-bar,
    .chart-bar-item:focus .chart-bar {
      transform: translateY(-6px) scaleY(1.02);
      filter: drop-shadow(0 0 14px currentColor) brightness(1.3);
    }
    .chart-bar-item:hover .chart-bar-label,
    .chart-bar-item:focus .chart-bar-label {
      transform: translateY(-6px);
      fill: #ffffff;
      font-weight: 800;
    }
    /* Dim non-hovered bars when any bar is hovered */
    .chart-svg:has(.chart-bar-item:hover) .chart-bar-item:not(:hover) .chart-bar {
      opacity: 0.38;
      filter: grayscale(25%);
    }
    .chart-svg:has(.chart-bar-item:hover) .chart-bar-item:not(:hover) .chart-bar-label {
      opacity: 0.3;
    }
"""

if ".chart-bar-item" not in raw_html:
    raw_html = raw_html.replace("    /* Custom Scrollbar */", css_addition + "\n    /* Custom Scrollbar */")

# 2. Build the SVG
svg_chart = build_svg_chart()

# 3. Replace the Benchmark Section Header, Hero Chart, and the 2 Panels
benchmark_start_marker = '    <!-- SECTION 1: VISUAL PERFORMANCE SHOWCASE -->'
table_start_marker = '      <!-- Formal Empirical Table -->'

bench_start_idx = raw_html.find(benchmark_start_marker)
table_start_idx = raw_html.find(table_start_marker)

if bench_start_idx == -1 or table_start_idx == -1:
    raise ValueError("Could not find section markers in HTML")

new_benchmark_content = f"""    <!-- SECTION 1: VISUAL PERFORMANCE SHOWCASE -->
    <section id="benchmarks" class="space-y-6">
      <div class="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-dark-border pb-4">
        <div>
          <span class="text-brand-400 font-mono text-xs uppercase tracking-widest font-semibold">Empirical Evaluations</span>
          <h2 class="text-2xl sm:text-3xl font-bold text-white mt-1">Generational Performance Progression</h2>
          <p class="text-sm text-slate-400 mt-1">Evaluated directly on Hostinger Linux VPS (`6.8.0-106-generic`) with live `BPF_PROG_TEST_RUN` execution.</p>
        </div>
      </div>

      <!-- Hero Bar Chart Container -->
      <div class="rounded-2xl bg-dark-card border border-dark-border p-4 sm:p-6 overflow-hidden glow-accent">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <h3 class="text-base font-semibold text-white flex items-center gap-2">
            Primary Suite Benchmark Comparison: Base vs Prior SOTA vs SFT vs RL
          </h3>
          <div class="flex items-center gap-2">
            <button id="view-interactive-btn" onclick="toggleMainChart('svg')" class="px-3 py-1 rounded-lg bg-brand-500/20 text-brand-300 border border-brand-500/40 text-xs font-semibold transition-all">
              Interactive SVG (Hover Active)
            </button>
            <button id="view-png-btn" onclick="toggleMainChart('png')" class="px-3 py-1 rounded-lg bg-dark-surface text-slate-400 hover:text-white border border-dark-border text-xs font-semibold transition-all">
              Static 300 DPI PNG
            </button>
          </div>
        </div>
        
        <!-- Chart Wrapper (Relative for Tooltip Positioning) -->
        <div id="chart-container-relative" class="relative overflow-x-auto rounded-xl bg-dark-bg p-2 sm:p-4 border border-dark-border/60">
          
          <!-- Floating Interactive Tooltip -->
          <div id="chart-tooltip" class="pointer-events-none absolute z-30 hidden -translate-x-1/2 -translate-y-full rounded-xl bg-slate-900/95 px-3.5 py-2.5 text-xs text-white shadow-2xl border border-brand-500/50 backdrop-blur-md transition-opacity duration-150 font-sans min-w-[210px]">
            <div id="tooltip-series" class="font-bold text-brand-300 text-xs"></div>
            <div id="tooltip-suite" class="text-slate-400 text-[11px] mt-0.5"></div>
            <div class="flex items-baseline justify-between gap-3 mt-1.5 pt-1.5 border-t border-slate-800">
              <span id="tooltip-val" class="text-base font-extrabold text-white font-mono"></span>
              <span id="tooltip-count" class="text-slate-400 font-mono text-xs"></span>
            </div>
            <div id="tooltip-badge" class="mt-1 text-[11px] text-emerald-400 font-medium"></div>
          </div>

          <!-- Interactive SVG Chart -->
          <div id="svg-chart-wrapper" class="w-full">
{svg_chart}
          </div>

          <!-- High-Res Static PNG (Initially Hidden, Toggleable) -->
          <div id="png-chart-wrapper" class="w-full hidden">
            <img src="assets/performance_hero_bar.png" alt="BPF-Guardian Benchmark Performance Across Training Stages" class="w-full h-auto rounded-lg shadow-lg">
          </div>

        </div>
      </div>

      <!-- Detailed Progression & Domain Scaling Panels (Stacked Full-Size) -->
      <div class="space-y-6">
        
        <!-- Comprehensive 4-Panel Suite Breakdown (Full-Size) -->
        <div class="rounded-2xl bg-dark-card border border-dark-border p-5 sm:p-7 space-y-4 hover:border-brand-500/30 transition-all">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 class="font-bold text-white text-base sm:text-lg">Comprehensive 4-Panel Suite Breakdown</h3>
              <p class="text-xs text-slate-400 mt-0.5">Synthesis, Standalone Repair, Confirmation &amp; Combined suites</p>
            </div>
            <span class="text-xs px-2.5 py-1 rounded-md bg-slate-800 text-brand-300 font-mono font-medium self-start sm:self-auto">4 Panels &bull; Full Breakdown</span>
          </div>
          <div class="rounded-xl overflow-hidden border border-dark-border/70 bg-dark-bg p-2">
            <img src="assets/performance_progression.png" alt="Comprehensive 4-Panel Suite Breakdown" class="w-full h-auto rounded-lg shadow-lg">
          </div>
          <p class="text-xs sm:text-sm text-slate-400 leading-relaxed">
            <strong class="text-brand-300">Key takeaway:</strong> On Protected Synthesis, base untuned Nemotron scores 0.0%, Qwen SFT v2 achieves 25.8%, Nemotron SFT v1 reaches 45.0%, and Multi-turn RL peaks at <strong class="text-white">49.2% Solve@2</strong> (+35 net solved tasks on combined benchmarks).
          </p>
        </div>

        <!-- Domain Robustness & Complexity Scaling (Full-Size beneath) -->
        <div class="rounded-2xl bg-dark-card border border-dark-border p-5 sm:p-7 space-y-4 hover:border-brand-500/30 transition-all">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 class="font-bold text-white text-base sm:text-lg">Domain Robustness &amp; Complexity Scaling</h3>
              <p class="text-xs text-slate-400 mt-0.5">Packet Filtering, Routing, Telemetry &amp; Transformations across algorithmic difficulty levels</p>
            </div>
            <span class="text-xs px-2.5 py-1 rounded-md bg-slate-800 text-brand-300 font-mono font-medium self-start sm:self-auto">Domain &amp; Level Analysis</span>
          </div>
          <div class="rounded-xl overflow-hidden border border-dark-border/70 bg-dark-bg p-2">
            <img src="assets/domain_breakdown.png" alt="Domain Robustness and Complexity Scaling" class="w-full h-auto rounded-lg shadow-lg">
          </div>
          <p class="text-xs sm:text-sm text-slate-400 leading-relaxed">
            <strong class="text-brand-300">Key takeaway:</strong> Performance scales robustly across all 4 networking domains (PFS, NRF, PIT, PTR) and complexity levels (Level 1 Ingress 87.5%, Level 2 Stateful Maps 66.7%, Level 3 Advanced Consistent Hashing 47.9%).
          </p>
        </div>

      </div>

"""

raw_html = raw_html[:bench_start_idx] + new_benchmark_content + raw_html[table_start_idx:]

# 4. Update Python Codeblock with Copy Button
target_code_header = """        <div class="bg-dark-surface px-5 py-3 border-b border-dark-border flex justify-between items-center">
          <span class="font-mono text-xs text-slate-300 flex items-center gap-2">
            <span class="h-2 w-2 rounded-full bg-brand-400"></span> Python: Load &amp; Generate Verified eBPF with PEFT
          </span>
          <span class="text-xs text-slate-400 font-mono">PyTorch / Transformers / PEFT</span>
        </div>"""

replacement_code_header = """        <div class="bg-dark-surface px-5 py-3 border-b border-dark-border flex justify-between items-center">
          <span class="font-mono text-xs text-slate-300 flex items-center gap-2">
            <span class="h-2 w-2 rounded-full bg-brand-400"></span> Python: Load &amp; Generate Verified eBPF with PEFT
          </span>
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400 font-mono hidden sm:inline">PyTorch / Transformers / PEFT</span>
            <button id="copy-code-btn" type="button" onclick="copyPythonCode()" aria-label="Copy Python code snippet"
                    class="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-dark-card hover:bg-slate-800 text-slate-300 hover:text-brand-300 text-xs font-mono border border-dark-border hover:border-brand-500/40 transition-all focus:outline-none focus:ring-2 focus:ring-brand-500/40 cursor-pointer">
              <svg id="copy-icon" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
              </svg>
              <svg id="check-icon" class="w-3.5 h-3.5 hidden text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              <span id="copy-text">Copy</span>
            </button>
          </div>
        </div>"""

raw_html = raw_html.replace(target_code_header, replacement_code_header)
raw_html = raw_html.replace('<pre><span class="text-brand-400">import</span> torch', '<pre id="python-code"><span class="text-brand-400">import</span> torch')

# 5. Add JavaScript Handlers before </body>
js_script = """  <script>
    // Tooltip & Hover interaction for Interactive Main Chart
    document.addEventListener('DOMContentLoaded', () => {
      const chartContainer = document.getElementById('chart-container-relative');
      const tooltip = document.getElementById('chart-tooltip');
      const ttSeries = document.getElementById('tooltip-series');
      const ttSuite = document.getElementById('tooltip-suite');
      const ttVal = document.getElementById('tooltip-val');
      const ttCount = document.getElementById('tooltip-count');
      const ttBadge = document.getElementById('tooltip-badge');

      const barItems = document.querySelectorAll('.chart-bar-item');
      barItems.forEach(item => {
        item.addEventListener('mouseenter', (e) => {
          const model = item.getAttribute('data-model');
          const suite = item.getAttribute('data-suite');
          const val = item.getAttribute('data-val');
          const count = item.getAttribute('data-count');
          const badge = item.getAttribute('data-badge');
          const color = item.getAttribute('data-color');

          if (ttSeries) {
            ttSeries.innerText = model;
            ttSeries.style.color = color || '#34D399';
          }
          if (ttSuite) ttSuite.innerText = suite;
          if (ttVal) ttVal.innerText = val;
          if (ttCount) ttCount.innerText = count;
          if (ttBadge) ttBadge.innerText = badge;

          if (tooltip) {
            tooltip.classList.remove('hidden');
            positionTooltip(e);
          }
        });

        item.addEventListener('mousemove', (e) => {
          positionTooltip(e);
        });

        item.addEventListener('mouseleave', () => {
          if (tooltip) tooltip.classList.add('hidden');
        });
      });

      function positionTooltip(e) {
        if (!chartContainer || !tooltip) return;
        const rect = chartContainer.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top - 14;
        tooltip.style.left = `${Math.max(110, Math.min(rect.width - 110, x))}px`;
        tooltip.style.top = `${Math.max(40, y)}px`;
      }
    });

    // Chart view toggle (SVG vs PNG)
    function toggleMainChart(view) {
      const svgWrapper = document.getElementById('svg-chart-wrapper');
      const pngWrapper = document.getElementById('png-chart-wrapper');
      const svgBtn = document.getElementById('view-interactive-btn');
      const pngBtn = document.getElementById('view-png-btn');

      if (!svgWrapper || !pngWrapper || !svgBtn || !pngBtn) return;

      if (view === 'svg') {
        svgWrapper.classList.remove('hidden');
        pngWrapper.classList.add('hidden');
        svgBtn.className = 'px-3 py-1 rounded-lg bg-brand-500/20 text-brand-300 border border-brand-500/40 text-xs font-semibold transition-all cursor-pointer';
        pngBtn.className = 'px-3 py-1 rounded-lg bg-dark-surface text-slate-400 hover:text-white border border-dark-border text-xs font-semibold transition-all cursor-pointer';
      } else {
        svgWrapper.classList.add('hidden');
        pngWrapper.classList.remove('hidden');
        pngBtn.className = 'px-3 py-1 rounded-lg bg-brand-500/20 text-brand-300 border border-brand-500/40 text-xs font-semibold transition-all cursor-pointer';
        svgBtn.className = 'px-3 py-1 rounded-lg bg-dark-surface text-slate-400 hover:text-white border border-dark-border text-xs font-semibold transition-all cursor-pointer';
      }
    }

    // Copy codeblock button handler
    function copyPythonCode() {
      const codeElement = document.getElementById('python-code');
      if (!codeElement) return;
      const text = codeElement.innerText;
      
      const copyBtn = document.getElementById('copy-code-btn');
      const copyIcon = document.getElementById('copy-icon');
      const checkIcon = document.getElementById('check-icon');
      const copyText = document.getElementById('copy-text');

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(showCopied).catch(fallbackCopy);
      } else {
        fallbackCopy();
      }

      function showCopied() {
        if (copyIcon) copyIcon.classList.add('hidden');
        if (checkIcon) checkIcon.classList.remove('hidden');
        if (copyText) copyText.innerText = 'Copied!';
        if (copyBtn) copyBtn.classList.add('border-emerald-500/60', 'text-emerald-300');

        setTimeout(() => {
          if (copyIcon) copyIcon.classList.remove('hidden');
          if (checkIcon) checkIcon.classList.add('hidden');
          if (copyText) copyText.innerText = 'Copy';
          if (copyBtn) copyBtn.classList.remove('border-emerald-500/60', 'text-emerald-300');
        }, 2000);
      }

      function fallbackCopy() {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          document.execCommand('copy');
          showCopied();
        } catch (err) {
          console.error('Copy fallback failed', err);
        }
        document.body.removeChild(textarea);
      }
    }
  </script>
"""

if "function copyPythonCode()" not in raw_html:
    raw_html = raw_html.replace("</body>", js_script + "\n</body>")

# Write to both docs/index.html and index.html
DOCS_HTML.write_text(raw_html, encoding="utf-8")
ROOT_HTML.write_text(raw_html, encoding="utf-8")
print(f"[+] Successfully updated {DOCS_HTML} and {ROOT_HTML}")
