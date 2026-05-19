# SentinelAI — Extension Modules

> **All modules are additive only. Zero modifications to any existing source file.**

---

## Integration Points

These extensions plug into the real SentinelAI architecture via three clean hooks:

### Hook 1 — Post-scan scoring (add 2 lines to `main.py` or anywhere after `cli.run()`)

```python
# In main.py, after init_db():
import cli_ext
cli_ext.patch_cli()   # wraps _run_scan_pipeline — no existing code changed
```

Every scan now automatically runs scoring, self-learning, and persistence.

### Hook 2 — Standalone entry point

```bash
python cli_ext.py score       scans/result.xml       # score any existing XML
python cli_ext.py autorecon   192.168.1.10 --tools   # extended auto-recon
python cli_ext.py dashboard                           # launch web dashboard
python cli_ext.py intel                               # pattern report
```

### Hook 3 — Direct API in your own code

```python
from scoring.attack_surface_scorer import AttackSurfaceScorer
from intelligence.self_learning     import SelfLearningLayer

scorer = AttackSurfaceScorer()
layer  = SelfLearningLayer()

# After analyzer.analyze():
result    = scorer.score_host(host_analysis)   # uses real HostAnalysis
enhanced  = layer.enhance(host_analysis, result)
layer.persist(target, host_analysis, result)

print(result)          # terminal output
print(result.to_dict()) # for report_generator integration
```

---

## Module Reference

### `scoring/attack_surface_scorer.py` — Attack Surface Scoring Engine

Accepts a real `HostAnalysis` from `analyzer.analyze()`.  
Re-uses `config.RISKY_PORTS` and `config.RISK_WEIGHTS` — same weights, extended factors.

**Scoring factors:**

| Factor | Source | Max pts |
|---|---|---|
| Risky ports | `config.RISKY_PORTS` + `RISK_WEIGHTS` | 5.0 |
| Insecure protocols | service name match | 3.0 |
| Outdated services | `ha.outdated` list | 4.0 |
| Anonymous/open access | NSE script output | 3.0 |
| CVE / vuln script hits | `ha.findings` severity | 4.0 |
| Weak TLS | ssl-* script output | 2.0 |
| Port count (>10) | `len(open_ports)` | 1.0 |

Score normalised to 0–10 → INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL.

```
──────────────────────────────────────────────────────
  Attack Surface Score : 8.1 / 10  [HIGH]
  Target               : 192.168.1.10
──────────────────────────────────────────────────────
  Risk Factors:
    • exposed SMB (port 445, CRITICAL)
    • exposed FTP (port 21, HIGH)
    • outdated: vsftpd 2.3.4
    • open/anonymous access: anonymous ftp login allowed
    • weak TLS: RC4, TLSV1.0
    • 1 CVE(s): CVE-2021-41773
──────────────────────────────────────────────────────
```

Integrates with `report_generator.py` via `result.to_dict()`.

---

### `intelligence/scan_memory.py` — Scan Memory Database

Creates `database/intelligence.db` alongside the existing `targets.db`.

```python
from intelligence.scan_memory import ScanMemoryDB
mem = ScanMemoryDB()
mem.save(target, host_analysis, scoring_result)

history     = mem.history("192.168.1.10")
svc_freq    = mem.service_frequency()   # [("smb",14), ("http",12), ...]
cve_freq    = mem.cve_frequency()
```

Stored per scan: target, ports, services, versions, CVEs, enum_recs, attack_vecs, risk_score, severity.

---

### `intelligence/pattern_recognizer.py` — Pattern Recognizer

```python
from intelligence.pattern_recognizer import PatternRecognizer
pr       = PatternRecognizer(mem)
insights = pr.analyze()
# {
#   "frequent_services":  [{"service":"smb","count":14}, ...],
#   "frequent_cves":      [{"cve":"CVE-2021-41773","count":6}, ...],
#   "service_techniques": {"apache": Counter({"dir brute force":8}), ...},
#   "high_risk_targets":  [{"target":"10.0.0.1","avg_risk":8.4,"scans":3}],
#   "top_enum_hints":     ["SMB share enumeration", ...],
# }

recs = pr.prioritised_recs(["apache","smb","ftp"])
# Returns historically-weighted recs, e.g.:
# "[8x seen] dir brute force (re: apache)"
# "[6x seen] Check CVE-2021-41773 (re: apache)"
```

Pattern detection examples:
- If Apache 2.4.49 + CVE-2021-41773 appear 6 times → surfaces to top of recs automatically
- If SMB appears frequently on a network → SMB enumeration prioritised first

---

### `intelligence/self_learning.py` — Self-Learning Layer

```python
from intelligence.self_learning import SelfLearningLayer
layer = SelfLearningLayer()

# Enhance recommendations for a new scan
enhanced = layer.enhance(host_analysis, scoring_result)

# Persist so future scans benefit
layer.persist(target, host_analysis, scoring_result)
```

Combines: `HostAnalysis.suggestions` + `KnowledgeBase` techniques + `PatternRecognizer` recs + CVE hints.

---

### `intelligence/knowledge_base.py` — Intelligence Knowledge Base

Seeded from `config.SERVICE_KB` patterns. Grows automatically via `auto_update()`.  
Stored at `database/knowledge_base.json`.

```python
from intelligence.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
kb.techniques("smb")
# ["SMB share enumeration", "null session check", "user enumeration via enum4linux",
#  "check EternalBlue MS17-010", "NTLM relay assessment"]

kb.auto_update("apache", ["new technique from scan"])
```

---

### `intelligence/llm_reasoning.py` — LLM Reasoning Module (Optional)

Fully offline-safe — not required for any other module.  
Accepts a real `HostAnalysis` + optional intelligence context.

```python
from intelligence.llm_reasoning import LLMReasoningModule

# Anthropic (same API pattern as assistant.py)
m = LLMReasoningModule(backend="anthropic", api_key="sk-ant-...")

# Ollama local LLM (fully offline)
m = LLMReasoningModule(backend="ollama", model="llama3")

# OpenAI
m = LLMReasoningModule(backend="openai", api_key="sk-...", model="gpt-4o-mini")

# HuggingFace
m = LLMReasoningModule(backend="huggingface", api_key="hf_...",
                        model="mistralai/Mistral-7B-Instruct-v0.2")

recs = m.analyze(host_analysis, intel=pr.analyze())
# ["1. Perform SMB share enumeration",
#  "2. Check Apache version for CVE-2021-41773",
#  "3. Run directory brute force against web server",
#  "4. Investigate privilege escalation vectors"]
```

---

### `tool_orchestrator.py` — Tool Orchestrator

Automatically selects tools from a `HostAnalysis` object.

```python
from tool_orchestrator import ToolOrchestrator
orch    = ToolOrchestrator()
results = orch.auto_run(host_analysis)

for r in results:
    print(r.tool, r.success, r.short_summary)
    print(r.parsed)
```

Auto-selection logic:
- HTTP/S detected → gobuster, whatweb, nikto, ffuf
- SMB detected → enum4linux
- Domain target → subfinder or amass

All tools are availability-checked before execution — graceful skip if not installed.

---

### `dashboard/app.py` + `dashboard/templates/dashboard.html` — Recon Dashboard

Read-only Flask dashboard. Reads `targets.db` (existing) and `intelligence.db` (extension).

```bash
python cli_ext.py dashboard
# → http://localhost:5000
```

API endpoints:
- `GET /api/scans` — scan history from `targets.db`
- `GET /api/hosts` — host inventory sorted by risk score
- `GET /api/findings` — all findings (CRITICAL first)
- `GET /api/intel/history` — intelligence DB history
- `GET /api/intel/services` — service frequency ranking
- `GET /api/intel/cves` — CVE frequency ranking

---

### `cli_ext.py` — CLI Extension Layer

Extends the existing CLI with new commands and hooks without modifying `cli.py`.

```bash
# Patch into existing main.py (MODE A, recommended)
import cli_ext
cli_ext.patch_cli()    # wraps _run_scan_pipeline transparently

# Standalone commands (MODE B)
python cli_ext.py score       scans/target_full.xml
python cli_ext.py autorecon   192.168.1.10 --tools --ai
python cli_ext.py dashboard
python cli_ext.py intel
```

---

## Install

```bash
pip install flask           # for dashboard
pip install openai          # optional: OpenAI backend
# ollama/HuggingFace accessed via HTTP — no package needed
```

---

## Legal

For authorized penetration testing / educational lab use only.
