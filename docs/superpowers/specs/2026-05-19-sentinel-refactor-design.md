# SentielAI v2 — Refactor Design Spec
**Date:** 2026-05-19  
**Scope:** Full codebase restructure, broken import fixes, dead code wiring, duplicate logic elimination

---

## Problem Statement

The current codebase dumps every file at the project root. Several modules are completely broken (wrong import paths crash on startup), the extension architecture (`cli_ext.py`) references subpackages that don't exist, five modules are dead code never imported anywhere, and two separate risk scorers + two separate LLM callers create contradictory behaviour. This refactor fixes all of that in a single clean pass.

---

## Approved Folder Structure

```
SentielAI/
├── main.py                        # entry point only
├── config.py                      # all config, profiles, risk data, env vars
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── scanner.py                 # nmap subprocess wrapper
│   ├── parser.py                  # xml → dataclasses
│   ├── analyzer.py                # analysis pipeline (no internal scoring)
│   ├── attack_surface_scorer.py   # single canonical scorer
│   ├── tool_orchestrator.py       # external tool runner
│   └── output.py                  # all Rich renderers (split from assistant.py)
│
├── modules/
│   ├── __init__.py
│   ├── subdomain_enum.py
│   ├── smb_enum.py
│   ├── ssh_analysis.py
│   ├── web_enum.py
│   ├── cve_lookup.py
│   └── exploit_advisor.py
│
├── ai/
│   ├── __init__.py
│   ├── llm_reasoning.py           # canonical multi-backend LLM
│   ├── knowledge_base.py          # service→technique map (reads config.SERVICE_KB)
│   ├── pattern_recognizer.py
│   └── self_learning.py
│
├── integrations/
│   └── __init__.py                # placeholder for metasploit/shodan future work
│
├── reporting/
│   ├── __init__.py
│   ├── report_generator.py
│   ├── app.py                     # flask dashboard (path fixed)
│   └── templates/
│       └── dashboard.html
│
├── database/
│   ├── __init__.py
│   ├── db.py                      # targets.db
│   └── scan_memory.py             # intelligence.db
│
├── cli.py                         # interactive REPL (absorbs cli_ext.py entirely)
├── logs/
├── reports/
└── scans/
```

---

## Data Flow

```
main.py
  └─▶ database/db.py      init_db()
  └─▶ cli.py              run()

cli.py (user command)
  ├─▶ core/scanner.py              run_scan() → dict
  ├─▶ core/parser.py               parse_xml() → ScanResult
  ├─▶ core/analyzer.py             analyze() → AnalysisReport
  ├─▶ core/attack_surface_scorer.py  score_host() per host
  ├─▶ modules/smb_enum.py          if port 139/445
  ├─▶ modules/ssh_analysis.py      if port 22
  ├─▶ modules/web_enum.py          if port 80/443/8080
  ├─▶ modules/exploit_advisor.py   always (appends refs to findings)
  ├─▶ ai/self_learning.py          enhance() + persist()
  ├─▶ core/output.py               render_report()
  ├─▶ database/db.py               save_scan()
  ├─▶ reporting/report_generator.py  generate_all() (report command)
  └─▶ modules/subdomain_enum.py    enumerate() (subdomains command)

LLM path (--ai flag):
  core/output.py → ai/llm_reasoning.LLMReasoningModule → Anthropic/Ollama/OpenAI

CVE path (--cve flag, rate-limited):
  post-scan → modules/cve_lookup.lookup_host_services()
```

---

## Key Decisions

### 1. cli_ext.py → merged into cli.py
The monkey-patch extension pattern is dropped. All post-scan hooks (scoring, self-learning, exploit refs) run directly from `cli.py`'s `_run_scan_pipeline`. One entry point, one CLI.

### 2. Single canonical scorer
`analyzer._compute_risk()` is removed. `core/attack_surface_scorer.AttackSurfaceScorer` is the only scorer. It runs after `analyze()` and writes `ScoringResult` back into each `HostAnalysis.risk_score`.

### 3. Single LLM layer
`assistant._call_llm()` and `_build_llm_prompt()` are dropped. `ai/llm_reasoning.LLMReasoningModule` is the only LLM caller. Supports Anthropic, OpenAI, Ollama, HuggingFace, raw HTTP. `core/output.py` calls it when `--ai` is passed.

### 4. knowledge_base._SEED dropped
`knowledge_base.py` no longer has a duplicate `_SEED` dict. It reads techniques directly from `config.SERVICE_KB` as its seed, then merges persisted JSON on top.

### 5. Dead modules wired into pipeline
`smb_enum`, `ssh_analysis`, `web_enum`, `exploit_advisor` are called automatically in the post-scan enrichment step in `cli.py`. `cve_lookup` runs on `--cve` flag. `llm_reasoning` runs on `--ai` flag.

---

## Broken Imports Fixed

| File | Broken Import | Fix |
|------|--------------|-----|
| `cli_ext.py` | `from scoring.attack_surface_scorer` | merged → `from core.attack_surface_scorer` |
| `cli_ext.py` | `from intelligence.self_learning` | merged → `from ai.self_learning` |
| `cli.py:355` | `from modules.subdomain_enum` | now real: `from modules.subdomain_enum` |
| `self_learning.py` | `from intelligence.*` | `from ai.*` and `from database.*` |
| `app.py` | `parent.parent.parent / database` | `parent.parent / database` |
| `app.py` | `templates/dashboard.html` | moved to `reporting/templates/` |
| `assistant._call_llm` | missing `x-api-key` header | replaced by `llm_reasoning` which has it |

---

## Config Changes

- `LLM_MODEL = "claude-sonnet-4-6"` (was `claude-sonnet-4-20250514`)
- Add `ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")`
- `requirements.txt`: add `flask` (optional), `openai` (optional), document what's needed for each feature

---

## What Is NOT Changed

- All scan logic, nmap profiles, risk weights, SERVICE_KB content — untouched
- Database schemas (targets.db, intelligence.db) — untouched
- Report formats (MD, HTML, JSON) — untouched
- The interactive REPL commands and UX — untouched
- `main.py` structure — minimal changes only (model ID, API key import)

---

## Implementation Order (for writing-plans)

1. Create all `__init__.py` files for new packages
2. Fix `config.py` (LLM_MODEL, ANTHROPIC_API_KEY, requirements.txt)
3. Move `core/` files: scanner, parser, analyzer, attack_surface_scorer, tool_orchestrator
4. Create `core/output.py` (split renderers from assistant.py)
5. Move `modules/` files: subdomain_enum, smb_enum, ssh_analysis, web_enum, cve_lookup, exploit_advisor
6. Move `ai/` files: llm_reasoning, knowledge_base (drop _SEED), pattern_recognizer, self_learning (fix imports)
7. Move `database/scan_memory.py` (fix imports)
8. Move `reporting/app.py` + `reporting/templates/dashboard.html` (fix paths)
9. Rewrite `cli.py`: absorb cli_ext, wire all dead modules into post-scan pipeline
10. Update `main.py`: fix imports for new paths
11. Delete root-level files that have been moved
12. Update `requirements.txt`
13. Smoke test: `python main.py --version`, `python main.py` → help, basic scan
