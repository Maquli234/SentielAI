"""
SentinelAI Extension — LLM Reasoning Module
============================================
Optional advanced reasoning layer. Offline-safe — SentinelAI works
fully without it.  Supports OpenAI, Ollama, HuggingFace, and raw HTTP.

Uses the same Anthropic API pattern already in assistant.py but adds:
  • Historical intelligence context from ScanMemoryDB
  • Pattern data from PatternRecognizer
  • Multiple backend support (not just Anthropic)

Usage:
    from intelligence.llm_reasoning import LLMReasoningModule
    m    = LLMReasoningModule(backend="ollama", model="llama3")
    recs = m.analyze(host_analysis, intel=pattern_recognizer.analyze())
"""
from __future__ import annotations
import json
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analyzer import HostAnalysis

_SYSTEM = (
    "You are a senior penetration tester. Analyse the provided scan results "
    "and historical intelligence. Produce a numbered list of the most relevant "
    "manual testing steps and likely attack vectors. Focus on reconnaissance and "
    "enumeration only — no automated exploitation."
)


def _build_prompt(ha: "HostAnalysis", intel: dict | None) -> str:
    host  = ha.host
    parts = [
        "=== Scan Results ===",
        f"Target      : {host.address}" + (f"  ({host.hostname})" if host.hostname else ""),
        f"OS          : {host.best_os.name + ' (' + str(host.best_os.accuracy) + '%)' if host.best_os else 'unknown'}",
        "Open Ports  :",
    ]
    for p in host.open_ports[:20]:
        parts.append(f"  {p.port}/{p.protocol}  {p.full_label}")

    crit_high = [f for f in ha.findings if f.severity in ("CRITICAL","HIGH")]
    if crit_high:
        parts.append("Key Findings:")
        for f in crit_high[:6]:
            parts.append(f"  [{f.severity}] {f.title}")

    if intel:
        parts.append("\n=== Historical Intelligence ===")
        if intel.get("frequent_services"):
            parts.append("Frequently seen services on this network: " +
                         str([x["service"] for x in intel["frequent_services"][:5]]))
        if intel.get("frequent_cves"):
            parts.append("Frequently seen CVEs: " +
                         str([x["cve"] for x in intel["frequent_cves"][:5]]))
        if intel.get("top_enum_hints"):
            parts.append("Historically effective techniques: " +
                         str(intel["top_enum_hints"][:5]))

    parts.append("\nAnalyse the above. Provide a prioritised numbered list of "
                 "penetration testing steps and attack vectors.")
    return "\n".join(parts)


def _parse(text: str) -> list[str]:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    numbered = [l for l in lines
                if len(l) > 2 and l[0].isdigit() and l[1] in ".):"]
    return numbered if numbered else lines[:20]


class LLMReasoningModule:
    """
    backend : "anthropic" | "openai" | "ollama" | "huggingface" | "http"
    api_key : required for anthropic/openai/huggingface
    model   : optional — sensible defaults per backend
    base_url: for ollama or custom HTTP endpoints
    """
    def __init__(self, backend: str = "anthropic", api_key: str = "",
                 model: str = "", base_url: str = ""):
        self.backend  = backend.lower()
        self.api_key  = api_key
        self.model    = model
        self.base_url = base_url

    def analyze(self, ha: "HostAnalysis",
                intel: dict | None = None) -> list[str]:
        prompt = _build_prompt(ha, intel)
        try:
            fn = {
                "anthropic":   self._anthropic,
                "openai":      self._openai,
                "ollama":      self._ollama,
                "huggingface": self._huggingface,
                "http":        self._raw_http,
            }.get(self.backend)
            if fn is None:
                return [f"[LLM] Unknown backend: {self.backend}"]
            return fn(prompt)
        except Exception as exc:
            return [f"[LLM] Error ({self.backend}): {exc}"]

    # ── Anthropic (matches existing assistant.py pattern) ────────────
    def _anthropic(self, prompt: str) -> list[str]:
        payload = json.dumps({
            "model": self.model or "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [{"role":"user","content": _SYSTEM + "\n\n" + prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=payload,
            headers={"Content-Type":"application/json",
                     "x-api-key": self.api_key,
                     "anthropic-version":"2023-06-01"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text","") for b in data.get("content",[])
                       if b.get("type")=="text")
        return _parse(text)

    # ── OpenAI ────────────────────────────────────────────────────────
    def _openai(self, prompt: str) -> list[str]:
        import openai  # type: ignore
        client = openai.OpenAI(api_key=self.api_key)
        resp = client.chat.completions.create(
            model=self.model or "gpt-4o-mini",
            messages=[{"role":"system","content":_SYSTEM},
                      {"role":"user","content":prompt}],
            max_tokens=1024, temperature=0.3)
        return _parse(resp.choices[0].message.content or "")

    # ── Ollama (local) ────────────────────────────────────────────────
    def _ollama(self, prompt: str) -> list[str]:
        url = self.base_url or "http://localhost:11434/api/chat"
        payload = json.dumps({
            "model": self.model or "llama3",
            "messages": [{"role":"system","content":_SYSTEM},
                         {"role":"user","content":prompt}],
            "stream": False,
        }).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return _parse(data.get("message",{}).get("content",""))

    # ── HuggingFace Inference API ─────────────────────────────────────
    def _huggingface(self, prompt: str) -> list[str]:
        model = self.model or "mistralai/Mistral-7B-Instruct-v0.2"
        url   = f"https://api-inference.huggingface.co/models/{model}"
        payload = json.dumps({"inputs": _SYSTEM + "\n" + prompt,
                              "parameters": {"max_new_tokens": 512}}).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type":"application/json",
                     "Authorization":f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        text = data[0].get("generated_text","") if isinstance(data,list) else ""
        return _parse(text)

    # ── Generic HTTP ──────────────────────────────────────────────────
    def _raw_http(self, prompt: str) -> list[str]:
        payload = json.dumps({"system": _SYSTEM, "prompt": prompt}).encode()
        req = urllib.request.Request(
            self.base_url, data=payload,
            headers={"Content-Type":"application/json",
                     "Authorization":f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return _parse(data.get("response", data.get("text","")))
