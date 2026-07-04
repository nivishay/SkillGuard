"""SkillGuard eval harness — measure detection accuracy against the real model.

This is a *measurement*, not a pass/fail test. It drives every Skill in the corpus through
``DetectionEngine.analyze`` and scores:

- **detection rate** — fraction of malicious Skills the engine flags as non-Clean,
- **false-positive rate** — fraction of clean Skills the engine wrongly flags as non-Clean,
- **per-scan latency** — so we can confirm a scan finishes in a reasonable time,
- **vector attribution** — whether each malicious catch names its expected Threat Vector.

It is kept out of the deterministic pytest suite on purpose: it calls the real, non-
deterministic model, so its output is a score to track over time, not an assertion.

Corpus layout (folders containing a ``SKILL.md``)::

    evals/corpus/clean/**/                       expected Clean
    evals/corpus/malicious/<vector>/**/          expected non-Clean, naming <vector>

where ``<vector>`` is one of ``prompt_injection``, ``bundled_code``, ``obfuscation``,
``analyzer_manipulation``.

Usage::

    # real run — needs ANTHROPIC_API_KEY (optionally SKILLGUARD_MODEL)
    python evals/run_eval.py

    # plumbing check without network: uses a stub LLM, so only the Static Pass contributes
    python evals/run_eval.py --offline
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# Allow running as a plain script (`python evals/run_eval.py`) without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from skillguard.engine import DetectionEngine  # noqa: E402
from skillguard.engine.llm.port import LLMJudge, LLMJudgment  # noqa: E402
from skillguard.loader import load_skill  # noqa: E402
from skillguard.models import Finding, Skill, ThreatVector, Tier  # noqa: E402

CORPUS_ROOT = Path(__file__).resolve().parent / "corpus"

# Maps a malicious corpus subfolder name to the Threat Vector it should be caught as.
_VECTOR_DIRS = {
    "prompt_injection": ThreatVector.PROMPT_INJECTION,
    "bundled_code": ThreatVector.MALICIOUS_BUNDLED_CODE,
    "obfuscation": ThreatVector.SECOND_STAGE_OBFUSCATION,
    # Analyzer-manipulation is recorded as a Prompt Injection finding (ADR 0002).
    "analyzer_manipulation": ThreatVector.PROMPT_INJECTION,
}


class _OfflineJudge:
    """Stub LLM for ``--offline`` plumbing checks: contributes nothing, so only the Static
    Pass drives the verdict. Lets the harness run end-to-end with no network or API key."""

    def judge(self, skill: Skill, static_findings: tuple[Finding, ...]) -> LLMJudgment:
        return LLMJudgment(tier=Tier.CLEAN)


@dataclass
class Case:
    """One corpus Skill and what we expect of it."""

    path: Path
    label: str  # "clean" or "malicious"
    expected_vector: ThreatVector | None  # only for malicious cases


@dataclass
class Result:
    case: Case
    tier: Tier
    vectors: set[ThreatVector]
    seconds: float
    error: str | None = None

    @property
    def flagged(self) -> bool:
        return self.tier is not Tier.CLEAN

    @property
    def correct(self) -> bool:
        if self.error is not None:
            return False
        if self.case.label == "clean":
            return not self.flagged
        # malicious: must be flagged and name the expected vector
        return self.flagged and self.case.expected_vector in self.vectors


def _skill_dirs(root: Path) -> Iterator[Path]:
    if not root.exists():
        return
    for skill_md in sorted(root.rglob("SKILL.md")):
        yield skill_md.parent


def discover_cases() -> list[Case]:
    cases: list[Case] = []
    for path in _skill_dirs(CORPUS_ROOT / "clean"):
        cases.append(Case(path=path, label="clean", expected_vector=None))
    for dir_name, vector in _VECTOR_DIRS.items():
        for path in _skill_dirs(CORPUS_ROOT / "malicious" / dir_name):
            cases.append(Case(path=path, label="malicious", expected_vector=vector))
    return cases


def run_case(engine: DetectionEngine, case: Case) -> Result:
    started = time.perf_counter()
    try:
        skill = load_skill(case.path)
        verdict = engine.analyze(skill)
    except Exception as exc:  # noqa: BLE001 - a scan failure is a data point, not a crash
        return Result(case, Tier.CLEAN, set(), time.perf_counter() - started, error=str(exc))
    return Result(
        case=case,
        tier=verdict.tier,
        vectors={f.vector for f in verdict.findings},
        seconds=time.perf_counter() - started,
    )


def _rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.0%} ({numerator}/{denominator})"


def report(results: list[Result]) -> None:
    clean = [r for r in results if r.case.label == "clean"]
    malicious = [r for r in results if r.case.label == "malicious"]

    caught = [r for r in malicious if r.correct]
    misses = [r for r in malicious if not r.correct]
    false_positives = [r for r in clean if r.flagged or r.error]

    name_width = max((len(r.case.path.name) for r in results), default=10)
    print("\nPer-Skill results")
    print("-" * (name_width + 34))
    for r in sorted(results, key=lambda x: (x.case.label, x.case.path.name)):
        mark = "ok " if r.correct else "XX "
        note = f" !{r.error}" if r.error else ""
        vecs = ", ".join(sorted(str(v) for v in r.vectors)) or "-"
        print(
            f"{mark}{r.case.path.name:<{name_width}}  {r.case.label:<9} "
            f"{str(r.tier):<10} {r.seconds:5.2f}s  [{vecs}]{note}"
        )

    latencies = [r.seconds for r in results]
    avg = sum(latencies) / len(latencies) if latencies else 0.0
    print("\nSummary")
    print("-" * 40)
    print(f"  Skills scanned    : {len(results)}")
    print(f"  Detection rate    : {_rate(len(caught), len(malicious))}")
    print(f"  False-positive rate: {_rate(len(false_positives), len(clean))}")
    print(f"  Latency           : avg {avg:.2f}s, max {max(latencies, default=0.0):.2f}s")
    if misses:
        print(f"  Missed malicious  : {', '.join(r.case.path.name for r in misses)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="SkillGuard detection-accuracy eval")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use a stub LLM (Static Pass only) — no network or API key needed",
    )
    args = parser.parse_args()

    if args.offline:
        judge: LLMJudge = _OfflineJudge()
        print("Running eval OFFLINE (Static Pass only; LLM stubbed).")
    else:
        from skillguard.engine.llm.anthropic_judge import AnthropicJudge

        judge = AnthropicJudge()
        print("Running eval against the real model (needs ANTHROPIC_API_KEY).")

    engine = DetectionEngine(judge=judge)
    cases = discover_cases()
    if not cases:
        print(f"No Skills found under {CORPUS_ROOT}.", file=sys.stderr)
        return 1

    results = [run_case(engine, case) for case in cases]
    report(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
