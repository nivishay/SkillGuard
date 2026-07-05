"""SkillGuard flow tester — a local web app to watch a scan flow through the engine.

This is a developer/tester tool, deliberately kept OUT of the shipped ``src/skillguard``
package (the engine-only MVP has no UI surface). It imports the real engine and drives its
stages one at a time, streaming an event per stage over Server-Sent Events so a tester can
watch a Skill go in and see the Verdict come out:

    Load Skill  ->  Static Pass (findings stream in)  ->  LLM Judgment  ->  Verdict

The combine step reuses :func:`skillguard.engine.combine_verdict`, so what you watch is
exactly what ``DetectionEngine.analyze`` produces — no duplicated logic.

Run it::

    # real scans — needs ANTHROPIC_API_KEY
    python devtools/tester.py

    # no network/key — Static Pass only, LLM stubbed
    python devtools/tester.py --offline

Then open http://localhost:8000. Point it at any Skill folder, or pick one from the
bundled eval corpus in the dropdown.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from skillguard.engine import combine_verdict  # noqa: E402
from skillguard.engine.llm.port import LLMJudgment  # noqa: E402
from skillguard.engine.static_pass import static_pass  # noqa: E402
from skillguard.loader import SkillLoadError, load_skill  # noqa: E402
from skillguard.models import Finding, Skill, Tier  # noqa: E402

_HTML = (Path(__file__).resolve().parent / "index.html").read_text(encoding="utf-8")
_CORPUS = _ROOT / "evals" / "corpus"

# Small delay between stages so the flow is watchable even when the Static Pass is instant.
# It only paces the *reveal*; the elapsed times reported per stage are the real measured
# durations, so this never misrepresents performance.
_PACE_SECONDS = 0.35


class _OfflineJudge:
    """Stub LLM so the tester runs with no network/key: only the Static Pass contributes."""

    def judge(self, skill: Skill, static_findings: tuple[Finding, ...]) -> LLMJudgment:
        return LLMJudgment(tier=Tier.CLEAN, explanation="(offline: LLM Judgment stubbed)")


def _finding_json(f: Finding) -> dict[str, object]:
    return {
        "vector": str(f.vector),
        "explanation": f.explanation,
        "file": f.location.file,
        "line": f.location.line,
    }


def scan_events(folder: str, offline: bool) -> Iterator[dict[str, object]]:
    """Yield one event dict per stage of a real scan of ``folder``."""
    started = time.perf_counter()

    yield {"stage": "loader", "status": "start"}
    try:
        t0 = time.perf_counter()
        skill = load_skill(folder)
    except SkillLoadError as exc:
        yield {"stage": "error", "message": str(exc)}
        return
    yield {
        "stage": "loader",
        "status": "done",
        "files": [f.path for f in skill.files],
        "elapsed": round(time.perf_counter() - t0, 3),
    }

    time.sleep(_PACE_SECONDS)
    yield {"stage": "static", "status": "start"}
    t0 = time.perf_counter()
    static_findings = static_pass(skill)
    for f in static_findings:
        yield {"stage": "static", "status": "finding", "finding": _finding_json(f)}
    yield {
        "stage": "static",
        "status": "done",
        "count": len(static_findings),
        "elapsed": round(time.perf_counter() - t0, 3),
    }

    time.sleep(_PACE_SECONDS)
    judge = _OfflineJudge() if offline else _real_judge()
    yield {"stage": "llm", "status": "start", "offline": offline}
    t0 = time.perf_counter()
    try:
        judgment = judge.judge(skill, static_findings)
    except Exception as exc:  # noqa: BLE001 - surface any LLM failure to the UI
        yield {"stage": "error", "message": str(exc)}
        return
    yield {
        "stage": "llm",
        "status": "done",
        "tier": str(judgment.tier),
        "explanation": judgment.explanation,
        "findings": [_finding_json(f) for f in judgment.findings],
        "elapsed": round(time.perf_counter() - t0, 3),
    }

    time.sleep(_PACE_SECONDS)
    verdict = combine_verdict(static_findings, judgment)
    yield {
        "stage": "verdict",
        "status": "done",
        "tier": str(verdict.tier),
        "findings": [_finding_json(f) for f in verdict.findings],
        "elapsed": round(time.perf_counter() - started, 3),
    }


def _real_judge() -> object:
    from skillguard.engine.llm.anthropic_judge import AnthropicJudge

    return AnthropicJudge()


def _discover_corpus() -> list[dict[str, str]]:
    """List bundled corpus Skills for the dropdown (label + absolute path)."""
    skills: list[dict[str, str]] = []
    for skill_md in sorted(_CORPUS.rglob("SKILL.md")):
        rel = skill_md.parent.relative_to(_CORPUS)
        skills.append({"label": rel.as_posix(), "path": str(skill_md.parent)})
    return skills


class _Handler(BaseHTTPRequestHandler):
    offline = False

    def log_message(self, *args: object) -> None:  # quiet the default request logging
        pass

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, _HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif parsed.path == "/skills":
            body = json.dumps(_discover_corpus()).encode("utf-8")
            self._send(200, body, "application/json")
        elif parsed.path == "/scan":
            self._stream_scan(parse_qs(parsed.query))
        else:
            self._send(404, b"not found", "text/plain")

    def _stream_scan(self, query: dict[str, list[str]]) -> None:
        folder = (query.get("folder") or [""])[0]
        offline = self.offline or (query.get("mode") or [""])[0] == "offline"
        if not folder:
            self._send(400, b"missing folder", "text/plain")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            for event in scan_events(folder, offline):
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
            self.wfile.write(b"data: {\"stage\": \"end\"}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # tester closed the tab mid-scan


def main() -> int:
    parser = argparse.ArgumentParser(description="SkillGuard scan flow tester (local web UI)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="stub the LLM (Static Pass only) — no network or API key needed",
    )
    args = parser.parse_args()

    _Handler.offline = args.offline
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    mode = "OFFLINE (Static Pass only)" if args.offline else "LIVE (real model)"
    print(f"SkillGuard tester [{mode}] -> http://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
