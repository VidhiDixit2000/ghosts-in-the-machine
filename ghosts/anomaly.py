"""The anomaly channel: find oddness, let the model name it.

The rules in rules.py encode what a failure looks like -- an empty .sql file, a
credential-shaped line. That only ever finds failures someone already met.

This module knows nothing about failures. It measures. A file's size collapsed.
A path vanished and came back. Two paths differ only in case. A large diff
arrived under a three-word commit message. None of those are failures; they are
just unusual.

The unusual commits go to the model, which says what -- if anything -- went
wrong. The measurements are bounded by what git can record. What the model can
name is not.

Additive by design: the concrete rules keep working whether this runs or not.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from ghosts.finding import Finding
from ghosts.ingest import CommitInfo
from ghosts.narrate import NarrateError, _api_key, _chat, _extract_json

RULE_ANOMALY = "A1-ANOMALY"

# How many of the oddest candidates to actually ask about.
MAX_CANDIDATES = 12

# Diff lines sent per candidate. Enough to judge, cheap enough to batch.
PATCH_LINES = 40

# Plain words for git's change letters, so the model cannot misread them.
_CHANGE_WORDS = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed"}

_CONTENT_EXTENSIONS = {
    ".sql", ".py", ".js", ".ts", ".json", ".yaml", ".yml",
    ".txt", ".md", ".toml", ".cfg", ".ini", ".lock", ".tsx", ".jsx",
}

_SKIP_DIRS = {"node_modules", "__pycache__", "dist", "build", ".git", "vendor"}


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def _skip(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(p in _SKIP_DIRS for p in parts)


def _patch_text(patch: Optional[bytes]) -> str:
    if not patch:
        return ""
    return patch.decode("utf-8", errors="replace")


def _added_removed(patch: Optional[bytes]) -> tuple[int, int]:
    text = _patch_text(patch)
    added = removed = 0
    for line in text.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def _score(commits: list[CommitInfo]) -> list[dict]:
    """Score every (commit, file) for how unusual it is. No notion of failure."""

    # Previous known size per path, and the full path history.
    last_size: dict[str, Optional[int]] = {}
    seen_paths: dict[str, int] = {}          # lowercase path -> first index seen
    original_case: dict[str, str] = {}
    deleted_at: dict[str, int] = {}

    candidates: list[dict] = []

    for i, c in enumerate(commits):
        patch_total = sum(len(_patch_text(d.patch).split("\n")) for d in c.diffs)
        short_message = len(c.message.split()) <= 3

        for d in c.diffs:
            if _skip(d.path):
                continue

            signals: list[str] = []
            score = 0.0

            prev = last_size.get(d.path)
            size = d.b_blob_size

            # 1. the file got much smaller than it was
            if d.change == "M" and prev and size is not None and prev > 200:
                ratio = size / prev
                if ratio < 0.25:
                    score += 3.0 * (1 - ratio)
                    signals.append(
                        f"size collapsed from {prev} to {size} bytes "
                        f"({int(ratio * 100)}% of what it was)"
                    )

            # 2. a file that should hold something holds almost nothing
            ext = os.path.splitext(d.path)[1].lower()
            if d.change in ("A", "M") and ext in _CONTENT_EXTENSIONS:
                if size is not None and size < 20:
                    score += 2.5
                    signals.append(f"resulting file is {size} bytes")

            # 3. a path that was deleted has come back
            if d.change == "A" and d.path in deleted_at:
                gap = i - deleted_at[d.path]
                score += 2.0
                signals.append(f"path was deleted {gap} commits earlier and is back")

            # 4. the same path, differing only in case
            lower = d.path.lower()
            if lower in seen_paths and original_case.get(lower) != d.path:
                score += 2.5
                signals.append(
                    f"path differs only in case from {original_case[lower]!r}, "
                    f"which git treats as a separate file"
                )

            # 5. a lot of change described by very little message
            added, removed = _added_removed(d.patch)
            if short_message and (added + removed) > 60:
                score += 1.5
                signals.append(
                    f'{added + removed} lines changed under the message '
                    f'"{c.message}"'
                )

            # 6. a change that is mostly deletion
            if d.change == "M" and removed > 30 and added < removed * 0.2:
                score += 1.5
                signals.append(f"{removed} lines removed, only {added} added")

            # bookkeeping
            if d.change == "D":
                deleted_at[d.path] = i
            else:
                last_size[d.path] = size
                seen_paths.setdefault(lower, i)
                original_case.setdefault(lower, d.path)

            if score > 0:
                candidates.append(
                    {
                        "commit_index": i,
                        "sha": c.sha,
                        "date": c.date,
                        "author": c.author,
                        "message": c.message,
                        "path": d.path,
                        "change": d.change,
                        "score": round(score, 2),
                        "signals": signals,
                        "patch": "\n".join(
                            _patch_text(d.patch).split("\n")[:PATCH_LINES]
                        ),
                    }
                )

    candidates.sort(key=lambda x: -x["score"])
    return candidates[:MAX_CANDIDATES]


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

_SYSTEM = (
    "You read git history and judge whether something broke without anyone "
    "noticing. You answer only in the JSON shape requested, with no commentary."
)

_PROMPT = """Below are commits flagged as unusual by measurements that know
nothing about what failures look like. They only noticed that something was
statistically odd: a file shrank, a path came back, a diff didn't match its
message.

Most of them will be nothing. Deliberate deletions, refactors, cleanups,
generated files. That is expected and you should say so.

For each candidate, decide: did something break here WITHOUT producing an error
at the time? That is the only question. A loud failure is not interesting. A
deliberate change is not interesting. You are looking for the case where what
someone evidently intended and what git recorded came apart, quietly.

Return ONLY a JSON array, one object per candidate, in the same order:

[{{"index":0,"is_failure":true,"name":"short name for what went wrong","confidence":7,"why":"one sentence, grounded in the evidence"}}]

Rules:
- is_failure false for anything deliberate or routine. Be strict. Most should
  be false.
- confidence 1-10, only meaningful when is_failure is true.
- name it in plain words. Do not invent a category; describe what happened.
- A commit is a snapshot, not a sequence. All changes listed for one commit
  happened together, atomically. There is no order between them: nothing in a
  commit happens before or after anything else in that same commit. When
  several changes share a commit, describe them as simultaneous. Use "in the
  same commit", "alongside", "together with". Do not use "after", "then",
  "following", "subsequently", or "immediately" to relate two changes within
  one commit. Those words are only correct between different commits, and
  only when you have both dates.
- changes_in_this_commit_unordered is an unordered snapshot: this file's part
  of the commit, possibly cut short, and not necessarily all of it. Other
  files from the same commit may appear as separate candidates. The order of
  files, candidates and diff lines says nothing about time.
- Describe only what the diff and the commit message show. Do not speculate
  about motive, cause, or consequence.
- Never guess at a redacted value.

CANDIDATES:
{candidates}
"""

_RETRY = (
    "Your previous reply was not valid JSON. Return ONLY a JSON array, "
    "starting with [ and ending with ]. No fences, no prose."
)


def _ask(candidates: list[dict], key: str) -> list[dict]:
    payload = [
        {
            "index": i,
            "file": c["path"],
            "what_happened": (
                f"In this commit, {c['path']} was "
                f"{_CHANGE_WORDS.get(c['change'], c['change'])}."
            ),
            "commit_message": c["message"],
            "date": c["date"],
            "why_flagged": c["signals"],
            "changes_in_this_commit_unordered": c["patch"],
        }
        for i, c in enumerate(candidates)
    ]
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": _PROMPT.format(
            candidates=json.dumps(payload, indent=1)[:40000]
        )},
    ]
    reply = _chat(key, messages, max_tokens=1600, temperature=0.1)
    try:
        parsed = _extract_json(reply)
    except NarrateError:
        messages.append({"role": "assistant", "content": reply})
        messages.append({"role": "user", "content": _RETRY})
        parsed = _extract_json(_chat(key, messages, max_tokens=1600, temperature=0.1))

    if isinstance(parsed, dict):
        parsed = parsed.get("results", [])
    return [v for v in parsed if isinstance(v, dict)] if isinstance(parsed, list) else []


# ---------------------------------------------------------------------------

def find_anomalies(
    commits: list[CommitInfo],
    *,
    api_key: Optional[str] = None,
    min_confidence: int = 6,
    verbose: bool = True,
) -> tuple[list[Finding], dict]:
    """Measure oddness, ask the model what it means, return Findings.

    Never raises. On any failure returns ([], meta-with-warning) so the
    concrete rules are unaffected.
    """
    meta: dict[str, Any] = {
        "candidates_scored": 0,
        "candidates_sent": 0,
        "named_as_failures": 0,
        "warning": None,
    }

    candidates = _score(commits)
    meta["candidates_scored"] = len(candidates)
    if not candidates:
        return [], meta

    key = _api_key(api_key)
    if not key:
        meta["warning"] = "No API key; anomaly channel skipped."
        if verbose:
            print(f"  ! {meta['warning']}")
        return [], meta

    meta["candidates_sent"] = len(candidates)
    if verbose:
        print(f"  Asking the model about {len(candidates)} unusual commits ...")

    try:
        verdicts = _ask(candidates, key)
    except NarrateError as exc:
        meta["warning"] = f"Anomaly channel failed: {exc}"
        if verbose:
            print(f"  ! {meta['warning']}")
        return [], meta

    findings: list[Finding] = []
    for v in verdicts:
        try:
            idx = int(v.get("index", -1))
        except (TypeError, ValueError):
            continue
        if not (0 <= idx < len(candidates)):
            continue
        if not v.get("is_failure"):
            continue
        try:
            confidence = max(1, min(10, int(v.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0
        if confidence < min_confidence:
            continue

        c = candidates[idx]
        name = str(v.get("name") or "Something broke quietly").strip()
        why = str(v.get("why") or "").strip()

        findings.append(
            Finding(
                rule_id=RULE_ANOMALY,
                commit_sha=c["sha"],
                date=c["date"],
                author=c["author"],
                file_path=c["path"],
                summary=f"{name}. {why}".strip(),
                evidence={
                    "commit_message": c["message"],
                    "change_type": c["change"],
                    "anomaly_score": c["score"],
                    "signals": c["signals"],
                    "named_by_model": True,
                    "model_confidence": confidence,
                },
            )
        )

    meta["named_as_failures"] = len(findings)
    return findings, meta