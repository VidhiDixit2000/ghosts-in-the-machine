"""Model layer: group the findings, rank them, and narrate the significant ones.

Deliberately separate from detection. The rules answer "what suspicious things
happened?" -- a question regular expressions are good at. This module answers
"which of these matter, which are the same story, and how do I explain them to
a person?" -- a question they are useless at.

Nothing here edits a Finding. Interpretation travels alongside the raw facts so
a reader can always tell which is which.

Open-weight model only (Gemma, via OpenRouter's hosted inference).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from ghosts.finding import Finding

API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it" 
ENV_VARS = ("OPENROUTER_API_KEY", "GEMMA_API_KEY")

# Groups scoring at or above this get narrated. Everything else is kept and
# reported with its score, so you can see what the model dismissed.
DEFAULT_THRESHOLD = 6

# Findings per grouping call. Small repos never hit this.
BATCH_SIZE = 40


class NarrateError(Exception):
    """A narration problem that must not abort the scan."""


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _api_key(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    for var in ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return None


def _chat(key: str, messages: list[dict], *, max_tokens: int = 1200,
          temperature: float = 0.1, attempts: int = 3) -> str:
    payload = json.dumps(
        {
            "model": MODEL,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
    ).encode("utf-8")

    last_error: Any = None
    for attempt in range(attempts):
        request = urllib.request.Request(
            API_URL,
            data=payload,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                body = json.loads(response.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            if exc.code == 429 or 500 <= exc.code < 600:
                time.sleep(min(2 ** attempt * 2, 20))
                last_error = f"HTTP {exc.code}"
                continue
            raise NarrateError(f"API returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            time.sleep(min(2 ** attempt, 8))
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise NarrateError(f"Unexpected API response shape: {exc}") from exc

    raise NarrateError(f"API unreachable after {attempts} attempts ({last_error})")


def _extract_json(text: str) -> Any:
    """Pull a JSON value out of a model reply that may be fenced or chatty."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start = cleaned.find(opener)
        end = cleaned.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise NarrateError("No JSON found in model reply")


# ---------------------------------------------------------------------------
# Pass one: group and rank
# ---------------------------------------------------------------------------

_GROUP_SYSTEM = (
    "You are a software archaeologist reading the history of a code repository. "
    "You answer only in the JSON shape you are asked for, with no commentary."
)

_GROUP_PROMPT = """Below are findings from a scan of a repository's git history.
Each one is a fact recorded from the repository: a rule that fired, a commit, a
date, a file, and evidence. Credentials are already redacted; never try to guess
or reconstruct a redacted value.

Your job has two parts.

FIRST, group findings that are the same underlying story. Several findings often
describe one event -- for example the same password appearing in three files in a
single commit is one story, not three.

SECOND, score each group 1-10 for how much it would matter to someone who just
inherited this repository:

  9-10  a credential still present, or a file that stayed empty for weeks or months
  7-8   a credential removed from the working tree but still in history
  5-6   suspicious, but plausibly deliberate
  1-4   noise, or a work-in-progress fixed almost immediately

Score honestly. Low scores are useful -- do not inflate something to make it
interesting, and do not drop anything.

Return ONLY a JSON array, no prose:

[{{"group_id":"g1","title":"short title","significance":8,"reason":"one line","finding_indices":[0,2]}}]

Every index below must appear in exactly one group.

FINDINGS:
{findings}
"""

_GROUP_RETRY = (
    "Your previous reply was not valid JSON. Return ONLY a JSON array matching "
    "the shape requested, starting with [ and ending with ]. No fences, no prose."
)


def _compact(findings: list[Finding], offset: int = 0) -> str:
    rows = []
    for i, f in enumerate(findings):
        rows.append(
            {
                "index": offset + i,
                "rule_id": f.rule_id,
                "date": f.date,
                "file": f.file_path,
                "summary": f.summary,
                "evidence": f.evidence,
            }
        )
    return json.dumps(rows, indent=1)


def _group(findings: list[Finding], key: str) -> list[dict]:
    groups: list[dict] = []

    for start in range(0, len(findings), BATCH_SIZE):
        batch = findings[start:start + BATCH_SIZE]
        prompt = _GROUP_PROMPT.format(findings=_compact(batch, offset=start))
        messages = [
            {"role": "system", "content": _GROUP_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        reply = _chat(key, messages)
        try:
            parsed = _extract_json(reply)
        except NarrateError:
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": _GROUP_RETRY})
            parsed = _extract_json(_chat(key, messages))

        if isinstance(parsed, dict):
            parsed = parsed.get("groups", [])
        if isinstance(parsed, list):
            groups.extend(g for g in parsed if isinstance(g, dict))

    return _repair(groups, len(findings))


def _repair(groups: list[dict], total: int) -> list[dict]:
    """Make sure every finding is accounted for exactly once."""
    seen: set[int] = set()
    cleaned: list[dict] = []

    for i, group in enumerate(groups):
        indices = [
            n for n in group.get("finding_indices", [])
            if isinstance(n, int) and 0 <= n < total and n not in seen
        ]
        if not indices:
            continue
        seen.update(indices)
        cleaned.append(
            {
                "group_id": group.get("group_id") or f"g{i + 1}",
                "title": group.get("title") or "Untitled",
                "significance": _clamp(group.get("significance")),
                "reason": group.get("reason") or "",
                "finding_indices": indices,
            }
        )

    missing = [n for n in range(total) if n not in seen]
    if missing:
        cleaned.append(
            {
                "group_id": f"g{len(cleaned) + 1}",
                "title": "Ungrouped findings",
                "significance": 5,
                "reason": "The model did not place these; kept so nothing is lost.",
                "finding_indices": missing,
            }
        )
    return cleaned


def _clamp(value: Any) -> int:
    try:
        return max(1, min(10, int(value)))
    except (TypeError, ValueError):
        return 5


# ---------------------------------------------------------------------------
# Pass two: narrate
# ---------------------------------------------------------------------------

_NARRATE_SYSTEM = (
    "You write short, precise accounts of how software broke. You are plain "
    "and specific, never florid. You never invent a detail that is not in the "
    "evidence you were given."
)

_NARRATE_PROMPT = """Write a short account of this finding for someone who has
just inherited this repository and is reading its history for the first time.
 
Two or three short paragraphs.
 
FIRST, find where what someone evidently intended and what git actually
recorded came apart. That gap is the story. It is also why the failure was
silent: the person had every reason to believe things had gone the other way,
so there was nothing to investigate.
 
Illustrations of the shape, not a list to match against -- the gap in the
evidence below may look like none of these:
 
  - a credential commented out rather than deleted (intended: removed;
    recorded: still present)
  - a file committed empty and filled much later (intended: content;
    recorded: nothing, for however long)
  - a commit message describing something the commit did not do
 
Open with whatever that gap turns out to be, concretely.
 
THEN say what it cost, or could have cost, for this repository specifically.
If the evidence does not support a claim about cost, write nothing about cost.
Do not write a sentence observing that the evidence is silent.
 
RULES, all firm:
 
  - Every sentence must carry a fact from the evidence below. If a sentence
    would be equally true of any repository, cut it.
  - Banned, because they carry no information: "could have allowed
    unauthorized access", "poses a potential security risk", "is not specified
    in the available evidence", "sensitive information", "best practice".
  - Do not restate the finding summary. The reader already has it.
  - Do not speculate about why the author did it.
  - Credentials are redacted. Never guess at a redacted value.
  - Plain language. The subject is eerie without help -- no theatrical
    phrasing, no "ghostly", no second person address.
 
Return plain text only, no JSON and no headings.
 
TITLE: {title}
 
EVIDENCE:
{findings}
"""
 
def _narrate_group(group: dict, findings: list[Finding], key: str) -> str:
    members = [findings[i] for i in group["finding_indices"]]
    prompt = _NARRATE_PROMPT.format(
        title=group["title"],
        findings=_compact(members),
    )
    reply = _chat(
        key,
        [
            {"role": "system", "content": _NARRATE_SYSTEM},
            {"role": "user", "content": prompt},
        ],
        max_tokens=700,
        temperature=0.1,
    )
    return reply.strip()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def narrate(
    findings: list[Finding],
    *,
    api_key: Optional[str] = None,
    threshold: int = DEFAULT_THRESHOLD,
    verbose: bool = True,
) -> dict:
    """Group, rank and narrate. Never raises -- degrades instead.

    Returns an interpretation block. On any failure it returns one carrying a
    ``warning`` and no groups, so the caller can still write out the findings.
    """
    base = {
        "model": MODEL,
        "provider": "openrouter",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "threshold": threshold,
        "groups": [],
        "warning": None,
    }

    if not findings:
        base["warning"] = "No findings to interpret."
        return base

    key = _api_key(api_key)
    if not key:
        base["warning"] = (
            "No API key found. Set " + " or ".join(ENV_VARS)
            + " to enable narration. Findings were written without it."
        )
        if verbose:
            print(f"  ! {base['warning']}")
        return base

    try:
        if verbose:
            print(f"  Grouping {len(findings)} findings with {MODEL} ...")
        groups = _group(findings, key)
    except NarrateError as exc:
        base["warning"] = f"Grouping failed: {exc}"
        if verbose:
            print(f"  ! {base['warning']}")
        return base

    for group in groups:
        group["findings"] = [findings[i].to_dict() for i in group["finding_indices"]]
        if group["significance"] < threshold:
            group["narration"] = None
            group["narration_skipped"] = (
                f"Scored {group['significance']}, below the threshold of {threshold}."
            )
            continue
        try:
            if verbose:
                print(f"  Narrating {group['group_id']}: {group['title']}")
            group["narration"] = _narrate_group(group, findings, key)
            group["narration_skipped"] = None
        except NarrateError as exc:
            group["narration"] = None
            group["narration_skipped"] = f"Narration failed: {exc}"

    groups.sort(key=lambda g: -g["significance"])
    base["groups"] = groups
    return base


def print_interpretation(interpretation: dict) -> None:
    """Human-readable dump of what the model made of the findings."""
    if interpretation.get("warning"):
        print(f"\n! {interpretation['warning']}")
        return

    groups = interpretation.get("groups", [])
    if not groups:
        print("\nThe model returned no groups.")
        return

    print(f"\n{len(groups)} group{'' if len(groups) == 1 else 's'} "
          f"(model: {interpretation['model']}):\n")

    for group in groups:
        print(f"  [{group['significance']}/10]  {group['title']}")
        print(f"      {group['reason']}")
        print(f"      findings: {', '.join(str(i) for i in group['finding_indices'])}")
        if group.get("narration"):
            print()
            for line in group["narration"].split("\n"):
                print(f"      {line}" if line.strip() else "")
        elif group.get("narration_skipped"):
            print(f"      ({group['narration_skipped']})")
        print()