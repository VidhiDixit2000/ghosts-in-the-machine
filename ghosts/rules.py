"""Two concrete detection rules.

No plugin registry and no shared rule interface -- just two functions that turn
ingest output into :class:`ghosts.finding.Finding` objects. The common shape
can be extracted later, once it is clear what the rules genuinely share.

Both rules look for the same thing from different angles: a change that
produced no error at the time, and so went unnoticed.
"""

from __future__ import annotations

import os
import re
from datetime import date
from typing import Any, Iterator, Optional

from ghosts.finding import Finding
from ghosts.ingest import CommitInfo

# Git's canonical empty blob. Seeing it as a resulting blob is a direct signal.
EMPTY_BLOB_SHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

# Don't read blobs larger than this when checking for whitespace-only content.
_BLANK_CHECK_LIMIT = 10_000_000


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_CONTENT_EXTENSIONS = {
    ".sql", ".py", ".js", ".ts", ".json", ".yaml", ".yml",
    ".txt", ".md", ".toml", ".cfg", ".ini",
}

_LEGITIMATELY_EMPTY = {"__init__.py", ".gitkeep", ".gitignore", "py.typed"}

_EXCLUDED_DIRS = {"test", "tests", "fixtures", "__pycache__"}


def _is_excluded_path(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    if parts[-1] in _LEGITIMATELY_EMPTY:
        return True
    return any(p in _EXCLUDED_DIRS for p in parts)


def _has_content_extension(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in _CONTENT_EXTENSIONS


def _blob_bytes(blob: Any) -> bytes:
    if blob is None:
        return b""
    try:
        return blob.data_stream.read()
    except Exception:
        return b""


def _is_blank(content: bytes) -> bool:
    return content.strip() == b""


def _blob_is_blank(blob_sha: Optional[str], size: Optional[int], blob: Any) -> bool:
    """True when this blob holds nothing but whitespace (or nothing at all)."""
    if blob_sha == EMPTY_BLOB_SHA:
        return True
    if size is None:
        return False
    if size == 0:
        return True
    if size > _BLANK_CHECK_LIMIT:
        return False  # too big to be whitespace in practice
    return _is_blank(_blob_bytes(blob))


def _head_file_bytes(repo: Any, path: str) -> Optional[bytes]:
    """Content of ``path`` at HEAD, or None when the file is not there."""
    try:
        node = repo.head.commit.tree
        parts = [p for p in path.split("/") if p]
        for part in parts[:-1]:
            node = node[part]
        obj = node[parts[-1]]
        return obj.data_stream.read()
    except Exception:
        return None


def _days_between(earlier: str, later: str) -> Optional[int]:
    try:
        return (date.fromisoformat(later) - date.fromisoformat(earlier)).days
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Rule one -- a file committed empty
# ---------------------------------------------------------------------------
#
# The interesting part is not that a file was empty. It is how long it stayed
# that way. A file empty for one commit is a work-in-progress; a file empty for
# two months is something nobody noticed.

RULE_EMPTY_FILE = "R1-EMPTY-FILE"


def _build_timeline(commits: list[CommitInfo]) -> dict[str, list[tuple]]:
    """path -> [(index, date, blob_sha, size, blob)], in commit order."""
    timeline: dict[str, list[tuple]] = {}
    for i, c in enumerate(commits):
        for d in c.diffs:
            if d.change == "D":
                continue
            timeline.setdefault(d.path, []).append(
                (i, c.date, d.b_blob_sha, d.b_blob_size, d.b_blob)
            )
    return timeline


def _first_fill(entries: list[tuple], after_index: int) -> Optional[tuple]:
    """First later entry where the file actually has content."""
    for i, cdate, sha, size, blob in entries:
        if i <= after_index:
            continue
        if not _blob_is_blank(sha, size, blob):
            return (i, cdate, sha)
    return None


def rule_empty_files(commits: list[CommitInfo], repo: Any) -> list[Finding]:
    timeline = _build_timeline(commits)
    findings: list[Finding] = []
    seen_paths: set[str] = set()

    for i, c in enumerate(commits):
        for d in c.diffs:
            if d.change not in ("A", "M", "R"):
                continue
            if not _has_content_extension(d.path):
                continue
            if _is_excluded_path(d.path):
                continue
            if not _blob_is_blank(d.b_blob_sha, d.b_blob_size, d.b_blob):
                continue

            fill = _first_fill(timeline.get(d.path, []), i)

            if fill is not None:
                _, fill_date, fill_sha = fill
                days = _days_between(c.date, fill_date)
                still_empty = False
                summary = (
                    f"{d.path} was committed empty and stayed empty for "
                    f"{days} day{'' if days == 1 else 's'} before it was filled."
                )
            else:
                fill_date = fill_sha = None
                days = None
                head = _head_file_bytes(repo, d.path)
                if head is None:
                    still_empty = False
                    summary = (
                        f"{d.path} was committed empty and the file no longer "
                        f"exists at HEAD."
                    )
                else:
                    still_empty = _is_blank(head)
                    summary = (
                        f"{d.path} was committed empty and is still empty at HEAD."
                        if still_empty
                        else f"{d.path} was committed empty."
                    )

            findings.append(
                Finding(
                    rule_id=RULE_EMPTY_FILE,
                    commit_sha=c.sha,
                    date=c.date,
                    author=c.author,
                    file_path=d.path,
                    summary=summary,
                    evidence={
                        "commit_message": c.message,
                        "change_type": d.change,
                        "blob_sha": d.b_blob_sha,
                        "blob_size": d.b_blob_size,
                        "days_until_filled": days,
                        "filled_in_commit": fill_sha,
                        "filled_on": fill_date,
                        "still_empty_at_head": still_empty,
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Rule two -- a credential-shaped value entering the tree
# ---------------------------------------------------------------------------
#
# Commented-out lines are scanned deliberately. Commenting a credential out
# feels like removing it, and git does not care -- the value is in history
# either way. That case is the point of this rule, not an edge of it.

RULE_DB_URI = "R2-DB-URI-CREDENTIALS"
RULE_AWS_KEY = "R2-AWS-ACCESS-KEY"
RULE_ASSIGNMENT = "R2-SECRET-ASSIGNMENT"
RULE_ENV_FILE = "R2-ENV-FILE-ADDED"

_URI_RE = re.compile(
    r"(?P<scheme>postgres|postgresql|mysql|mongodb|redis)://"
    r"(?P<user>[^:@/\s]+):(?P<password>[^@/\s]+)@",
    re.IGNORECASE,
)

_AWS_KEY_RE = re.compile(
    r"\b(?P<key>(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b"
)

_ASSIGN_RE = re.compile(
    r"(?P<name>password|passwd|secret|token|api[_-]?key|apikey)"
    r"\s*[:=]\s*"
    r"[\"']?(?P<value>[^\s,;}\"']+)[\"']?",
    re.IGNORECASE,
)

_PLACEHOLDER_TOKENS = {"your", "changeme", "xxx", "example", "dummy", "placeholder", "redacted"}


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    if "{{" in v or "}}" in v or "${" in v:
        return True
    if "***" in v:
        return True
    if "(" in v:  # os.getenv(...), env("..."), etc -- not a literal
        return True
    for token in re.split(r"[\s_\-:.=/]+", v.lower()):
        if token in _PLACEHOLDER_TOKENS:
            return True
    return False


def _match_secrets(line: str) -> list[tuple[str, list[tuple[int, int]]]]:
    """(rule_id, spans-to-redact) for every credential pattern in ``line``."""
    hits: list[tuple[str, list[tuple[int, int]]]] = []

    for m in _URI_RE.finditer(line):
        if _is_placeholder(m.group("password")):
            continue
        hits.append((RULE_DB_URI, [m.span("password")]))

    for m in _AWS_KEY_RE.finditer(line):
        hits.append((RULE_AWS_KEY, [m.span("key")]))

    for m in _ASSIGN_RE.finditer(line):
        if _is_placeholder(m.group("value")):
            continue
        hits.append((RULE_ASSIGNMENT, [m.span("value")]))

    return hits


def _redact(line: str, spans: list[tuple[int, int]]) -> str:
    """Replace each span with [REDACTED], keeping everything around it."""
    out: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor:
            continue
        out.append(line[cursor:start])
        out.append("[REDACTED]")
        cursor = end
    out.append(line[cursor:])
    return "".join(out).rstrip()


def _iter_added_lines(patch: Optional[bytes]) -> Iterator[tuple[int, str]]:
    """Yield (line number in the new file, text) for added lines."""
    if not patch:
        return
    text = patch.decode("utf-8", errors="replace")
    new_no = 0
    in_hunk = False
    for raw in text.split("\n"):
        if raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            if m:
                new_no = int(m.group(1))
                in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        if raw.startswith("\\"):  # "\ No newline at end of file"
            continue
        if raw.startswith("+"):
            yield new_no, raw[1:]
            new_no += 1
        elif raw.startswith("-"):
            continue
        else:
            new_no += 1


def _is_env_file(path: str) -> bool:
    base = os.path.basename(path)
    if base == ".env":
        return True
    if base.startswith(".env."):
        return base not in (".env.example", ".env.sample", ".env.template")
    return False


def _head_still_has_secret(repo: Any, path: str) -> bool:
    content = _head_file_bytes(repo, path)
    if content is None:
        return False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return any(_match_secrets(line) for line in text.split("\n"))


def rule_secrets(commits: list[CommitInfo], repo: Any) -> list[Finding]:
    # Keyed on (path, redacted line) so the same secret is reported once, at
    # the commit where it first entered the tree.
    seen: dict[tuple[str, str], Finding] = {}
    env_seen: set[str] = set()
    findings: list[Finding] = []

    for c in commits:
        for d in c.diffs:
            if d.change not in ("A", "M", "R"):
                continue

            if d.change == "A" and _is_env_file(d.path) and d.path not in env_seen:
                env_seen.add(d.path)
                findings.append(
                    Finding(
                        rule_id=RULE_ENV_FILE,
                        commit_sha=c.sha,
                        date=c.date,
                        author=c.author,
                        file_path=d.path,
                        summary=(
                            f"An environment file ({d.path}) was committed. "
                            f"Whatever it held is in history from here on."
                        ),
                        evidence={
                            "commit_message": c.message,
                            "matched_pattern": "env_file",
                            "present_in_history": True,
                            "removed_from_working_tree": _head_file_bytes(repo, d.path) is None,
                        },
                    )
                )

            for line_no, line in _iter_added_lines(d.patch):
                for rule_id, spans in _match_secrets(line):
                    redacted = _redact(line, spans)
                    key = (d.path, redacted)
                    if key in seen:
                        continue
                    still_present = _head_still_has_secret(repo, d.path)
                    finding = Finding(
                        rule_id=rule_id,
                        commit_sha=c.sha,
                        date=c.date,
                        author=c.author,
                        file_path=d.path,
                        summary=(
                            f"A credential-shaped value entered the tree at "
                            f"{d.path}:{line_no}."
                            + (
                                " It is gone from the working tree, but it is still in history."
                                if not still_present
                                else " It is still present at HEAD."
                            )
                        ),
                        evidence={
                            "commit_message": c.message,
                            "line_number": line_no,
                            "redacted_line": redacted,
                            "matched_pattern": rule_id,
                            "present_in_history": True,
                            "removed_from_working_tree": not still_present,
                        },
                    )
                    seen[key] = finding
                    findings.append(finding)

    return findings


# ---------------------------------------------------------------------------

def run_all(commits: list[CommitInfo], repo: Any) -> list[Finding]:
    findings = rule_empty_files(commits, repo) + rule_secrets(commits, repo)
    findings.sort(key=lambda f: (f.date, f.rule_id, f.file_path))
    return findings