"""Normalised finding shape.

Every rule produces the same structure so the later AI stage reads one shape
regardless of which rule fired. The ``evidence`` blob holds raw facts only --
no interpretation. Interpretation lives in ``summary`` and is kept separate so
the raw facts survive untouched when someone adds judgement on top.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    rule_id: str
    commit_sha: str
    date: str
    author: str
    file_path: str
    summary: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "commit_sha": self.commit_sha,
            "date": self.date,
            "author": self.author,
            "file_path": self.file_path,
            "summary": self.summary,
            "evidence": self.evidence,
        }