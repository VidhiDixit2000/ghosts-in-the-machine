"""Repository ingestion: shallow-clone a public GitHub repo and walk history.

Chosen approach: GitPython. It is a thin wrapper over the git binary and gives
us diff objects, blob sizes and patch text from one clean API, which is what
the rules need. The shallow clone is bounded by ``--depth`` so a very large
repo cannot pull its whole history; we report when that cap was hit instead of
silently scanning a truncated slice.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any, Optional

import git

GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?(?:/|$)",
    re.IGNORECASE,
)


class IngestError(Exception):
    """Base error for ingestion failures."""


class RepoNotFound(IngestError):
    """Repository not found (HTTP 404 / fatal: not found)."""


class NetworkError(IngestError):
    """Network failure while cloning."""


@dataclass
class DiffEntry:
    """One file changed within a commit.

    ``b_blob`` is the raw git blob object for the file's new state (or None for
    a deletion). It is kept opaque (``Any``) so the finding layer never imports
    git directly -- it only needs ``.size`` and ``.data_stream``.
    """

    path: str
    change: str  # 'A' added, 'M' modified, 'D' deleted, 'R' renamed
    a_blob_sha: Optional[str]
    b_blob_sha: Optional[str]
    b_blob_size: Optional[int]
    b_blob: Any = None  # raw blob object, or None
    patch: Optional[bytes] = None  # raw unified-diff bytes for this file, or None


@dataclass
class CommitInfo:
    sha: str
    date: str  # ISO date (YYYY-MM-DD) in the author's timezone
    author: str
    message: str  # first line of the commit message
    diffs: list[DiffEntry] = field(default_factory=list)


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a public GitHub URL."""
    m = GITHUB_URL_RE.search(url)
    if not m:
        raise IngestError(f"Not a public GitHub repository URL: {url!r}")
    return m.group("owner"), m.group("repo")


def clone_repo(url: str, dest: str, max_commits: int = 500) -> git.Repo:
    """Shallow-clone ``url`` into ``dest`` with a bounded history depth."""
    try:
        return git.Repo.clone_from(url, dest, depth=max_commits)
    except git.exc.GitCommandError as exc:
        err = " ".join(filter(None, [exc.stderr or "", str(exc)])).lower()
        if "repository not found" in err or "not found" in err or "404" in err or "does not exist" in err:
            raise RepoNotFound(f"Repository not found: {url!r}") from exc
        raise NetworkError(f"Could not clone {url!r}: {exc}") from exc
    except git.exc.GitError as exc:
        raise NetworkError(f"Could not clone {url!r}: {exc}") from exc


def _classify(diff: Any) -> str:
    if diff.new_file:
        return "A"
    if diff.deleted_file:
        return "D"
    if diff.renamed_file:
        return "R"
    return "M"


# REPLACE the existing walk_history() in ghosts/ingest.py with this one.
# Everything else in ingest.py stays exactly as it is.
#
# What changed and why
# --------------------
# The old version called  c.diff(parent)  which puts the COMMIT on the 'a'
# side and the PARENT on the 'b' side -- i.e. backwards. b_blob was the blob
# BEFORE the commit, new_file/deleted_file were inverted, and the patch's
# +/- lines were swapped.
#
# Proof, from the earlier probe of commit 4199e0b:
#   git show --raw  ->  :100644 100644 73fcb43 f2e3728 M  README.md
#                                      ^old     ^new
#   GitPython       ->  a= f2e37285  b= 73fcb438
#                          ^new         ^old      (reversed)
#
# Fix: diff from the parent TO the commit, so a=old and b=new.
# The root commit has no parent, so its tree is walked directly and every
# file in it is recorded as an addition.


def walk_history(repo: git.Repo, max_commits: int = 500) -> tuple[list[CommitInfo], dict[str, Any]]:
    """Walk commit history oldest-first, returning commits and scan metadata.

    ``meta['capped']`` is True when the repo had at least ``max_commits``
    commits and the scan therefore only saw a prefix of its history.
    """
    commits = list(repo.iter_commits(max_count=max_commits))
    commits.reverse()  # oldest first

    out: list[CommitInfo] = []
    for c in commits:
        entries: list[DiffEntry] = []

        if c.parents:
            # parent -> commit, so a=old state, b=new state.
            for d in c.parents[0].diff(c, create_patch=True):
                patch = d.diff
                if isinstance(patch, str):
                    patch = patch.encode("utf-8", errors="replace")
                elif not isinstance(patch, (bytes, bytearray)):
                    patch = None
                a = d.a_blob
                b = d.b_blob
                entries.append(
                    DiffEntry(
                        path=(d.b_path or d.a_path or "").replace("\\", "/"),
                        change=_classify(d),
                        a_blob_sha=a.hexsha if a else None,
                        b_blob_sha=b.hexsha if b else None,
                        b_blob_size=b.size if b else None,
                        b_blob=b,
                        patch=bytes(patch) if patch else None,
                    )
                )
        else:
            # Root commit: no parent to diff against. Every blob in the tree
            # is, by definition, an addition. Synthesised rather than diffed
            # so the orientation cannot be ambiguous.
            for blob in c.tree.traverse():
                if blob.type != "blob":
                    continue
                entries.append(
                    DiffEntry(
                        path=blob.path.replace("\\", "/"),
                        change="A",
                        a_blob_sha=None,
                        b_blob_sha=blob.hexsha,
                        b_blob_size=blob.size,
                        b_blob=blob,
                        patch=_synthetic_add_patch(blob),
                    )
                )

        out.append(
            CommitInfo(
                sha=c.hexsha,
                date=c.authored_datetime.date().isoformat(),
                author=c.author.name or c.author.email or "Unknown",
                message=(c.message or "").strip().splitlines()[0] if c.message else "",
                diffs=entries,
            )
        )

    meta = {
        "capped": len(commits) >= max_commits,
        "commits_scanned": len(commits),
        "max_commits": max_commits,
    }
    return out, meta


def _synthetic_add_patch(blob: Any) -> Optional[bytes]:
    """Build an all-added unified diff for a root-commit blob.

    The rules parse added lines out of patch text. A root commit has no real
    diff, so one is synthesised: every line of the file is an addition, which
    is exactly what happened.
    """
    MAX = 2_000_000
    try:
        if blob.size is None or blob.size > MAX:
            return None
        content = blob.data_stream.read()
    except Exception:
        return None
    if not content:
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None  # binary; nothing to scan
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    header = f"@@ -0,0 +1,{len(lines)} @@\n"
    body = "".join("+" + ln + "\n" for ln in lines)
    return (header + body).encode("utf-8")

def scan_repo(url: str, max_commits: int = 500) -> tuple[list[CommitInfo], dict[str, Any], git.Repo]:
    """Clone, walk, and return (commits, meta, repo) -- caller must clean up.

    The returned ``repo`` is backed by a temp directory the caller is
    responsible for removing (see :func:`main`). Rules need it to read blob
    contents and the HEAD tree after the walk.
    """
    dest = tempfile.mkdtemp(prefix="ghosts-")
    repo = clone_repo(url, dest, max_commits)
    commits, meta = walk_history(repo, max_commits)
    return commits, meta, repo


def cleanup_repo(repo: git.Repo) -> None:
    """Remove the temp directory backing ``repo``."""
    try:
        shutil.rmtree(repo.working_tree_dir, ignore_errors=True)
    except Exception:
        pass