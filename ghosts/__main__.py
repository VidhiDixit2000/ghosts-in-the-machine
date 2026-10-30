"""Command line entry point.

    python -m ghosts <github-url>

Clone, scan and report -- all inside one process, because /tmp does not
survive between shell invocations on every machine.
"""

from __future__ import annotations
from ghosts.narrate import narrate, print_interpretation
import argparse
import json
import sys

from ghosts.ingest import IngestError, cleanup_repo, scan_repo
from ghosts.rules import run_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghosts",
        description="Find things that broke quietly in a repository's history.",
    )
    parser.add_argument("url", help="Public GitHub repository URL")
    parser.add_argument(
        "--max-commits", type=int, default=500,
        help="How far back to look (default: 500)",
    )
    parser.add_argument(
        "--json", dest="json_path", default="findings.json",
        help="Where to write findings as JSON (default: findings.json)",
    )
    parser.add_argument(
        "--narrate", action="store_true",
        help="Run the model layer: group, rank and narrate the findings",
    )
    parser.add_argument(
        "--narrate-out", dest="narrate_path", default="findings.narrated.json",
        help="Where to write the narrated output (default: findings.narrated.json)",
    )
    parser.add_argument(
        "--threshold", type=int, default=6,
        help="Narrate groups scoring at or above this, 1-10 (default: 6)",
    )

    args = parser.parse_args(argv)

    repo = None
    try:
        print(f"Cloning {args.url} ...", file=sys.stderr)
        commits, meta, repo = scan_repo(args.url, args.max_commits)
        print(
            f"Walked {meta['commits_scanned']} commits"
            + (" (history was capped)" if meta["capped"] else ""),
            file=sys.stderr,
        )

        findings = run_all(commits, repo)

        if not findings:
            print("\nNothing found. The history is quiet.")
        else:
            print(f"\n{len(findings)} finding{'' if len(findings) == 1 else 's'}:\n")
            for f in findings:
                print(f"  [{f.rule_id}]  {f.date}  {f.commit_sha[:8]}  {f.author}")
                print(f"      {f.summary}")
                line = f.evidence.get("redacted_line")
                if line:
                    print(f"      > {line.strip()}")
                msg = f.evidence.get("commit_message")
                if msg:
                    print(f'      commit: "{msg}"')
                print()

        payload = {
            "repository": args.url,
            "scan": meta,
            "findings": [f.to_dict() for f in findings],
        }
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Written to {args.json_path}", file=sys.stderr)

        if args.narrate:
            interpretation = narrate(findings, threshold=args.threshold)
            print_interpretation(interpretation)
            narrated = dict(payload)
            narrated["interpretation"] = interpretation
            with open(args.narrate_path, "w", encoding="utf-8") as fh:
                json.dump(narrated, fh, indent=2)
            print(f"Written to {args.narrate_path}", file=sys.stderr)

        return 0

    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if repo is not None:
            cleanup_repo(repo)


if __name__ == "__main__":
    raise SystemExit(main())