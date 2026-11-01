# Ghosts in the Machine

Reads a public repository's git history and finds failures that never produced
an error — the ones nobody noticed, because there was nothing to notice.

**Live:** [ghostsinthemachine.tech](https://ghostsinthemachine.tech) ·
also at [ghosts-in-the-machine.onrender.com](https://ghosts-in-the-machine.onrender.com/)

**Write-up:** [Turns out I'm the one making the ghosts](https://dev.to/vidhidixit2000/turns-out-im-the-one-making-the-ghosts-3oij)

---

## What it does

Point it at a public repository. It clones the history, walks every commit and
every diff, and reports things like:

- a file committed empty and filled 78 days later
- a `readme.md` committed empty by a commit whose message was "Add README"
- a database password in three places in one commit, one of them commented out
- a `.json` file deleted inside a 14,000-line change

None of those raise an error at the time. That is the whole point: they are
failures with no symptom, so nobody goes looking.

## How it works

Three stages. The first two are deterministic; only the third uses a model.

```
   a public repo
        │
        ▼
 ┌─────────────────┐
 │  walk history   │   every commit, every diff
 └────────┬────────┘
          ▼
 ┌─────────────────┐
 │  rules          │   no AI. zero-byte blobs,
 │  (deterministic)│   credential-shaped lines
 └────────┬────────┘
          ▼
 ┌─────────────────┐
 │  oddness        │   no AI. size collapses, resurrected
 │  (deterministic)│   paths, diffs that don't match
 └────────┬────────┘   their own message
          ▼  findings, with commit hashes
 ┌─────────────────┐
 │  Gemma          │   did this break? which of these
 │  (open weights) │   matter? how do I explain it?
 └────────┬────────┘
          ▼
 ┌─────────────────────────────────────┐
 │  what the model made of it          │
 ├─────────────────────────────────────┤
 │  what git actually recorded         │  ← both shown, so you can
 └─────────────────────────────────────┘    check one against the other
```

**Named rules** (`ghosts/rules.py`) look for two specific failures: a blob that
is zero bytes or whitespace-only when its extension implies content, and added
lines that look like credentials. Credentials are redacted before anything is
stored, printed or sent anywhere.

**Oddness measurements** (`ghosts/anomaly.py`) name no failure at all. Six
measurements score how *unusual* a change is — size collapse, a file too small
for its extension, a resurrected path, two paths differing only in case, a
large diff under a short message, a change that is almost all deletion. The
dozen oddest go to the model in one call, and the model decides whether
anything actually broke.

The point of the split: a named rule finds one kind of failure, forever. A
measurement surfaces failures nobody wrote a rule for, because the signal set
is bounded by what git can record while what the model can name is not.

**Narration** (`ghosts/narrate.py`) groups the findings, ranks them, and writes
them up. It never replaces the findings — the page shows the model's account
above the raw evidence, so you can check one against the other. That matters:
the model has produced both a self-contradictory account of when a credential
was removed, and a confident theory about a deletion that the evidence did not
support. Both were visible precisely because the evidence sits underneath.

## Running it

```bash
git clone https://github.com/VidhiDixit2000/ghosts-in-the-machine
cd ghosts-in-the-machine
pip install -r requirements.txt
```

Narration and the oddness channel need an OpenRouter key. Without one, the
named rules still run and report normally.

```bash
export OPENROUTER_API_KEY=sk-or-...        # PowerShell: $env:OPENROUTER_API_KEY = "..."
```

### Command line

```bash
python -m ghosts https://github.com/owner/repo
python -m ghosts https://github.com/owner/repo --anomalies --narrate
```

| Flag | What it does |
|---|---|
| `--anomalies` | Also run the oddness measurements and ask the model about them |
| `--narrate` | Group, rank and write up the findings |
| `--threshold N` | Narrate groups scoring at or above N out of 10 (default 6) |

Findings are written to `findings.json`; narration to `findings.narrated.json`.
Both are gitignored.

### Web app

```bash
python -m uvicorn ghosts.web:app --port 8000
```

Then open `http://127.0.0.1:8000`. Two exhibits load on arrival; paste any
public repository into the box to scan that one instead.

### Environment variables

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | Required for narration and the oddness channel |
| `GHOSTS_MAX_COMMITS` | Commit depth cap (default 500) |
| `GHOSTS_SCAN_TIMEOUT` | Seconds before a scan is abandoned (default 240) |

## Layout

```
ghosts/
  ingest.py    clone and walk history
  finding.py   the Finding record
  rules.py     named rules, deterministic
  anomaly.py   oddness measurements + model judgement
  narrate.py   grouping, ranking, narration
  web.py       FastAPI app and the page
```

## What it doesn't do

- Two named rules and six measurements. Most well-kept repositories come back
  empty, correctly, and the page says so.
- Commit depth is capped. The page tells you when a history was truncated.
- Large repositories are slow; cloning dominates, not scanning.
- The narration is not stable between runs, and the model sometimes reads
  intent into odd commits or garbles facts it was given correctly. The evidence
  pane exists for exactly this reason.
- Secret detection is shallow next to dedicated tools. The quiet-failure half
  is where the gap is.

## Built for

The [Hacktoberfest Open-Source AI Challenge: Ghost in the Machine](https://dev.to/challenges/hacktoberfest-week4-2026-10-26),
October 2026.

Gemma (open weights) via OpenRouter · Render · ElevenLabs · .tech

## Commits after the deadline

The submission deadline was 31 October 2026, 11:59 PM PDT. Everything the
write-up describes was committed before it. Any commit after that point is
listed here.

- 1 November 2026 — added README and MIT licence. No code changes.

## Licence

MIT.
