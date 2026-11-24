#!/usr/bin/env python3
"""Run a backend over the corpus and write a scored report.

    python src/run.py --backend mock
    python src/run.py --backend jev --limit 200
    python src/run.py --backend local --model gemma4:12b   # EXODON_OLLAMA_URL
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import backends as B  # noqa: E402
import config  # noqa: E402
import metrics as M  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = config.DATA / "corpus" / "corpus.jsonl"
RESULTS = config.DATA / "results"


def load(path: pathlib.Path, limit: int | None = None,
         gold_only: bool = True) -> list[dict]:
    if not path.exists():
        sys.exit(f"no corpus at {path} -- build it first (see README), or "
                 f"pass --corpus corpus/synthetic.jsonl for a plumbing check")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if gold_only:
        # Drop the Spam folder: that is Fastmail's unreviewed verdict, not a
        # human label, so scoring against it measures agreement with the
        # incumbent rather than correctness.
        rows = [r for r in rows if r.get("gold", 1)]
    if limit:
        # Stratified so a --limit smoke run keeps both classes.
        pos = [r for r in rows if r["label"] == 1][: limit // 2]
        neg = [r for r in rows if r["label"] == 0][: limit - len(pos)]
        rows = pos + neg
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True,
                    choices=["jev", "jeff", "laya", "local", "fastmail", "mock"])
    ap.add_argument("--model", default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--think", action="store_true",
                    help="local backend: leave the model's thinking on "
                         "(~100x slower; see backends.py)")
    ap.add_argument("--prompt", choices=["ours", "gatekeeper"], default="ours",
                    help="local backend: our definition, or the Medium article's "
                         "executive-assistant prompt (see backends.GATEKEEPER)")
    ap.add_argument("--context", action="store_true",
                    help="local backend: append mailbox context (needs a "
                         "*_ctx.jsonl corpus from src/context.py)")
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                    help="real mail by default; corpus/synthetic.jsonl is a "
                         "trivially separable fixture for plumbing checks only")
    ap.add_argument("--include-fastmail-labeled", action="store_true",
                    help="also score the Spam folder, whose labels are "
                         "Fastmail's own verdict rather than Kyle's")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=8,
                    help="jev allows 1200 req/min; keep local at 1")
    ap.add_argument("--tag", default=None, help="suffix for the results file")
    args = ap.parse_args()

    if args.backend == "jev":
        be = B.JevBackend(model=args.model or "jev-latest",
                          base_url=args.base_url)
    elif args.backend in ("jeff", "laya"):
        # Self-hosted jev look-alikes on the same wire format. For laya,
        # --model picks a checkpoint (english / typed-decisions); anything
        # else lets its router choose.
        be = B.JevBackend(model=args.model or "jev-latest",
                          base_url=args.base_url or "http://127.0.0.1:8000",
                          api_key=os.environ.get("TYPESAFE_API_KEY", "devkey"))
        be.name = args.backend
    elif args.backend == "local":
        be = B.OllamaLogprobBackend(args.base_url or config.OLLAMA_URL, args.model or "gemma4:12b",
                                    think=args.think, prompt=args.prompt,
                                    context=args.context)
        # One GPU, one model resident: concurrency buys nothing and risks
        # eviction thrash between the two gemma4 variants.
        args.workers = 1
    elif args.backend == "fastmail":
        be = B.FastmailBaseline()
    else:
        be = B.MockBackend()

    emails = load(pathlib.Path(args.corpus), args.limit,
                  gold_only=not args.include_fastmail_labeled)
    print(f"scoring {len(emails)} messages with {be.name} "
          f"({sum(e['label'] for e in emails)} spam)", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        verdicts = list(pool.map(be.score, emails))

    rows, lats, toks = [], [], 0
    scored = []
    for e, v in zip(emails, verdicts):
        rows.append(M.Row(label=e["label"], p=v.p_spam,
                          fastmail=e.get("fastmail_said_spam", 0),
                          source=e.get("source", ""), id=e.get("id", "")))
        if v.error is None:
            lats.append(v.latency_ms)
            toks += v.input_tokens
        scored.append({"id": e.get("id"), "subject": e.get("subject"),
                       "from": e.get("from_email"), "label": e["label"],
                       "source": e.get("source"), "p_spam": v.p_spam,
                       "confidence": v.confidence, "error": v.error,
                       "raw": v.raw})

    tag = args.tag or (args.model or be.name)
    RESULTS.mkdir(exist_ok=True)
    stem = f"{be.name}_{tag}".replace("/", "_").replace(":", "-")
    (RESULTS / f"{stem}.scores.jsonl").write_text(
        "\n".join(json.dumps(s) for s in scored))

    rep = M.report(rows, name=f"{be.name}:{tag}", tokens=toks, latencies=lats)
    (RESULTS / f"{stem}.report.json").write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
