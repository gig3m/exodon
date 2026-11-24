#!/usr/bin/env python3
"""Blind, one-keypress review of the work corpus.

    python3 src/review.py

Shows one email at a time with no model scores and no hint of which folder it
came from, in a fixed random order. Every answer is saved immediately, so you
can quit at any point and pick up where you left off.

    1  real correspondence   a person writing about actual business
    2  transactional         receipt, order, shipping, account / security notice
    3  subscribed            newsletter or promo you signed up for
    4  cold outreach         sales pitch from someone with no relationship
    5  scam / phishing
    0  unsure                dropped from scoring, never forced into a bucket

    b  back one      q  quit (progress is saved)
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import termios
import textwrap
import time
import tty

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402

CORPUS = config.DATA / "corpus" / "work.jsonl"
LABELS = config.DATA / "corpus" / "work_labels.jsonl"

CATS = {
    "1": "correspondence",
    "2": "transactional",
    "3": "subscribed",
    "4": "cold_outreach",
    "5": "scam",
    "0": "unsure",
}
LEGEND = ("1 correspondence   2 transactional   3 subscribed   "
          "4 cold outreach   5 scam   0 unsure      b back   q quit")


def getch() -> str:
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def load_labels() -> dict[str, dict]:
    """Append-only log; the last answer for an id wins."""
    out: dict[str, dict] = {}
    if LABELS.exists():
        for line in LABELS.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                out[rec["id"]] = rec
    return out


def show(r: dict, i: int, n: int, done: int, prev: str | None) -> None:
    w = min(shutil.get_terminal_size((100, 30)).columns, 110)
    os.system("clear")
    bar = int((done / n) * (w - 20))
    print(f"[{'#' * bar}{'.' * (w - 20 - bar)}] {done}/{n}")
    print("─" * w)
    who = f"{r['from_name']} <{r['from_email']}>" if r["from_name"] else r["from_email"]
    print(f"From:     {who}")
    print(f"Subject:  {r['subject'] or '(no subject)'}")
    print(f"Date:     {r['received_at'][:10]}")
    hints = []
    if r.get("corresponded"):
        hints.append("you have emailed this sender before")
    if r.get("answered"):
        hints.append("you replied to this one")
    if hints:
        print(f"Note:     {'; '.join(hints)}")
    print("─" * w)
    body = r["preview"] or "(no body text)"
    for line in textwrap.wrap(body, w)[:14]:
        print(line)
    print("─" * w)
    if prev:
        print(f"(previously labeled: {prev})")
    print(LEGEND)


def main() -> None:
    rows = [json.loads(l) for l in CORPUS.read_text().splitlines() if l.strip()]
    labels = load_labels()
    n = len(rows)

    # Resume at the first unlabeled message.
    i = next((k for k, r in enumerate(rows) if r["id"] not in labels), n)
    with LABELS.open("a") as log:
        while i < n:
            r = rows[i]
            prev = labels.get(r["id"], {}).get("category")
            show(r, i, n, len(labels), prev)
            k = getch().lower()
            if k in ("q", "\x03"):
                break
            if k == "b":
                i = max(0, i - 1)
                continue
            if k in CATS:
                rec = {"id": r["id"], "category": CATS[k], "at": time.time()}
                log.write(json.dumps(rec) + "\n")
                log.flush()
                labels[r["id"]] = rec
                i += 1
    os.system("clear")
    print(f"{len(labels)}/{n} labeled -> {LABELS}")
    if len(labels) < n:
        print("run again to continue where you left off")


if __name__ == "__main__":
    main()
