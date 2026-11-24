#!/usr/bin/env python3
"""Build the work-account review set over read-only IMAP.

    keys exec MY_IMAP_SECRET -- python3 src/build_work_corpus.py   # see .env.example

Every mailbox is opened with readonly=True and every fetch uses BODY.PEEK, so
nothing is marked read -- and the credential itself is read-only regardless.

The output is a fixed, randomly drawn review set chosen *before* any model is
run on it, so that label cleanup cannot drift toward whichever model gets
looked at first:

    Identified Spam   200 of the folder     (Kyle's training folder)
    Spam              100 of the folder     (Fastmail's own verdict)
    Archive           250 of the latest 1000

Each row carries the mailbox's own evidence (answered / flagged / Kyle has
emailed the sender) and Fastmail's X-Spam-score, but NOT a trusted label: the
folder is recorded as `source` only. Labels come from review.py.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import imaplib
import json
import os
import pathlib
import random
import re
import ssl
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402
PREVIEW_CHARS = 600
SEED = 20260923  # fixed so the review set is reproducible

TAG = re.compile(r"<[^>]+>")
STYLE = re.compile(r"<(style|script)[^>]*>.*?</\1>", re.S | re.I)
WS = re.compile(r"\s+")


def connect(pw: str) -> imaplib.IMAP4_SSL:
    M = imaplib.IMAP4_SSL(config.IMAP_HOST, 993, ssl_context=ssl.create_default_context())
    M.login(config.imap_user(), pw)
    return M


def uids(M: imaplib.IMAP4_SSL, folder: str) -> list[bytes]:
    ok, _ = M.select(f'"{folder}"', readonly=True)
    if ok != "OK":
        sys.exit(f"cannot select {folder}")
    ok, data = M.uid("SEARCH", None, "ALL")
    return data[0].split()  # ascending UID ~ oldest first


def sent_recipients(M: imaplib.IMAP4_SSL) -> set[str]:
    out: set[str] = set()
    ids = uids(M, "Sent")
    for i in range(0, len(ids), 500):
        ok, resp = M.uid("FETCH", b",".join(ids[i:i + 500]).decode(),
                         "(BODY.PEEK[HEADER.FIELDS (TO CC BCC)])")
        for item in resp:
            if isinstance(item, tuple):
                msg = email.message_from_bytes(item[1], policy=email.policy.compat32)
                vals = [str(v) for f in ("To", "Cc", "Bcc") for v in msg.get_all(f, [])]
                out |= {a.strip().lower() for _, a in email.utils.getaddresses(vals) if a}
    print(f"Sent: {len(ids)} messages, {len(out)} recipients", file=sys.stderr)
    return out


def body_text(msg: email.message.EmailMessage) -> str:
    """Properly decoded text: plain part if there is one, else de-tagged HTML."""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    try:
        text = part.get_content()
    except Exception:  # noqa: BLE001 - broken charsets are routine in spam
        raw = part.get_payload(decode=True) or b""
        text = raw.decode("utf-8", errors="replace")
    if part.get_content_type() == "text/html":
        text = TAG.sub(" ", STYLE.sub(" ", text))
    return WS.sub(" ", text).strip()


def addr(msg, field: str) -> tuple[str, str]:
    name, a = email.utils.parseaddr(str(msg.get(field, "")))
    return name.strip(), a.strip().lower()


def fetch(M: imaplib.IMAP4_SSL, folder: str, picks: list[bytes], sent: set[str]) -> list[dict]:
    uids(M, folder)  # select, read-only
    rows = []
    for i in range(0, len(picks), 25):
        ok, resp = M.uid("FETCH", b",".join(picks[i:i + 25]).decode(),
                         "(FLAGS INTERNALDATE BODY.PEEK[])")
        for item in resp:
            if not isinstance(item, tuple):
                continue
            meta = item[0]
            uid = re.search(rb"UID (\d+)", meta).group(1).decode()
            flags = {f.decode().lower() for f in
                     re.search(rb"FLAGS \(([^)]*)\)", meta).group(1).split()}
            when = re.search(rb'INTERNALDATE "([^"]+)"', meta)
            msg = email.message_from_bytes(item[1], policy=email.policy.default)
            fname, faddr = addr(msg, "From")
            score = msg.get("X-Spam-score")
            try:
                score = float(str(score).strip()) if score is not None else None
            except ValueError:
                score = None
            rows.append({
                "id": f"work:{folder}:{uid}",
                "source": folder,
                "subject": str(msg.get("Subject", "") or ""),
                "from_name": fname,
                "from_email": faddr,
                "to": addr(msg, "To")[1],
                "received_at": when.group(1).decode() if when else "",
                "preview": body_text(msg)[:PREVIEW_CHARS],
                "list_unsubscribe": msg.get("List-Unsubscribe") is not None,
                "fastmail_score": score,
                "fastmail_said_spam": 1 if folder == "Spam" else 0,
                "answered": "\\answered" in flags,
                "flagged": "\\flagged" in flags,
                "seen": "\\seen" in flags,
                "corresponded": faddr in sent,
            })
        print(f"  {folder}: {min(i + 25, len(picks))}/{len(picks)}",
              file=sys.stderr, end="\r")
    print(file=sys.stderr)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--identified", type=int, default=200)
    ap.add_argument("--spam", type=int, default=100)
    ap.add_argument("--archive", type=int, default=250)
    ap.add_argument("--archive-pool", type=int, default=1000)
    ap.add_argument("--out", default=str(config.DATA / "corpus" / "work.jsonl"))
    args = ap.parse_args()

    pw = config.imap_password()
    M = connect(pw)
    rng = random.Random(SEED)
    rows: list[dict] = []
    try:
        sent = sent_recipients(M)
        for folder, n, pool in (("Identified Spam", args.identified, None),
                                ("Spam", args.spam, None),
                                ("Archive", args.archive, args.archive_pool)):
            ids = uids(M, folder)
            if pool:
                ids = ids[-pool:]  # most recent
            picks = rng.sample(ids, min(n, len(ids)))
            print(f"{folder}: sampled {len(picks)} of {len(ids)}", file=sys.stderr)
            rows += fetch(M, folder, picks, sent)
    finally:
        try:
            M.logout()
        except Exception:  # noqa: BLE001
            pass

    rng.shuffle(rows)  # review order must not reveal the source folder
    out = pathlib.Path(args.out)
    out.write_text("\n".join(json.dumps(r) for r in rows))
    print(f"\nwrote {len(rows)} -> {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
