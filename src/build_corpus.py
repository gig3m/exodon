#!/usr/bin/env python3
"""Build the labeled corpus from Fastmail over IMAP.

    keys exec MY_IMAP_SECRET -- python3 src/build_corpus.py   # .env: account + EXODON_IMAP_PASSWORD_ENV=MY_IMAP_SECRET

Sampling is recency-matched on purpose: the most recent N from each folder,
rather than all 16k of Archive. Two reasons.

1. Spam changes. Archive goes back years; Identified Spam is mostly recent.
   Scoring 2019 receipts against 2026 cold outreach measures era, not spam.
2. Class balance. A 481-vs-16589 split makes precision numbers hostage to the
   base rate and buys very little extra signal on the negative side.

Labels (see README for why this is the valid framing):
  Identified Spam -> label 1, gold. Kyle filed it by hand, AND Fastmail
                     delivered it, so it is also the incumbent's miss set.
  Archive         -> label 0, gold. Kyle filed it by hand.
  Spam            -> label 1, NOT gold. This is Fastmail's own verdict,
                     unreviewed. Kept for the baseline arm and excluded from
                     the headline metric by default.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import imaplib
import json
import os
import pathlib
import re
import ssl
import sys
from email.header import decode_header, make_header

HOST = "imap.fastmail.com"
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402

# We deliberately do not pull whole messages: a mail client has the envelope
# and a preview without a full fetch, and it is ~6x fewer input tokens at
# classification time.
#
# Named header fields rather than a byte-truncated BODY[]: Fastmail prepends
# such a large block of Received/ARC/DKIM/X-Spam headers that Subject can sit
# past byte 8000, which silently yields blank subjects on every message.
HEADER_FIELDS = (
    "FROM TO CC SUBJECT DATE LIST-UNSUBSCRIBE "
    "X-SPAM-SCORE X-SPAM-KNOWN-SENDER X-SPAM-SENDER-REPUTATION X-SPAM-HITS"
)
BODY_BYTES = 2000
PREVIEW_CHARS = 600

SPECS = [
    # (folder, label, gold, fastmail_said_spam, default count)
    ("Identified Spam", 1, 1, 0, 500),
    ("Archive", 0, 1, 0, 1000),
    ("Spam", 1, 0, 1, 250),
]


def hdr(msg: email.message.Message, name: str) -> str:
    raw = msg.get(name)
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw))).strip()
    except Exception:  # noqa: BLE001 - malformed headers are common in spam
        return str(raw).strip()


def split_addr(value: str) -> tuple[str, str]:
    name, addr = email.utils.parseaddr(value)
    return name.strip(), addr.strip().lower()


TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


MIME_NOISE = re.compile(
    rb"^(--[-\w=.]+|Content-[\w-]+:.*|charset=.*)$", re.M | re.I)


def preview_of(body: bytes) -> str:
    """The text a list view would show.

    The fetch is byte-truncated so the MIME tree is incomplete and proper
    part-walking is not available; strip the boundary/Content-* scaffolding
    and any tags, then take the head of what is left.
    """
    body = MIME_NOISE.sub(b"", body)
    text = body.decode("utf-8", errors="replace")
    text = text.replace("=\r\n", "").replace("=\n", "")  # qp soft breaks
    text = TAG.sub(" ", text)
    text = WS.sub(" ", text)
    return text.strip()[:PREVIEW_CHARS]


def spam_score(msg: email.message.Message) -> float | None:
    """Fastmail's own continuous score, which turns the incumbent from a
    single binary point into a full ROC curve worth comparing against."""
    raw = msg.get("X-Spam-score")
    if raw is None:
        return None
    try:
        return float(str(raw).strip())
    except ValueError:
        return None


def fetch_folder(M: imaplib.IMAP4_SSL, folder: str, count: int) -> list[dict]:
    ok, data = M.select(f'"{folder}"', readonly=True)
    if ok != "OK":
        print(f"  !! cannot select {folder}: {data}", file=sys.stderr)
        return []
    ok, data = M.uid("SEARCH", None, "ALL")
    uids = data[0].split()
    if not uids:
        return []
    uids = uids[-count:]  # most recent
    print(f"  {folder}: {len(uids)} of {len(data[0].split())}", file=sys.stderr)

    out = []
    for i in range(0, len(uids), 50):
        chunk = b",".join(uids[i:i + 50]).decode()
        ok, resp = M.uid(
            "FETCH", chunk,
            f"(BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})] "
            f"BODY.PEEK[TEXT]<0.{BODY_BYTES}> INTERNALDATE)")
        if ok != "OK":
            continue
        # Each message yields two literals (headers, then body text); pair
        # them up by UID rather than assuming response ordering.
        by_uid: dict[str, dict] = {}
        for item in resp:
            if not isinstance(item, tuple):
                continue
            meta, blob = item[0], item[1]
            m = re.search(rb"UID (\d+)", meta)
            if not m:
                continue
            uid = m.group(1).decode()
            slot = by_uid.setdefault(uid, {})
            if b"HEADER.FIELDS" in meta:
                slot["hdr"] = blob
            elif b"BODY[TEXT]" in meta or b"TEXT]<" in meta:
                slot["body"] = blob
            m = re.search(rb'INTERNALDATE "([^"]+)"', meta)
            if m:
                slot["when"] = m.group(1).decode()

        for uid, slot in by_uid.items():
            if "hdr" not in slot:
                continue
            msg = email.message_from_bytes(slot["hdr"],
                                           policy=email.policy.default)
            fname, faddr = split_addr(hdr(msg, "From"))
            out.append({
                "id": f"{folder}:{uid}",
                "subject": hdr(msg, "Subject"),
                "from_name": fname,
                "from_email": faddr,
                "to": split_addr(hdr(msg, "To"))[1],
                "list_unsubscribe": bool(msg.get("List-Unsubscribe")),
                "received_at": slot.get("when", ""),
                "preview": preview_of(slot.get("body", b"")),
                # The incumbent's own signals, free at corpus-build time.
                "fastmail_score": spam_score(msg),
                "fastmail_known_sender": hdr(msg, "X-Spam-known-sender"),
                "fastmail_sender_reputation": hdr(msg, "X-Spam-sender-reputation"),
            })
        print(f"    fetched {min(i + 50, len(uids))}/{len(uids)}",
              file=sys.stderr, end="\r")
    print(file=sys.stderr)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=int, default=1000)
    ap.add_argument("--spam-folder", type=int, default=250)
    ap.add_argument("--identified", type=int, default=500)
    ap.add_argument("--out", default=str(config.DATA / "corpus" / "corpus.jsonl"))
    args = ap.parse_args()

    pw = config.imap_password()

    counts = {"Identified Spam": args.identified, "Archive": args.archive,
              "Spam": args.spam_folder}

    M = imaplib.IMAP4_SSL(config.IMAP_HOST, 993, ssl_context=ssl.create_default_context())
    M.login(config.imap_user(), pw)
    rows = []
    try:
        for folder, label, gold, fm, _ in SPECS:
            for r in fetch_folder(M, folder, counts[folder]):
                r.update(label=label, gold=gold, fastmail_said_spam=fm,
                         source=folder)
                rows.append(r)
    finally:
        try:
            M.logout()
        except Exception:  # noqa: BLE001
            pass

    out = pathlib.Path(args.out)
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(json.dumps(r) for r in rows))

    gold_pos = sum(1 for r in rows if r["gold"] and r["label"] == 1)
    gold_neg = sum(1 for r in rows if r["gold"] and r["label"] == 0)
    print(f"\nwrote {len(rows)} -> {out}", file=sys.stderr)
    print(f"  gold spam {gold_pos} / gold ham {gold_neg} / "
          f"fastmail-labeled {len(rows) - gold_pos - gold_neg}", file=sys.stderr)


if __name__ == "__main__":
    main()
