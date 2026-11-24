#!/usr/bin/env python3
"""Pin the corpus labels using facts the mailbox can prove.

    keys exec MY_IMAP_SECRET -- python3 src/pin.py   # .env: account + EXODON_IMAP_PASSWORD_ENV=MY_IMAP_SECRET

Folder placement is not ground truth: spam gets bulk-archived, and legit mail
gets dragged into the training folder by mistake. So instead of trusting the
folder, this collects evidence per message:

  answered     Kyle replied to it (IMAP \\Answered)
  flagged      Kyle flagged it
  corresponded Kyle has sent mail to this sender (from the Sent folder)
  seen         Kyle opened it -- weak, recorded but never decisive

and assigns each message a status:

  confirmed_ham  in Archive AND answered/flagged/corresponded. The folder and
                 the facts agree, so no human review needed.
  conflict       in a spam folder BUT answered/flagged/corresponded. The facts
                 contradict the folder (the law-firm case). Reviewed first.
  needs_review   everything else. The folder is the only evidence.

Evidence only ever confirms a filing or raises a conflict. It never silently
relabels anything: a reply to a cold pitch ("please remove me") is still a
reply, so an automated flip would be wrong some of the time.

Writes corpus/evidence.jsonl, keyed by message id, alongside the corpus rather
than into it, so rebuilding the corpus does not wipe it.
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
import re
import ssl
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402
CORPUS = config.DATA / "corpus" / "corpus.jsonl"
EVIDENCE = config.DATA / "corpus" / "evidence.jsonl"


def sent_addresses(M: imaplib.IMAP4_SSL) -> set[str]:
    """Everyone Kyle has ever sent mail to, across the whole Sent folder."""
    ok, _ = M.select("Sent", readonly=True)
    if ok != "OK":
        sys.exit("cannot select Sent")
    ok, data = M.uid("SEARCH", None, "ALL")
    uids = data[0].split()
    addrs: set[str] = set()
    for i in range(0, len(uids), 500):
        chunk = b",".join(uids[i:i + 500]).decode()
        ok, resp = M.uid("FETCH", chunk, "(BODY.PEEK[HEADER.FIELDS (TO CC BCC)])")
        for item in resp:
            if not isinstance(item, tuple):
                continue
            msg = email.message_from_bytes(item[1], policy=email.policy.compat32)
            fields = msg.get_all("To", []) + msg.get_all("Cc", []) + msg.get_all("Bcc", [])
            for _, a in email.utils.getaddresses([str(f) for f in fields]):
                if a:
                    addrs.add(a.strip().lower())
    print(f"  Sent: {len(uids)} messages, {len(addrs)} distinct recipients",
          file=sys.stderr)
    return addrs


def folder_flags(M: imaplib.IMAP4_SSL, folder: str, uids: list[str]) -> dict[str, set[str]]:
    ok, _ = M.select(f'"{folder}"', readonly=True)
    if ok != "OK":
        return {}
    out: dict[str, set[str]] = {}
    for i in range(0, len(uids), 500):
        chunk = ",".join(uids[i:i + 500])
        ok, resp = M.uid("FETCH", chunk, "(FLAGS)")
        for item in resp:
            line = item if isinstance(item, bytes) else item[0]
            m_uid = re.search(rb"UID (\d+)", line)
            m_fl = re.search(rb"FLAGS \(([^)]*)\)", line)
            if m_uid and m_fl:
                out[m_uid.group(1).decode()] = {
                    f.decode().lower() for f in m_fl.group(1).split()}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    args = ap.parse_args()

    pw = config.imap_password()

    rows = [json.loads(line) for line in CORPUS.read_text().splitlines() if line.strip()]
    by_folder: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        folder, uid = r["id"].rsplit(":", 1)
        by_folder[folder].append(uid)

    M = imaplib.IMAP4_SSL(config.IMAP_HOST, 993, ssl_context=ssl.create_default_context())
    M.login(config.imap_user(), pw)
    try:
        sent = sent_addresses(M)
        flags = {f: folder_flags(M, f, uids) for f, uids in by_folder.items()}
    finally:
        try:
            M.logout()
        except Exception:  # noqa: BLE001
            pass

    out = []
    for r in rows:
        folder, uid = r["id"].rsplit(":", 1)
        fl = flags.get(folder, {}).get(uid, set())
        ev = {
            "id": r["id"],
            "answered": "\\answered" in fl,
            "flagged": "\\flagged" in fl,
            "seen": "\\seen" in fl,
            "corresponded": r.get("from_email", "") in sent,
        }
        proof_of_ham = ev["answered"] or ev["flagged"] or ev["corresponded"]
        if r["label"] == 0 and proof_of_ham:
            ev["status"] = "confirmed_ham"
        elif r["label"] == 1 and proof_of_ham:
            ev["status"] = "conflict"
        else:
            ev["status"] = "needs_review"
        out.append(ev)

    EVIDENCE.write_text("\n".join(json.dumps(e) for e in out))

    tally = Counter((r["source"], e["status"]) for r, e in zip(rows, out))
    print(f"\nwrote {len(out)} -> {EVIDENCE}", file=sys.stderr)
    for (src, st), n in sorted(tally.items()):
        print(f"  {src:16} {st:14} {n}", file=sys.stderr)


if __name__ == "__main__":
    main()
