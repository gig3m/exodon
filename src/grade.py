#!/usr/bin/env python3
"""Grade shadow decisions against where the owner actually filed each message.

    keys exec MY_RO_JMAP_TOKEN -- python3 src/grade.py      # grade, then report
    python3 src/grade.py report                                  # report only, offline

Read-only: it looks up each logged message's current folder and nothing else.
A message is graded as soon as it leaves the inbox and re-checked for a week,
so a later re-filing wins; after that its grade is final. The owner's mark
from the review page overrides the folder. See docs/shadow-mode.md for what
each folder counts as.
"""

from __future__ import annotations

import datetime as dt
import logging
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import config  # noqa: E402
import shadow as S  # noqa: E402

RECHECK_H = 24 * 7
# The label a decision is scored against: the owner's mark if any, else the
# folder. The only definition -- every count here and on the page uses it.
LABEL = "coalesce(feedback, outcome)"


def _age_hours(received_at: str) -> float:
    try:
        t = dt.datetime.fromisoformat(received_at.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 3600


def grade(store: S.Store, client, account: str = "default", training: str | None = None) -> int:
    """Look up where each recent (or never graded) message is now and store
    it. Commits per batch so the log is never locked across a network call."""
    boxes = client.mailboxes()
    junk = {b["name"] for b in boxes.values() if b.get("role") == "junk"}
    # decided_at stands in for a missing received date, so such rows still age out
    # Mail exodon itself moved to Spam counts as arrived there: if Spam's
    # auto-purge removes it, that is nobody's verdict either.
    act = "action" if "action" in store.cols else "null"
    rows = store.db.execute("select email_id, coalesce(nullif(received_at, ''), decided_at), "
                            f"arrived_in, outcome, {act} from decisions where account=?",
                            (account,)).fetchall()
    due = {i: (_age_hours(r), bool(junk & set((a or "").split(","))) or m == "moved")
           for i, r, a, o, m in rows if o is None or _age_hours(r) < RECHECK_H}
    ids, changed = list(due), 0
    for k in range(0, len(ids), 100):
        batch = ids[k:k + 100]
        r = client.call("Email/get", {"ids": batch, "properties": ["mailboxIds"]})
        found = {m["id"]: m.get("mailboxIds") for m in r["list"]}
        for i in batch:
            age, arrived_junk = due[i]
            mb = found.get(i)
            o = S.outcome(mb, boxes, age, training=training, arrived_junk=arrived_junk)
            names = None if o is None else (
                ",".join(boxes.get(b, {}).get("name", b) for b in (mb or {})) or "deleted")
            prev = store.db.execute("select outcome from decisions where account=? and "
                                    "email_id=?", (account, i)).fetchone()[0]
            store.db.execute("update decisions set outcome=?, outcome_folder=?, graded_at=? "
                             "where account=? and email_id=?", (o, names, S.now(), account, i))
            changed += prev != o
        store.db.commit()
    return changed


def summary(store: S.Store, account: str, days: float | None = None,
            label: str = LABEL) -> dict:
    """Headline counts on the effective label, optionally for recent mail only."""
    since = "" if days is None else (dt.datetime.now(dt.timezone.utc)
                                     - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    one = lambda where: store.db.execute(
        f"select count(*) from decisions where account=? and received_at>=? and {where}",
        (account, since)).fetchone()[0]
    return {
        "total": one("1"),
        "graded": one(f"{label} is not null"),
        "spam": one(f"{label}='spam'"),
        "spam_caught": one(f"{label}='spam' and would='screen'"),
        "real": one(f"{label}='real'"),
        "real_screened": one(f"{label}='real' and would='screen'"),
        "fastmail_spam": one(f"{label}='fastmail_spam'"),
        "fastmail_screened": one(f"{label}='fastmail_spam' and would='screen'"),
        "deleted": one(f"{label}='deleted'"),
        "unknown": one(f"{label}='unknown'"),
    }


def report(store: S.Store) -> None:
    accounts = [r[0] for r in store.db.execute(
        "select distinct account from decisions order by account")] or ["-"]
    for i, a in enumerate(accounts):
        if i:
            print("\n" + "-" * 72 + "\n")
        _report_account(store, a)


def _report_account(store: S.Store, account: str) -> None:
    q = lambda sql, *a: store.db.execute(sql, (account, *a)).fetchall()
    training = next((a.training_folder for a in config.accounts() if a.name == account),
                    config.TRAINING_FOLDER)
    (total,) = q("select count(*) from decisions where account=?")[0]
    graded = q(f"select count(*) from decisions where account=? and {LABEL} is not null")[0][0]
    by = dict(q(f"select {LABEL}, count(*) from decisions where account=? and {LABEL} is not null "
                f"group by {LABEL}"))
    print(f"[{account}] {total} decisions logged; {graded} graded "
          f"({total - graded} still in the inbox or not checked yet).")
    spam, real = by.get("spam", 0), by.get("real", 0)
    deleted = by.get("deleted", 0)
    print(f"Of the graded: {spam} you filed as spam, {real} real mail you kept, "
          f"{deleted} deleted (listed separately, not scored), "
          f"{by.get('fastmail_spam', 0)} left in Fastmail's Spam (moderate signal, shown separately), "
          f"{by.get('unknown', 0)} unknown (not counted).\n")
    def count(outcome, would):
        return q(f"select count(*) from decisions where account=? and {LABEL}=? and would=?",
                 outcome, would)[0][0]

    if "action" in store.cols:
        moved = q("select count(*), sum(outcome='real'), sum(outcome='spam') from decisions "
                  "where account=? and action='moved'")[0]
        if moved[0]:
            print(f"LIVE: moved {moved[0]} to Spam; you pulled {moved[1] or 0} back out as real "
                  f"and filed {moved[2] or 0} as spam. The rest are counted below as "
                  "\"left in Fastmail's Spam\".\n")
    if not spam and not real:
        print("Nothing to score yet.")
    else:
        _score(q, count, spam, real, training)
    _moderate_and_deleted(q, count, by)


def _score(q, count, spam, real, training):
    print("Spam you filed:")
    print(f"  would have been screened:        {count('spam', 'screen')} of {spam}")
    print(f"  would have gone to review:       {count('spam', 'review')}")
    print(f"  would have reached your inbox:   {count('spam', 'inbox')}")
    print("Real mail you kept:")
    print(f"  would have been screened (bad):  {count('real', 'screen')} of {real}")
    print(f"  would have gone to review:       {count('real', 'review')}")
    for src, entry, p, frm, subj in q("select source, list_entry, p_spam, from_email, subject "
                                      f"from decisions where account=? and {LABEL}='real' "
                                      "and would='screen' order by decided_at"):
        why = (f"blocked by {entry}" if src == "block" else f"rule: {entry}" if src == "rule"
               else f"model {p:.3f}")
        print(f"    - {frm[:34]:34} {subj[:44]:44} ({why})")

    # Other cut-offs, from the stored probability: what a stricter or looser
    # screen would have done on the same mail.
    print("\nIf the model's screen line were somewhere else (lists and rule unchanged):")
    for cut in (0.999, 0.99, 0.95, 0.9, 0.5):
        hit = "(source in ('block','rule') or (source='model' and p_spam>=?))"
        caught = q(f"select count(*) from decisions where account=? and {LABEL}='spam' and {hit}",
                   cut)[0][0]
        lost = q(f"select count(*) from decisions where account=? and {LABEL}='real' and {hit}",
                 cut)[0][0]
        print(f"  at {cut:<5}  catches {caught} of {spam} spam, screens {lost} of {real} real")

    fm = lambda o: q(f"select count(*) from decisions where account=? and {LABEL}=? and "
                     "arrived_in like '%Spam%' and arrived_in not like ?", o, f"%{training}%")[0][0]
    print(f"\nFastmail on the same mail: put {fm('spam')} of your {spam} spam in its Spam folder, "
          f"and {fm('real')} of {real} real emails.")



def _moderate_and_deleted(q, count, by):
    deleted = by.get("deleted", 0)
    # Fastmail's own Spam, left there: a moderate spam signal -- Fastmail's
    # verdict that the owner did not overturn, but never looked at closely.
    # Kept apart from the score above so a weaker label cannot blur it.
    fs = by.get("fastmail_spam", 0)
    if fs:
        print(f"\nLeft in Fastmail's Spam (moderate signal): {fs}")
        print(f"  exodon would have screened:      {count('fastmail_spam', 'screen')}")
        print(f"  would have gone to review:       {count('fastmail_spam', 'review')}")
        print(f"  would have reached your inbox:   {count('fastmail_spam', 'inbox')}  (possible misses)")
        for src, entry, p, frm, subj in q("select source, list_entry, p_spam, from_email, subject "
                                          f"from decisions where account=? and {LABEL}='fastmail_spam' "
                                          "and would='inbox' order by decided_at limit 10"):
            why = f"allowed by {entry}" if src == "allow" else f"model {p:.3f}" if p is not None else src
            print(f"    - {frm[:34]:34} {subj[:44]:44} ({why})")

    # Deleted mail is ambiguous: usually read-and-done, sometimes spam binned
    # instead of filed. Not scored; the ones gemma would have screened are
    # listed so they can be eyeballed.
    screened = q("select source, list_entry, p_spam, from_email, subject from decisions "
                 f"where account=? and {LABEL}='deleted' and would='screen' order by decided_at")
    print(f"\nDeleted mail (not scored): {deleted}, of which exodon would have screened "
          f"{len(screened)}:")
    for src, entry, p, frm, subj in screened:
        why = (f"blocked by {entry}" if src == "block" else f"rule: {entry}" if src == "rule"
               else f"model {p:.3f}")
        print(f"    - {frm[:34]:34} {subj[:44]:44} ({why})")


def write_report(store: S.Store, path: pathlib.Path) -> None:
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print(f"exodon report, {S.now()}\n")
        report(store)
    path.write_text(buf.getvalue())


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    accounts = config.accounts()
    store = S.Store(config.STATE / "shadow.db", legacy_account=accounts[0].name)
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        return report(store)
    import jmap as J
    for acct in accounts:
        try:
            tok = acct.token()
        except SystemExit as e:
            print(f"[{acct.name}] skipped: {e}")
            continue
        n = grade(store, J.Jmap(tok), acct.name, acct.training_folder)
        print(f"[{acct.name}] graded {n} new decisions")
    print()
    report(store)


if __name__ == "__main__":
    main()
