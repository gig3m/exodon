"""The readout: what exodon decided over a recent window, as JSON, for another
agent to summarize and second-guess. Read-only; served by the review
page at GET /api/readout to the containers in EXODON_WEB_READERS holding an
EXODON_READOUT_TOKEN_* token.

Per mailbox: counts, everything screened (moved, or would have been in
shadow mode), the unsure ones, where the owner's filing disagreed, and model
errors -- with a short body preview so a second reader can judge for itself.
"""

from __future__ import annotations

import datetime as dt

import config
import grade as G
import shadow as S

MAX_HOURS = 24 * 14
ROW_CAP = 200


def since(hours: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).isoformat(
        timespec="seconds")


def _row(r: dict) -> dict:
    out = {"from": r["from_email"], "name": r["from_name"] or None,
           "subject": r["subject"], "received_at": r["received_at"],
           "source": r["source"], "score": r["p_spam"],
           "list_entry": r["list_entry"], "authenticated": bool(r["authenticated"]),
           "action": r.get("action"), "owner_label": r["label"],
           "now_in": r["outcome_folder"] or None, "preview": r.get("preview") or None}
    if r["source"] == "model" and r["p_spam"] is not None:
        out["sure"] = r["p_spam"] >= config.SURE_AT
    elif r["source"] == "block":
        out["sure"] = True
    elif r["source"] == "rule":
        out["sure"] = False
    return out


def readout(store: S.Store, accounts: list[config.Account], hours: float = 24) -> dict:
    hours = max(1.0, min(float(hours), MAX_HOURS))
    start = since(hours)
    label = G.LABEL if "feedback" in store.cols else "outcome"
    extra = ", ".join(c for c in ("action", "preview") if c in store.cols)
    cols = ("from_email, from_name, subject, received_at, decided_at, source, would, "
            "p_spam, list_entry, authenticated, outcome_folder, error"
            + (f", {extra}" if extra else "") + f", {label} as label")
    out = {"generated_at": S.now(), "window_hours": hours, "since": start,
           "screen_at": config.SCREEN_AT, "sure_at": config.SURE_AT,
           "review_page": config.WEB_ORIGIN or None, "accounts": {}}
    for acct in accounts:
        cur = store.db.cursor()  # dict rows for this query only; Store.get wants tuples
        cur.row_factory = lambda c, row: {d[0]: v for d, v in zip(c.description, row)}
        rows = cur.execute(f"select {cols} from decisions where account=? and "
                           "decided_at>? order by decided_at desc", (acct.name, start)).fetchall()
        out["accounts"][acct.name] = _account(store, acct, rows)
    return out


def _account(store: S.Store, acct: config.Account, rows: list[dict]) -> dict:
    counts = {"total": len(rows), "inbox": 0, "review": 0, "screen": 0, "error": 0,
              "by_allow_list": 0, "by_block_list": 0, "by_rule": 0, "by_model": 0,
              "moved": 0, "move_failed": 0}
    for r in rows:
        counts[r["would"]] = counts.get(r["would"], 0) + 1
        counts[{"allow": "by_allow_list", "block": "by_block_list",
                "rule": "by_rule"}.get(r["source"],
                                                                        "by_model")] += 1
        a = r.get("action") or ""
        if a == "moved":
            counts["moved"] += 1
        elif a.startswith("move failed"):
            counts["move_failed"] += 1

    screened = [r for r in rows if r["would"] == "screen"]
    unsure = [r for r in rows if r["would"] == "review"
              or (r["would"] == "screen" and r["source"] == "rule")
              or (r["would"] == "screen" and r["source"] == "model"
                  and (r["p_spam"] or 0) < config.SURE_AT)]
    # The owner's filing (or a mark on the review page) said otherwise.
    disagreed = [r for r in rows if (r["would"] == "screen" and r["label"] == "real")
                 or (r["would"] == "inbox" and r["label"] == "spam")]
    errors = [r for r in rows if r["would"] == "error"]
    alive = store.get(f"{acct.name}:alive")
    started = store.db.execute("select max(at) from events where kind='live' and detail like ?",
                               (f"[{acct.name}]%",)).fetchone()[0]
    note = None
    if not acct.live:
        note = "shadow mode: nothing was moved; 'screened' means it would have been"
    elif started:
        note = (f"live since {started}; mail decided before then was shadow only "
                "(screened, not moved)")
    return {
        "mode": acct.mode,
        "live_since": started if acct.live else None,
        "note": note,
        "last_heartbeat": alive,
        "counts": counts,
        "screened": [_row(r) for r in screened[:ROW_CAP]],
        "unsure": [_row(r) for r in unsure[:ROW_CAP]],
        "owner_disagreed": [_row(r) for r in disagreed[:ROW_CAP]],
        "model_errors": {"count": len(errors),
                         "latest": (errors[0]["error"] or "")[:300] if errors else None,
                         "latest_at": errors[0]["decided_at"] if errors else None},
        "truncated": any(len(x) > ROW_CAP for x in (screened, unsure, disagreed)),
    }
