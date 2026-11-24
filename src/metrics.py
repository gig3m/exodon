"""Scoring. Pure stdlib so the harness runs anywhere without a numpy pin.

The operational question for a mail client is not "what is the accuracy" -- it
is "how much spam can I auto-file while almost never touching real mail", and
"can I trust the probability enough to route on it". So the headline numbers
here are recall at a pinned false-positive rate, and calibration error.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class Row:
    label: int          # 1 = spam (ground truth from Kyle's own filing)
    p: float            # predicted P(spam)
    fastmail: int       # what the incumbent said
    source: str         # which folder it came from
    id: str = ""


def _finite(rows: list[Row]) -> list[Row]:
    return [r for r in rows if not math.isnan(r.p)]


def confusion(rows: list[Row], thr: float) -> dict:
    tp = fp = tn = fn = 0
    for r in rows:
        pred = r.p >= thr
        if r.label == 1 and pred:
            tp += 1
        elif r.label == 1:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec and rec and not math.isnan(prec + rec) else float("nan")
    return {"threshold": thr, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "fpr": fpr, "f1": f1,
            "accuracy": (tp + tn) / len(rows) if rows else float("nan")}


def roc_auc(rows: list[Row]) -> float:
    """Rank-based AUC (Mann-Whitney U), ties averaged."""
    rows = _finite(rows)
    pos = [r.p for r in rows if r.label == 1]
    neg = [r.p for r in rows if r.label == 0]
    if not pos or not neg:
        return float("nan")
    ordered = sorted((r.p, r.label) for r in rows)
    ranks: dict[int, float] = {}
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1][0] == ordered[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    rank_sum = sum(ranks[k] for k, (_, lab) in enumerate(ordered) if lab == 1)
    n1, n0 = len(pos), len(neg)
    return (rank_sum - n1 * (n1 + 1) / 2) / (n1 * n0)


def pr_auc(rows: list[Row]) -> float:
    """Average precision over the descending-score sweep."""
    rows = sorted(_finite(rows), key=lambda r: -r.p)
    total_pos = sum(r.label for r in rows)
    if not total_pos:
        return float("nan")
    tp = fp = 0
    prev_rec = 0.0
    ap = 0.0
    for r in rows:
        if r.label == 1:
            tp += 1
        else:
            fp += 1
        rec = tp / total_pos
        prec = tp / (tp + fp)
        ap += prec * (rec - prev_rec)
        prev_rec = rec
    return ap


def threshold_at_fpr(rows: list[Row], max_fpr: float) -> dict:
    """Lowest threshold whose false-positive rate stays within budget.

    This is the number that decides whether the thing is shippable: a mail
    client that files one real message in a hundred as junk is worse than one
    that files no spam at all.
    """
    rows = _finite(rows)
    best = None
    for thr in sorted({r.p for r in rows} | {0.0, 1.0}):
        c = confusion(rows, thr)
        if not math.isnan(c["fpr"]) and c["fpr"] <= max_fpr:
            if best is None or c["recall"] > best["recall"]:
                best = c
    return best or {"note": f"no threshold achieves FPR <= {max_fpr}"}


def calibration(rows: list[Row], bins: int = 10) -> dict:
    """Brier score, expected calibration error, and the reliability table.

    ECE is the headline for the jev-vs-local-model comparison: a model whose
    0.8 actually means 80% lets code route on the number. One that piles every
    answer at 0.02/0.98 forces a hard cutover with no review band.
    """
    rows = _finite(rows)
    if not rows:
        return {}
    brier = sum((r.p - r.label) ** 2 for r in rows) / len(rows)
    table = []
    ece = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        chunk = [r for r in rows if (lo <= r.p < hi) or (b == bins - 1 and r.p == 1.0)]
        if not chunk:
            table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": 0})
            continue
        conf = sum(r.p for r in chunk) / len(chunk)
        acc = sum(r.label for r in chunk) / len(chunk)
        ece += len(chunk) / len(rows) * abs(conf - acc)
        table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": len(chunk),
                      "mean_p": round(conf, 3), "actual_spam_rate": round(acc, 3),
                      "gap": round(acc - conf, 3)})
    return {"brier": brier, "ece": ece, "reliability": table}


def routing(rows: list[Row], junk_at: float = 0.95, inbox_below: float = 0.40) -> dict:
    """Three-band policy: auto-junk / hold for review / straight to inbox.

    Reports how much mail each band absorbs and how many mistakes ride along,
    because the value of a calibrated score is that the middle band is small.
    """
    rows = _finite(rows)
    auto = [r for r in rows if r.p >= junk_at]
    inbox = [r for r in rows if r.p < inbox_below]
    review = [r for r in rows if inbox_below <= r.p < junk_at]
    n = len(rows) or 1
    return {
        "auto_junk": {"n": len(auto), "pct": round(100 * len(auto) / n, 1),
                      "real_mail_caught": sum(1 for r in auto if r.label == 0)},
        "review": {"n": len(review), "pct": round(100 * len(review) / n, 1)},
        "to_inbox": {"n": len(inbox), "pct": round(100 * len(inbox) / n, 1),
                     "spam_let_through": sum(1 for r in inbox if r.label == 1)},
    }


def beats_incumbent(rows: list[Row], thr: float) -> dict:
    """The point of the exercise.

    Everything in the Identified Spam folder is mail Fastmail delivered and
    Kyle had to file by hand -- the incumbent's false negatives. Catching those
    without disturbing Archive is the only result that justifies the work.
    """
    missed = [r for r in _finite(rows) if r.label == 1 and r.fastmail == 0]
    caught = sum(1 for r in missed if r.p >= thr)
    ham = [r for r in _finite(rows) if r.label == 0]
    return {
        "incumbent_false_negatives": len(missed),
        "recovered_by_model": caught,
        "recovery_rate": round(caught / len(missed), 3) if missed else float("nan"),
        "new_false_positives_on_archive": sum(1 for r in ham if r.p >= thr),
        "archive_n": len(ham),
    }


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% CI on a rate, so a spike on a few hundred messages is not
    over-read. Wilson rather than normal because the rates here sit near 0."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - m), min(1.0, c + m))


def report(rows: list[Row], name: str, cost_per_btok: float = 42.0,
           tokens: int = 0, latencies: list[float] | None = None) -> dict:
    fin = _finite(rows)
    thr_strict = threshold_at_fpr(fin, 0.001)   # <=0.1% of real mail touched
    thr_loose = threshold_at_fpr(fin, 0.01)     # <=1%
    out = {
        "backend": name,
        "n": len(rows),
        "n_scored": len(fin),
        "n_errors": len(rows) - len(fin),
        "spam_rate": round(sum(r.label for r in fin) / len(fin), 3) if fin else None,
        "roc_auc": round(roc_auc(fin), 4),
        "pr_auc": round(pr_auc(fin), 4),
        "at_threshold_0.5": confusion(fin, 0.5),
        "at_fpr_0.1pct": thr_strict,
        "at_fpr_1pct": thr_loose,
        "calibration": calibration(fin),
        "routing": routing(fin),
    }
    if isinstance(thr_strict, dict) and "threshold" in thr_strict:
        out["vs_fastmail"] = beats_incumbent(fin, thr_strict["threshold"])
        rec = thr_strict["recall"]
        tp, fn = thr_strict["tp"], thr_strict["fn"]
        lo, hi = wilson(tp, tp + fn)
        out["recall_ci95"] = [round(lo, 3), round(hi, 3)]
        del rec
    if latencies:
        s = sorted(latencies)
        out["latency_ms"] = {
            "p50": round(s[len(s) // 2], 1),
            "p95": round(s[int(len(s) * 0.95)], 1),
            "mean": round(sum(s) / len(s), 1),
        }
    if tokens:
        out["cost"] = {
            "input_tokens": tokens,
            "usd_for_corpus": round(tokens / 1e9 * cost_per_btok, 6),
            "usd_per_million_emails": round(
                tokens / max(len(fin), 1) * 1e6 / 1e9 * cost_per_btok, 4),
        }
    return out
