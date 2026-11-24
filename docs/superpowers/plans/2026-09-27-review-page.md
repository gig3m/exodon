# Review page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A tailnet-only page at exodon.example.net showing recent shadow decisions against the owner's filing, with mark and allow/block feedback.

**Architecture:** The watcher gains a heartbeat and hourly re-checking grades. A new stdlib web server in its own container reads the same sqlite log (WAL), writes marks, and appends validated lines to the list files. Pure logic lives in `listedit.py` and `grade.py` so it is testable without a server.

**Tech Stack:** Python 3.12 stdlib (`http.server`, `sqlite3`), httpx (existing), Docker Compose, NPM, a DNS record, an uptime monitor.

**Spec:** `docs/superpowers/specs/2026-09-27-review-page-design.md`

## Global Constraints

- The web container holds no mail token and never calls JMAP.
- Host allowlist: `exodon.example.net`, `localhost:8799`, `exodon-web:8799`; POST Origin exactly `https://exodon.example.net`.
- List patterns derive from the logged sender only; address scope needs `^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$`; domain scope refused for free-mail/bulk platforms.
- Every written list file must parse to the old entries plus/minus exactly one.
- `LABEL = "coalesce(feedback, outcome)"` is the only effective-label expression.
- No new dependencies. Tests: `python3 -m unittest discover -s tests`.
- Blocking privacy scan before every commit (no real addresses in tests).

## Review Focus

1. A hand edit to a list file racing a page write: expect a retry or a refusal, never a lost edit (test: mtime changes between read and replace).
2. A subject containing ` ` or `\r`: expect one note line, no second pattern (test in Task 4).
3. A decision whose sender is empty or has no `@`: expect a refusal, not a 500 (test in Task 4).
4. A message moved back to the inbox after being graded: expect its outcome cleared (test in Task 3).
5. The web server starting before the watcher has migrated (no `feedback` column yet): expect the page to render, with marks disabled, not crash (test in Task 5).

---

### Task 1: Pings from the push stream

**Files:** Modify `src/jmap.py` (`events`); Test `tests/test_web.py` (new file, `Sse` class).

**Interfaces:** Produces `jmap.parse_sse(lines: Iterable[str]) -> Iterator[dict]`: state events as parsed JSON, pings as `{"type": "ping"}`. `Jmap.events()` delegates to it.

- [ ] Test: `list(parse_sse(["event: ping", "data: {\"interval\":60}", "", "event: state", "data: {\"@type\":\"StateChange\"}", ""]))` equals `[{"type": "ping"}, {"@type": "StateChange"}]`. Run, expect ImportError.
- [ ] Implement `parse_sse` (move the loop out of `events()`; on a blank line yield state JSON or the ping dict). Run, expect pass.
- [ ] Commit.

### Task 2: Store: feedback columns, list_changes, WAL, reader mode

**Files:** Modify `src/shadow.py` (`SCHEMA`, `Store.__init__`); Test `tests/test_shadow.py` (`Store` class).

**Interfaces:** Produces `Store(path, legacy_account=None, migrate=True)`. With `migrate=True`: legacy migration, `SCHEMA` (now including `list_changes (id integer primary key, at, action, list, line, account, email_id, undone_at)`), `ALTER TABLE decisions ADD COLUMN feedback/feedback_at` tolerating "duplicate column", `pragma journal_mode=wal`. With `migrate=False`: connect only. `Store.cols` as before.

- [ ] Tests: opening an old-shape log twice adds `feedback`/`feedback_at` and `list_changes` with no error; `pragma journal_mode` returns `wal`; `Store(path, migrate=False)` on a fresh file performs no DDL (no `decisions` table).
- [ ] Implement. Run the full suite. Commit.

### Task 3: Hourly re-checking grades with one effective label

**Files:** Modify `src/grade.py`, `src/shadow.py` (`Shadow.run`, `Shadow.maybe_grade`, new `Shadow.alive`); Test `tests/test_shadow.py` (`Regrade` class).

**Interfaces:**
- `grade.LABEL: str`.
- `grade.grade(store, client, account, training=None) -> int` re-checks rows with age < 168 h or `outcome is null`; `None` clears `outcome`/`outcome_folder`; commits per batch of 100.
- `grade.summary(store, account, days=None) -> dict` with keys `total, graded, spam, spam_caught, real, real_screened, fastmail_spam, fastmail_screened, deleted`, all counted on `LABEL`, `days` limiting by `received_at`.
- `Shadow.alive()` sets `<account>:alive`; `run()` calls it on every event, `sync()` only for non-pings, then `maybe_grade(every_h=1.0)`.
- `GRADE_AFTER_H` removed.

- [ ] Tests with a fake client (`mailboxes()` returns a dict; `call("Email/get")` returns mailboxIds from a dict):
  - filed in Identified Spam 1 h after arrival → `spam` (no wait);
  - graded `real`, now in the training folder, 3 days old → becomes `spam`;
  - graded `real`, 10 days old, now in spam → stays `real`;
  - graded `real`, moved back to Inbox → `outcome` null;
  - `feedback='spam'` on a deleted row → `summary` counts it as spam, and as graded;
  - `feedback` on an inbox row with null outcome → graded.
- [ ] Implement; switch `_report_account` queries to `LABEL`, and use `summary` for the headline counts. Run suite. Commit.

### Task 4: listedit: candidate, verdict, safe append/remove

**Files:** Create `src/listedit.py`; Test `tests/test_listedit.py`.

**Interfaces:**
- `class Refused(Exception)`
- `is_platform(addr) -> bool` (`context.org(addr) == addr`)
- `default_scope(addr) -> "address" | "domain"`
- `candidate(addr, scope) -> str` or `Refused`
- `@dataclass Verdict(status: str, pattern: str, message: str)`, status in `covered|ok|blocked`
- `verdict(entries, addr, name, which, pattern, list_note=None) -> Verdict`
- `note(subject) -> str`; `line_for(pattern, subject, today) -> str`
- `append(path, which, line) -> None`; `remove(path, which, line) -> None` (validate, mtime guard with one retry, `os.replace`, mode kept)

- [ ] Tests (placeholder domains only):
  - default scope: `a@gmail.com` → address, `a@mail.acme.com` → domain, candidate `@acme.com`;
  - refusals: `*@gmail.com`, `a#b@acme.com`, `a@b@c`, empty, domain scope for `x@gmail.com`;
  - verdicts: none → ok; `@acme.com` in allow, adding allow → covered, with the not-authenticated note when `list_note` says ignored; block `@acme.com`, adding allow `bob@acme.com` → ok "overrides block @acme.com"; allow `bob@acme.com`, adding block `@acme.com` for bob → blocked; identical allow exists, adding block → blocked;
  - `note("x\r\n@gmail.com #\"y")` has no line breaks, `#` or `"`; `line_for` parses to exactly one entry;
  - append then `load` = old + one; append refuses when the old file has a bad line in a way that would change entries (validation path) — simulate by monkeypatching `lists.load`; mtime changed between read and replace → retried, hand-added line preserved;
  - remove: removes only its line; refuses when missing or duplicated.
- [ ] Implement. Run suite. Commit.

### Task 5: web.py

**Files:** Create `src/web.py`; Test `tests/test_web.py`.

**Interfaces:** `web.make_server(port, db_path, lists_dir) -> ThreadingHTTPServer`; `web.render_page(db, params, lists_dir) -> str`; routes `GET /`, `GET /health`, `POST /api/mark|/api/list/preview|/api/list/add|/api/list/undo`.

- [ ] Tests (server on an ephemeral port in a thread, temp DB and lists, `Host: localhost:8799`):
  - foreign Host → 421; POST with no Origin, foreign Origin, or `text/plain` → 403;
  - mark round trip sets and clears `feedback`; unknown email_id → 400;
  - list add writes one line and a `list_changes` row; undo removes it and sets `undone_at`;
  - a `<script>` subject and a `"` in the sender name are escaped; CSP, X-Frame-Options and Referrer-Policy present;
  - `/health`: 200 with a fresh heartbeat, 503 with a stale one;
  - DB without `feedback` column (older log) → page renders 200.
- [ ] Implement. Run suite. Commit.

### Task 6: Deploy

**Files:** Modify `docker/docker-compose.yml`, `src/lists.py` docstring, `docs/shadow-mode.md`; outside the repo: DNS, NPM, the uptime monitor.

- [ ] Compose: `exodon-web` service (same image, `command: python3 src/web.py`, no ports, network `nginx-proxy-manager_default` external, mounts `..:/app:ro`, `../var:/app/var`, `../lists:/app/lists`).
- [ ] `docker/up.sh`; confirm both containers up; `docker exec exodon-web python3 -c` fetch of `/health` with `Host: localhost:8799`.
- [ ] DNS record, NPM host → `exodon-web:8799` (TLS); `curl https://exodon.example.net/health`.
- [ ] Uptime monitor endpoint on `/health` (dashboard-only).
- [ ] Live add + undo with a throwaway pattern; watcher logs "lists reloaded".
- [ ] Screenshot at desktop and phone width; fix what looks wrong.
- [ ] Commit, push.
