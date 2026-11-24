"""Minimal JMAP client: session, method calls, push events.

READ-ONLY BY CONSTRUCTION unless built with `write=True`. `call` refuses every
method outside READ_METHODS, always, so a bug cannot move, flag or delete mail
even if handed a writable token. A live mailbox's client (`write=True`) gets
exactly two writes, each its own narrow method: `move` (one message from one
mailbox to another, nothing else in the patch) and `create` (a new message in
a mailbox -- the digest). Nothing here can destroy, flag, or send mail.
"""

from __future__ import annotations

import json
from typing import Iterable, Iterator

import httpx

SESSION_URL = "https://api.fastmail.com/jmap/session"
USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]
READ_METHODS = {"Mailbox/get", "Email/get", "Email/query", "Email/changes"}


class ReadOnlyViolation(RuntimeError):
    pass


class JmapError(RuntimeError):
    def __init__(self, method: str, err: dict):
        self.type = err.get("type", "")
        super().__init__(f"{method}: {err}")


class Jmap:
    def __init__(self, token: str, session_url: str = SESSION_URL, write: bool = False):
        self.write = write
        self.http = httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=60)
        s = self.http.get(session_url).raise_for_status().json()
        self.account = s["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        self.api_url = s["apiUrl"]
        self.event_url = s["eventSourceUrl"]
        self.read_only = s["accounts"][self.account].get("isReadOnly", False)

    def call(self, method: str, args: dict) -> dict:
        if method not in READ_METHODS:
            raise ReadOnlyViolation(f"refusing non-read JMAP method {method}")
        return self._post(method, args)

    def _set(self, args: dict) -> dict:
        if not self.write:
            raise ReadOnlyViolation("refusing Email/set: this client is read-only")
        r = self._post("Email/set", args)
        failed = r.get("notUpdated") or r.get("notCreated")
        if failed:
            raise JmapError("Email/set", next(iter(failed.values())))
        return r

    def move(self, email_id: str, src: str, dst: str) -> None:
        """Move one message from mailbox `src` to `dst`. Only these two
        mailboxIds entries are in the patch; keywords and the rest stay put."""
        self._set({"update": {email_id: {f"mailboxIds/{src}": None,
                                         f"mailboxIds/{dst}": True}}})

    def create(self, mailbox: str, sender: str, to: str, subject: str, text: str,
               headers: dict[str, str] | None = None) -> str:
        """Put a new unread plain-text message straight into `mailbox`. Not
        sent: no submission, so it can only ever reach this mailbox."""
        email = {"mailboxIds": {mailbox: True}, "keywords": {},
                 "from": [{"email": sender, "name": "exodon"}], "to": [{"email": to}],
                 "subject": subject, "bodyValues": {"t": {"value": text}},
                 "textBody": [{"partId": "t", "type": "text/plain"}]}
        for k, v in (headers or {}).items():
            email[f"header:{k}:asText"] = v
        return self._set({"create": {"d": email}})["created"]["d"]["id"]

    def _post(self, method: str, args: dict) -> dict:
        body = {"using": USING,
                "methodCalls": [[method, {"accountId": self.account, **args}, "0"]]}
        r = self.http.post(self.api_url, json=body).raise_for_status().json()
        name, result, _ = r["methodResponses"][0]
        if name == "error":
            raise JmapError(method, result)
        return result

    def mailboxes(self) -> dict[str, dict]:
        """id -> {name, role}"""
        return {b["id"]: b for b in
                self.call("Mailbox/get", {"properties": ["name", "role"]})["list"]}

    def email_state(self) -> str:
        return self.call("Email/get", {"ids": [], "properties": ["id"]})["state"]

    def changes(self, since: str) -> tuple[list[str], str]:
        """New message ids since `since`, and the state to save. Pages until
        Fastmail reports no more changes. Raises JmapError with type
        cannotCalculateChanges when `since` is too old."""
        created: list[str] = []
        state = since
        while True:
            r = self.call("Email/changes", {"sinceState": state, "maxChanges": 256})
            created += r["created"]
            state = r["newState"]
            if not r["hasMoreChanges"]:
                return created, state

    def events(self, ping: int = 60) -> Iterator[dict]:
        """Yield push `state` events, and pings as {"type": "ping"}, forever-ish;
        the caller reconnects when this returns or raises. Pings keep idle
        connections from being cut, and let the caller prove it is alive."""
        url = (self.event_url.replace("{types}", "Email")
               .replace("{closeafter}", "no").replace("{ping}", str(ping)))
        timeout = httpx.Timeout(10, read=ping * 3)
        with self.http.stream("GET", url, headers={"Accept": "text/event-stream"},
                              timeout=timeout) as r:
            r.raise_for_status()
            yield from parse_sse(r.iter_lines())


def parse_sse(lines: Iterable[str]) -> Iterator[dict]:
    """Server-sent events -> state change objects, and {"type": "ping"}."""
    event, data = "", []
    for line in lines:
        if line == "":
            if event == "state" and data:
                yield json.loads("\n".join(data))
            elif event == "ping":
                yield {"type": "ping"}
            event, data = "", []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].strip())


def backoff(attempt: int) -> float:
    return min(300.0, 2.0 ** min(attempt, 8))
