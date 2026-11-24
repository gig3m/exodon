"""Review page and push parsing. No mail network; the web server runs on an
ephemeral local port against a temporary log and list directory.

    python3 -m unittest discover -s tests
"""

import http.client
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import jmap as J  # noqa: E402
import shadow as S  # noqa: E402
import web as W  # noqa: E402

ORIGIN = "https://exodon.example.net"


class Sse(unittest.TestCase):
    def test_state_and_ping(self):
        lines = ["event: ping", 'data: {"interval":60}', "",
                 "event: state", 'data: {"@type":"StateChange"}', ""]
        self.assertEqual(list(J.parse_sse(lines)), [{"type": "ping"}, {"@type": "StateChange"}])


class Preview(unittest.TestCase):
    def test_html_only_mail_reads_as_words(self):
        self.assertEqual(W.plain("<style>.a{b:c}</style><!-- x --><p>Hi&nbsp;Kyle,</p><br>We"),
                         "Hi Kyle, We")
        self.assertEqual(W.plain("<html><head><title>T</title><meta chars"), "")
        self.assertEqual(W.plain(None), "")


class Page(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        self.db, self.lists = d / "shadow.db", d / "lists"
        self.lists.mkdir()
        (self.lists / "allow.txt").write_text("@friend.example\n")
        (self.lists / "block.txt").write_text("")
        st = S.Store(self.db)
        st.record({"account": "work", "email_id": "E1", "received_at": S.now()[:19] + "Z",
                   "from_email": "pitch@acme.com", "from_name": 'Bob "the" <b>',
                   "subject": "<script>alert(1)</script>", "would": "screen",
                   "source": "model", "p_spam": 0.999})
        st.set("work:email_state", "J1")
        st.set("work:alive", S.now())
        st.db.close()
        self.srv = self.serve()

    def serve(self, proxy="", modes=None):
        srv = W.make_server(0, self.db, self.lists, hosts={"localhost:8799"}, origin=ORIGIN,
                            proxy=proxy, accounts=["work"], modes=modes or {"work": "shadow"})
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, host="localhost:8799", origin=ORIGIN,
            ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        headers = {"Host": host}
        if origin:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = ctype
            body = json.dumps(body)
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        return r.status, dict(r.getheaders()), data

    def feedback(self):
        return sqlite3.connect(self.db).execute(
            "select feedback from decisions where email_id='E1'").fetchone()[0]

    def test_page_escapes_and_sends_security_headers(self):
        code, h, body = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertNotIn("<script>alert(1)", body)
        self.assertIn("&lt;script&gt;alert(1)", body)
        self.assertNotIn('Bob "the"', body)
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")

    def test_only_the_proxy_may_connect(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = self.serve(proxy="proxy.invalid")  # resolves to nothing; we are 127.0.0.1
        self.assertEqual(self.req("GET", "/")[0], 200)  # local probe allowed
        with mock.patch.object(W, "LOCAL_PEERS", set()):
            self.assertEqual(self.req("GET", "/")[0], 403)

    def test_bad_days_value(self):
        for d in ("nan", "inf", "-1", "abc"):
            self.assertEqual(self.req("GET", f"/?days={d}")[0], 200, d)

    def test_foreign_host_is_refused(self):
        self.assertEqual(self.req("GET", "/", host="evil.example")[0], 421)

    def test_posts_need_our_origin_and_json(self):
        body = {"account": "work", "email_id": "E1", "label": "spam"}
        self.assertEqual(self.req("POST", "/api/mark", body, origin=None)[0], 403)
        self.assertEqual(self.req("POST", "/api/mark", body, origin="https://evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/api/mark", body, ctype="text/plain")[0], 403)
        self.assertIsNone(self.feedback())

    def test_mark_round_trip(self):
        self.assertEqual(self.req("POST", "/api/mark", {"account": "work", "email_id": "E1",
                                                        "label": "spam"})[0], 200)
        self.assertEqual(self.feedback(), "spam")
        self.req("POST", "/api/mark", {"account": "work", "email_id": "E1", "label": None})
        self.assertIsNone(self.feedback())
        self.assertEqual(self.req("POST", "/api/mark", {"account": "work", "email_id": "NOPE",
                                                        "label": "spam"})[0], 400)

    def test_list_add_and_undo(self):
        ask = {"account": "work", "email_id": "E1", "list": "block", "scope": "domain"}
        code, _, body = self.req("POST", "/api/list/preview", ask)
        self.assertEqual((code, json.loads(body)["status"]), (200, "ok"))
        code, _, body = self.req("POST", "/api/list/add", ask)
        self.assertEqual(code, 200, body)
        change = json.loads(body)["change_id"]
        self.assertIn("@acme.com  # exodon page", (self.lists / "block.txt").read_text())
        self.assertEqual(json.loads(self.req("POST", "/api/list/preview", ask)[2])["status"],
                         "covered")
        self.assertEqual(self.req("POST", "/api/list/undo", {"change_id": change})[0], 200)
        self.assertEqual((self.lists / "block.txt").read_text(), "")
        undone = sqlite3.connect(self.db).execute(
            "select undone_at from list_changes where id=?", (change,)).fetchone()[0]
        self.assertIsNotNone(undone)
        self.assertEqual(self.req("POST", "/api/list/undo", {"change_id": change})[0], 400)

    def test_health(self):
        code, _, body = self.req("GET", "/health")
        self.assertEqual((code, json.loads(body)["ok"]), (200, True))
        db = sqlite3.connect(self.db)
        db.execute("update meta set value='2020-01-01T00:00:00+00:00' where key='work:alive'")
        db.commit()
        self.assertEqual(self.req("GET", "/health")[0], 503)

    def test_page_renders_on_a_log_the_watcher_has_not_upgraded(self):
        db = sqlite3.connect(self.db)
        db.execute("alter table decisions drop column feedback")
        db.execute("drop table list_changes")
        db.commit()
        self.assertEqual(self.req("GET", "/")[0], 200)

    def add_home(self):
        st = S.Store(self.db)
        st.record({"account": "home", "email_id": "H1", "received_at": S.now()[:19] + "Z",
                   "from_email": "aunt@family.example", "from_name": "Aunt May",
                   "subject": "Sunday lunch", "would": "inbox", "source": "allow",
                   "list_entry": "@family.example"})
        st.record({"account": "home", "email_id": "H2", "received_at": S.now()[:19] + "Z",
                   "from_email": "maybe@odd.example", "from_name": "Odd",
                   "subject": "Quick question", "would": "review", "source": "model",
                   "p_spam": 0.7})
        st.db.close()

    def test_views_mailbox_and_search(self):
        self.add_home()
        body = self.req("GET", "/")[2]  # filtered is the default
        self.assertIn("&lt;script&gt;alert", body)
        self.assertNotIn("Sunday lunch", body)
        body = self.req("GET", "/?view=through")[2]
        self.assertIn("Sunday lunch", body)
        self.assertIn("Quick question", body)
        self.assertNotIn("&lt;script&gt;alert", body)
        body = self.req("GET", "/?view=unsure")[2]
        self.assertIn("Quick question", body)
        self.assertNotIn("Sunday lunch", body)
        body = self.req("GET", "/?view=through&account=work")[2]
        self.assertNotIn("Sunday lunch", body)
        body = self.req("GET", "/?view=through&q=sunday")[2]
        self.assertIn("Sunday lunch", body)
        self.assertNotIn("Quick question", body)
        for q in ("%", "_", "\\", "'"):
            self.assertEqual(self.req("GET", "/?q=" + urllib.parse.quote(q))[0], 200, q)
        for v in ("nope", "<x>"):
            self.assertEqual(self.req("GET", "/?view=" + urllib.parse.quote(v))[0], 200, v)

    def moves(self):
        return sqlite3.connect(self.db).execute(
            "select dir, state from moves order by id").fetchall()

    def live(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = self.serve(modes={"work": "live"})
        db = sqlite3.connect(self.db)
        db.execute("update decisions set action='moved' where email_id='E1'")
        db.commit()

    def mark(self, label):
        code, _, body = self.req("POST", "/api/mark", {"account": "work", "email_id": "E1",
                                                       "label": label})
        self.assertEqual(code, 200, body)
        return json.loads(body)

    def test_not_spam_on_a_live_mailbox_asks_for_the_move_back(self):
        self.live()
        self.assertEqual(self.mark("real")["move"], "inbox")
        self.assertEqual(self.moves(), [("inbox", "pending")])
        self.assertEqual(self.mark(None)["move"], None)  # changed my mind before it ran
        self.assertEqual(self.moves(), [("inbox", "cancelled")])
        self.mark("real")
        db = sqlite3.connect(self.db)
        db.execute("update moves set state='done' where state='pending'")
        db.commit()
        self.assertEqual(self.mark(None)["move"], "spam")  # undo after it ran: back to Spam
        self.assertEqual(self.moves()[-1], ("spam", "pending"))

    def test_spam_on_mail_already_moved_asks_for_nothing(self):
        self.live()
        self.assertIsNone(self.mark("spam")["move"])
        self.assertEqual(self.moves(), [])

    def test_shadow_mailbox_only_records_the_mark(self):
        self.assertIsNone(self.mark("real")["move"])
        self.assertEqual(self.moves(), [])
        self.assertEqual(self.feedback(), "real")

    def test_move_status(self):
        self.live()
        self.mark("real")
        code, _, body = self.req("GET", "/api/moves")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["moves"],
                         [{"account": "work", "email_id": "E1", "dir": "inbox", "state": "pending"}])

    def test_lists_page(self):
        (self.lists / "block.txt").write_text('name:*<b>funding*  # "</td><script>x"\n')
        code, _, body = self.req("GET", "/lists")
        self.assertEqual(code, 200)
        self.assertIn("@friend.example", body)
        self.assertNotIn("funding", body)  # allow is the default tab
        code, _, body = self.req("GET", "/lists?list=block")
        self.assertIn("funding", body)
        self.assertNotIn("<script>x", body)
        self.assertNotIn("<b>funding", body)
        (self.lists / "block.txt").write_text("not a pattern\n")
        code, _, body = self.req("GET", "/lists")
        self.assertEqual(code, 200)
        self.assertIn("cannot load this file", body)

    def test_hand_add_remove_and_restore(self):
        code, _, body = self.req("POST", "/api/list/new",
                                 {"list": "block", "pattern": "@Spammy.example", "note": "rotating"})
        self.assertEqual(code, 200, body)
        self.assertIn('@spammy.example  # exodon page', (self.lists / "block.txt").read_text())
        self.assertEqual(self.req("POST", "/api/list/new",
                                  {"list": "block", "pattern": "@spammy.example"})[0], 400)
        for bad in ("@gmail.com", "x\n@evil.example", "re:([", "plain words", "a@b.example # x", ""):
            self.assertEqual(self.req("POST", "/api/list/new",
                                      {"list": "block", "pattern": bad})[0], 400, bad)
        line = "@friend.example"
        code, _, body = self.req("POST", "/api/list/remove", {"list": "allow", "line": line})
        self.assertEqual(code, 200, body)
        self.assertEqual((self.lists / "allow.txt").read_text(), "")
        self.assertEqual(self.req("POST", "/api/list/remove", {"list": "allow", "line": line})[0], 400)
        code, _, body = self.req("POST", "/api/list/undo", {"change_id": json.loads(body)["change_id"]})
        self.assertEqual(code, 200, body)
        self.assertEqual((self.lists / "allow.txt").read_text(), "@friend.example\n")

    def test_check_sender(self):
        v = json.loads(self.req("POST", "/api/list/check", {"address": "x@mail.friend.example"})[2])
        self.assertEqual((v["would"], v["entry"]), ("inbox", "@friend.example"))
        v = json.loads(self.req("POST", "/api/list/check", {"address": "x@nobody.example"})[2])
        self.assertEqual(v["would"], "model")
        self.assertEqual(self.req("POST", "/api/list/check", {"address": ""})[0], 400)


class Readout(unittest.TestCase):
    """GET /api/readout: token-guarded JSON for another agent."""

    TOKEN = "t0ken"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        self.db, lists = d / "shadow.db", d / "lists"
        lists.mkdir()
        st = S.Store(self.db)
        rows = [  # (id, would, source, p_spam, action, outcome)
            ("M1", "screen", "model", 0.97, "moved", "real"),     # unsure, pulled back
            ("M2", "screen", "block", None, "moved", None),       # sure
            ("M3", "review", "model", 0.6, None, None),           # unsure, kept
            ("M4", "inbox", "model", 0.01, None, "spam"),          # a miss
            ("M5", "error", "model", None, None, None),
        ]
        for i, would, src, p, action, outcome in rows:
            st.record({"account": "personal", "email_id": i, "decided_at": S.now(),
                       "received_at": S.now(), "from_email": f"{i.lower()}@x.example",
                       "subject": f"subject {i}", "would": would, "source": src,
                       "p_spam": p, "action": action, "outcome": outcome,
                       "preview": f"body of {i}", "list_entry": "@x.example" if src == "block" else None,
                       "error": "HTTP 500: CUDA busy" if would == "error" else None})
        st.record({"account": "personal", "email_id": "OLD", "decided_at": "2020-01-01T00:00:00+00:00",
                   "would": "screen", "source": "model", "p_spam": 0.99})
        st.set("personal:alive", S.now())
        st.event("live", "[personal] live mode started")
        st.db.close()
        self.srv = W.make_server(0, self.db, lists, hosts={"exodon-web:8799"}, origin=ORIGIN,
                                 proxy="proxy.invalid", accounts=["personal"],
                                 readers=["localhost"], readout_token=self.TOKEN)
        self.srv.acct_objs = [W.config.Account("personal", "Identified Spam", "live")]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def get(self, path="/api/readout", token=TOKEN):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        h = {"Host": "exodon-web:8799"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        c.request("GET", path, headers=h)
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        return r.status, data

    def test_needs_the_token(self):
        self.assertEqual(self.get(token=None)[0], 401)
        self.assertEqual(self.get(token="wrong")[0], 401)
        self.srv.readout_token = ""
        self.assertEqual(self.get()[0], 404)  # unset token = route off

    def test_each_reader_has_its_own_token(self):
        self.srv.readout_token = [self.TOKEN, "s3cond"]
        self.assertEqual(self.get(token=self.TOKEN)[0], 200)
        self.assertEqual(self.get(token="s3cond")[0], 200)
        self.assertEqual(self.get(token="wrong")[0], 401)
        self.assertEqual(self.get(token=None)[0], 401)
        self.srv.readout_token = ["", ""]
        self.assertEqual(self.get()[0], 404)  # all empty = route off

    def test_tokens_from_env(self):
        env = {"EXODON_READOUT_TOKEN": "a", "EXODON_READOUT_TOKEN_OTHER": "b",
               "EXODON_READOUT_TOKENX": "c", "EXODON_READOUT_TOKEN_EMPTY": ""}
        with mock.patch.dict(W.os.environ, env, clear=True):
            import importlib
            m = importlib.reload(W)
            try:
                self.assertEqual(m.READOUT_TOKEN, ["a", "b"])
            finally:
                importlib.reload(W)

    def test_contents(self):
        code, body = self.get("/api/readout?hours=24")
        self.assertEqual(code, 200)
        a = json.loads(body)["accounts"]["personal"]
        self.assertEqual(a["counts"]["total"], 5)  # OLD is outside the window
        self.assertEqual(a["counts"]["moved"], 2)
        self.assertEqual(a["counts"]["by_block_list"], 1)
        self.assertEqual({r["from"] for r in a["screened"]}, {"m1@x.example", "m2@x.example"})
        self.assertEqual({r["from"] for r in a["unsure"]}, {"m1@x.example", "m3@x.example"})
        self.assertEqual({r["from"] for r in a["owner_disagreed"]},
                         {"m1@x.example", "m4@x.example"})
        self.assertIsNotNone(a["last_heartbeat"])
        self.assertEqual(a["mode"], "live")
        self.assertIsNotNone(a["live_since"])
        self.assertEqual(a["model_errors"]["count"], 1)
        self.assertIn("CUDA", a["model_errors"]["latest"])
        m1 = next(r for r in a["screened"] if r["from"] == "m1@x.example")
        self.assertEqual((m1["preview"], m1["sure"], m1["owner_label"]), ("body of M1", False, "real"))

    def test_bad_hours(self):
        self.assertEqual(self.get("/api/readout?hours=abc")[0], 400)
        self.assertEqual(self.get("/api/readout?hours=nan")[0], 200)

    def test_readers_reach_the_readout_and_nothing_else(self):
        # we connect from 127.0.0.1; with local probes not special, only the
        # reader list ("localhost") lets us in -- and only for the readout
        with mock.patch.object(W, "LOCAL_PEERS", set()):
            self.assertEqual(self.get()[0], 200)
            self.assertEqual(self.get("/", token=None)[0], 403)


if __name__ == "__main__":
    unittest.main()