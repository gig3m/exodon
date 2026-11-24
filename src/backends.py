"""Classifier backends. Each returns P(spam) in [0,1] plus optional confidence.

Every backend implements `score(email) -> Verdict` and is swappable, so the
scorer compares jev, a local model, and the Fastmail baseline on identical input.
"""

from __future__ import annotations

import html
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx


@dataclass
class Verdict:
    p_spam: float
    confidence: float | None = None   # jev reports this as a separate axis
    latency_ms: float = 0.0
    input_tokens: int = 0
    raw: dict = field(default_factory=dict)
    error: str | None = None


class Backend(Protocol):
    name: str

    def score(self, email: dict) -> Verdict: ...


INVISIBLE = re.compile(r"[\u00ad\u034f\u200b-\u200f\u2007\u2060\ufeff]")


def clean(text: str) -> str:
    """Undo what the extraction left behind: HTML entities (&nbsp; &zwnj;,
    sometimes double-escaped) and the invisible padding characters marketing
    mail uses to stuff the inbox preview."""
    for _ in range(2):
        text = html.unescape(text)
    text = INVISIBLE.sub("", text)
    return " ".join(text.split())


def render(email: dict, body: bool = True, context: bool = False) -> str:
    """Flatten an email record into the text a model sees.

    Header-and-preview only by default in the corpus we build, because a mail
    client has those without fetching bodies, and it is ~6x fewer input tokens.
    With context=True, append the mailbox facts from src/context.py (who the
    recipient has written to, what they kept) -- the one thing a model cannot
    read off the email itself.
    """
    parts = [
        f"From: {email.get('from_name') or ''} <{email.get('from_email') or ''}>",
        f"To: {email.get('to') or ''}",
        f"Subject: {clean(email.get('subject') or '')}",
        f"Date: {email.get('received_at') or ''}",
    ]
    if body:
        parts.append("")
        parts.append(clean(email.get("body") or email.get("preview") or ""))
    if context and email.get("context"):
        parts.append("")
        parts.append(email["context"])
    return "\n".join(parts)


# The question text is shared across backends so the comparison is apples to
# apples. It targets solicitation, not tone -- the failure mode in this corpus
# is polite, well-written cold outreach, not obvious junk.
SPAM_INSTRUCTIONS = (
    "This message is unsolicited: bulk marketing, cold sales outreach, "
    "lead-generation, or phishing. Mail the recipient signed up for "
    "(newsletters, receipts, order confirmations, account notices) is NOT "
    "unsolicited, even when it is automated or promotional."
)

COLD_OUTREACH_INSTRUCTIONS = (
    "This message is cold outreach from a salesperson the recipient has no "
    "prior relationship with."
)

# When mailbox context is supplied, say how to use it. Without this the model
# has facts but no rule connecting them to the question.
CONTEXT_RULE = (
    "The mailbox context says whether the recipient already has a relationship "
    "with the sender's company. Mail from a company the recipient already deals "
    "with is not unsolicited, even when it is a newsletter or promotion."
)

# From Manash Pratim, "I Built a Local AI That Ruthlessly Destroys My Spam
# Emails" (Medium, 2026-01-12), kept nearly verbatim. Only the final line is
# changed, from "SPAM or HAM" to yes/no, so the answer token reads the same
# way as ours for the logprob calculation.
GATEKEEPER = """You are a ruthlessly efficient executive assistant protecting your boss's time. Your job is to identify emails that waste time and filter them mercilessly.

Email metadata:
{email}

Classification criteria:
SPAM indicators (filter these):
- Mass outreach with template language
- Recruiting messages from people who clearly haven't read your work
- Sales pitches disguised as "quick questions"
- Newsletter-style content not explicitly subscribed to
- LinkedIn notification spam
- Generic networking requests with no specific context
- "I came across your profile" or similar opening lines
- Calendar invite spam from unknown senders
- Promotional content from services you didn't sign up for
- Cold outreach that could have been sent to anyone
HAM indicators (let these through):
- Direct responses to previous conversations
- Messages referencing specific projects or work
- Emails from known contacts or colleagues
- Time-sensitive information requiring action
- Personal messages with genuine human voice
- Receipts and confirmations for things you purchased
- Legitimate account security notifications
- Messages that demonstrate actual familiarity with your work
{rule}
The key question: Did a human specifically write this email for your boss, or could it have been sent to 10,000 other people?

Should this email be filtered? Answer with exactly one word, yes or no."""

FAKE_THREAD_INSTRUCTIONS = (
    "The subject line uses 'Re:' or 'Fwd:' to imply a prior conversation that "
    "the message body does not actually show evidence of."
)


class JevBackend:
    """TypeSafe System One. POST /v1/systemone, one Noul per question.

    Several questions ride in the same request at no extra state cost -- jev
    ingests state once and evaluates questions in parallel -- so we ask the
    companion diagnostics for free and let code combine them.
    """

    name = "jev"

    def __init__(self, model: str = "jev-latest", api_key: str | None = None,
                 extra_questions: bool = True, base_url: str | None = None):
        self.model = model
        # jeff (github.com/logan-markewich/jeff) serves this same wire format
        # from a self-hosted GLiFormer, so pointing base_url at it swaps the
        # model without touching anything else in the harness.
        self.base_url = (base_url or os.environ.get("TYPESAFE_BASE_URL")
                         or "https://api.typesafe.ai").rstrip("/")
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        if not self.api_key:
            raise RuntimeError("TYPESAFE_API_KEY is not set")
        self.extra = extra_questions
        self.client = httpx.Client(
            base_url=f"{self.base_url}/v1",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=60.0,
        )

    def _questions(self) -> dict:
        q = {"spam": {"type": "noul", "instructions": SPAM_INSTRUCTIONS}}
        if self.extra:
            q["cold_outreach"] = {
                "type": "noul", "instructions": COLD_OUTREACH_INSTRUCTIONS}
            q["fake_thread"] = {
                "type": "noul", "instructions": FAKE_THREAD_INSTRUCTIONS}
            q["category"] = {
                "type": "choice",
                "instructions": "What kind of message is this",
                "criteria": {
                    "personal": "A human writing to this specific person about shared business",
                    "transactional": "Receipt, order confirmation, account or security notice",
                    "subscribed_bulk": "Newsletter or promotion the recipient opted into",
                    "cold_sales": "Unsolicited sales or lead-gen outreach",
                    "phishing_fraud": "Deceptive message attempting theft or credential capture",
                },
            }
        return q

    def score(self, email: dict) -> Verdict:
        payload = {
            "state": render(email),
            "model": self.model,
            "questions": self._questions(),
        }
        t0 = time.perf_counter()
        try:
            r = self.client.post("/systemone", json=payload)
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code != 200:
                return Verdict(p_spam=float("nan"), latency_ms=dt,
                               error=f"HTTP {r.status_code}: {r.text[:200]}")
            data = r.json()
            ans = data["answers"]
            # A Noul returns the probability that the statement is true; there
            # is no separate confidence field on a noul, so leave it None and
            # read certainty off the choice question when present.
            conf = ans.get("category", {}).get("confidence")
            return Verdict(
                p_spam=float(ans["spam"]["noul"]),
                confidence=conf,
                latency_ms=dt,
                input_tokens=data.get("usage", {}).get("input_tokens", 0),
                raw=data,
            )
        except Exception as e:  # noqa: BLE001 - surface transport errors as rows
            return Verdict(p_spam=float("nan"),
                           latency_ms=(time.perf_counter() - t0) * 1000,
                           error=repr(e))


class OllamaLogprobBackend:
    """Local model via ollama's native /api/chat.

    Two things this has to get right, both learned the hard way against
    gemma4:12b on a local RTX 5070:

    1. `think: false`. gemma4 is a thinking model -- left alone it opens a
       `<|channel>thought` block and reasons for hundreds of tokens before
       answering, which costs ~10s per email and makes the final yes/no token
       a post-hoc rationalization (near-deterministic, useless for routing).
       With thinking off the answer is the first token: ~90ms, clean logprobs.
    2. The OpenAI shim at /v1/chat/completions nests logprobs under `choices`;
       the native endpoint returns them at the top level. We use the native
       one because `think` is not exposed on the shim.

    We read the token distribution rather than asking the model for a number:
    self-reported percentages from instruct models are far worse calibrated
    than their own logits.
    """

    name = "local"

    YES = ("yes", "y", "spam", "true", "1")
    NO = ("no", "n", "ham", "false", "0")

    def __init__(self, base_url: str, model: str, think: bool = False,
                 prompt: str = "ours", context: bool = False):
        self.model = model
        self.think = think
        self.prompt = prompt
        self.context = context
        self.client = httpx.Client(base_url=base_url.rstrip("/"), timeout=180.0)

    def build_prompt(self, email: dict) -> str:
        text = render(email, context=self.context)
        if self.prompt == "gatekeeper":
            rule = f"\n{CONTEXT_RULE}\n" if self.context else ""
            return GATEKEEPER.format(email=text, rule=rule)
        rule = f" {CONTEXT_RULE}" if self.context else ""
        return (
            f"{SPAM_INSTRUCTIONS}{rule}\n\n"
            f"---\n{text}\n---\n\n"
            "Answer with exactly one word, yes or no: is this message unsolicited?"
        )

    def score(self, email: dict) -> Verdict:
        prompt = self.build_prompt(email)
        payload = {
            "model": self.model,
            "think": self.think,
            "stream": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {"num_predict": 1, "temperature": 0},
            "logprobs": True,
            "top_logprobs": 20,
        }
        t0 = time.perf_counter()
        try:
            r = self.client.post("/api/chat", json=payload)
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code != 200:
                return Verdict(p_spam=float("nan"), latency_ms=dt,
                               error=f"HTTP {r.status_code}: {r.text[:200]}")
            data = r.json()
            lp = data.get("logprobs")
            if not lp:
                return Verdict(p_spam=float("nan"), latency_ms=dt,
                               error="no logprobs in response")
            top = lp[0]["top_logprobs"]
            yes = sum(math.exp(t["logprob"]) for t in top
                      if t["token"].strip().lower() in self.YES)
            no = sum(math.exp(t["logprob"]) for t in top
                     if t["token"].strip().lower() in self.NO)
            if yes + no == 0:
                return Verdict(
                    p_spam=float("nan"), latency_ms=dt,
                    error=f"no yes/no mass; top={[t['token'] for t in top[:5]]}")
            return Verdict(
                p_spam=yes / (yes + no),
                # Mass landing outside {yes,no} means the model wandered off
                # the instruction; track it as a confidence proxy.
                confidence=yes + no,
                latency_ms=dt,
                input_tokens=data.get("prompt_eval_count", 0),
                raw={"yes": yes, "no": no, "token": lp[0]["token"]},
            )
        except Exception as e:  # noqa: BLE001
            return Verdict(p_spam=float("nan"),
                           latency_ms=(time.perf_counter() - t0) * 1000,
                           error=repr(e))


class FastmailBaseline:
    """The incumbent, for free, straight off the `X-Spam-score` header that
    Fastmail already wrote on every message at delivery time.

    Using the continuous score rather than folder placement matters: it gives
    the incumbent a real ROC curve instead of one binary point, so beating it
    means beating its whole operating range, not just the one threshold it
    happens to ship with (~5.0).

    Scores are divided by 10 and clipped purely to land in [0,1]; this is
    monotone, so every ranking metric is unaffected.
    """

    name = "fastmail"
    SCALE = 10.0

    def score(self, email: dict) -> Verdict:
        raw = email.get("fastmail_score")
        if raw is None:
            # Fall back to where Fastmail actually filed it.
            return Verdict(p_spam=1.0 if email.get("fastmail_said_spam") else 0.0,
                           confidence=0.0)
        return Verdict(p_spam=min(1.0, max(0.0, float(raw) / self.SCALE)),
                       confidence=1.0, latency_ms=0.0,
                       raw={"x_spam_score": raw})


class MockBackend:
    """Deterministic stand-in so the pipeline can be verified end to end before
    an API key exists. Produces a plausible, deliberately imperfect signal."""

    name = "mock"

    def score(self, email: dict) -> Verdict:
        text = render(email).lower()
        hits = sum(kw in text for kw in (
            "unsubscribe", "reach out", "following up", "quick question",
            "last follow-up", "worth a look", "free", "webinar", "book a call",
            "who handles", "circle back", "opportunit"))
        p = 1 / (1 + math.exp(-(hits - 1.5)))
        # add stable per-record jitter so the reliability curve is not degenerate
        p = min(0.99, max(0.01, p + ((hash(email.get("id", "")) % 200) - 100) / 1000))
        return Verdict(p_spam=p, confidence=abs(p - 0.5) * 2,
                       latency_ms=0.1, input_tokens=len(text) // 4)
