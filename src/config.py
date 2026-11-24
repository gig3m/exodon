"""Settings, read from the environment and an optional .env at the repo root.

Everything personal -- mail account, model host -- lives in .env
(gitignored); .env.example documents the keys. Real environment variables win
over .env, so `keys exec SECRET -- python3 src/...` works unchanged.

Paths:
    DATA   spike/ by default (EXODON_DATA_DIR): mail samples, results and
           generated proposals. Built from real mail, so gitignored.
    LISTS  lists/: the live allow/block/decisions files (gitignored) next to
           their tracked *.example stubs.
    STATE  var/ by default (EXODON_STATE_DIR): shadow mode's decision log.
           Personal, so gitignored.
"""

from __future__ import annotations

import os
import pathlib
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_dotenv(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)  # the real environment wins


_load_dotenv(ROOT / ".env")

DATA = pathlib.Path(os.environ.get("EXODON_DATA_DIR") or ROOT / "spike")
LISTS = ROOT / "lists"
STATE = pathlib.Path(os.environ.get("EXODON_STATE_DIR") or ROOT / "var")

IMAP_HOST = os.environ.get("EXODON_IMAP_HOST", "imap.fastmail.com")
OLLAMA_URL = os.environ.get("EXODON_OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("EXODON_MODEL", "gemma4:12b")

# Bands. In shadow mode they are display only (the raw probability is what
# gets graded); in live mode `screen` is what gets moved to Spam.
SCREEN_AT = float(os.environ.get("EXODON_SCREEN_AT", "0.95"))
REVIEW_AT = float(os.environ.get("EXODON_REVIEW_AT", "0.5"))
# Live mode's daily digest: unsure mail (review band, and anything moved to
# Spam on a model score below SURE_AT), sent at DIGEST_AT local time ("off":
# never; an agent can read the same list from /api/readout).
SURE_AT = float(os.environ.get("EXODON_SURE_AT", "0.999"))
DIGEST_AT = os.environ.get("EXODON_DIGEST_AT", "07:00")
TZ = os.environ.get("EXODON_TZ", "America/Chicago")
WEB_ORIGIN = os.environ.get("EXODON_WEB_ORIGIN", "")
# The owner's hand-trained spam folder: ground truth for grading.
TRAINING_FOLDER = os.environ.get("EXODON_TRAINING_FOLDER", "Identified Spam")
# Only Authentication-Results stamped by the provider's own servers are
# trusted; anything else in the headers could have been written by the sender.
AUTHSERV_SUFFIX = os.environ.get("EXODON_AUTHSERV", "messagingengine.com").lower()


def _pre(account: str | None) -> str:
    return f"{account.upper()}_" if account and account != "default" else ""


def imap_user(account: str | None = None) -> str:
    """EXODON_<ACCOUNT>_IMAP_USER, falling back to EXODON_IMAP_USER."""
    user = os.environ.get(f"EXODON_{_pre(account)}IMAP_USER") or os.environ.get("EXODON_IMAP_USER")
    if not user:
        sys.exit(f"EXODON_{_pre(account)}IMAP_USER is not set -- copy .env.example to .env")
    return user


def _secret(name: str) -> str | None:
    """EXODON_<name> itself, or the variable that EXODON_<name>_ENV names."""
    val = os.environ.get(f"EXODON_{name}")
    if val:
        return val
    var = os.environ.get(f"EXODON_{name}_ENV")
    return os.environ.get(var) if var else None


def jmap_token(account: str | None = None) -> str:
    """The JMAP token for one account: EXODON_<ACCOUNT>_JMAP_TOKEN(_ENV), or
    the unprefixed EXODON_JMAP_TOKEN(_ENV) when no accounts are configured."""
    prefix = f"{account.upper()}_" if account and account != "default" else ""
    tok = _secret(f"{prefix}JMAP_TOKEN")
    if not tok:
        sys.exit(f"no JMAP token for {account or 'the mailbox'}: set EXODON_{prefix}JMAP_TOKEN, "
                 f"or EXODON_{prefix}JMAP_TOKEN_ENV naming a variable that holds it "
                 "(a read-only token is all shadow mode needs)")
    return tok


@dataclass(frozen=True)
class Account:
    name: str
    training_folder: str
    mode: str = "shadow"  # or "live": move screened mail to Spam, send a digest

    @property
    def live(self) -> bool:
        return self.mode == "live"

    def token(self) -> str:
        return jmap_token(self.name)

    def write_token(self) -> str:
        """Live mode's writable token: EXODON_<NAME>_JMAP_WRITE_TOKEN(_ENV).
        Kept apart from the read token on purpose -- the watcher's push stream
        stays on the read-only one, and Fastmail allows one push stream per
        token, so a shared writable token would kick its other user's off."""
        tok = _secret(f"{self.name.upper()}_JMAP_WRITE_TOKEN")
        if not tok:
            sys.exit(f"[{self.name}] live mode needs EXODON_{self.name.upper()}_JMAP_WRITE_TOKEN "
                     f"or EXODON_{self.name.upper()}_JMAP_WRITE_TOKEN_ENV")
        return tok


def accounts() -> list[Account]:
    """EXODON_ACCOUNTS=work,personal -> one watcher per mailbox, each with its
    own token and (optionally) its own hand-trained spam folder:
    EXODON_<NAME>_TRAINING_FOLDER, else EXODON_TRAINING_FOLDER.
    EXODON_<NAME>_MODE=live turns one mailbox live; the default is shadow."""
    names = [n.strip().lower() for n in os.environ.get("EXODON_ACCOUNTS", "").split(",") if n.strip()]
    if not names:
        return [Account("default", TRAINING_FOLDER)]
    out = []
    for n in names:
        mode = os.environ.get(f"EXODON_{n.upper()}_MODE", "shadow").strip().lower()
        if mode not in ("shadow", "live"):
            sys.exit(f"EXODON_{n.upper()}_MODE must be shadow or live, not {mode!r}")
        out.append(Account(n, os.environ.get(f"EXODON_{n.upper()}_TRAINING_FOLDER", TRAINING_FOLDER),
                           mode))
    return out


def imap_password(account: str | None = None) -> str:
    """The password itself (EXODON_[<ACCOUNT>_]IMAP_PASSWORD), or the name of
    the variable that holds it (..._IMAP_PASSWORD_ENV), so a secrets manager
    can inject it under its own name: `keys exec MY_IMAP_SECRET -- ...`.
    Account-prefixed settings win; unprefixed ones are the fallback."""
    for pre in dict.fromkeys((_pre(account), "")):
        pw = _secret(f"{pre}IMAP_PASSWORD")
        if pw:
            return pw
    sys.exit(f"no IMAP password for {account or 'the mailbox'}: set "
             f"EXODON_{_pre(account)}IMAP_PASSWORD, or ..._IMAP_PASSWORD_ENV naming a variable "
             "that holds it (and run under the secrets manager that injects it)")
