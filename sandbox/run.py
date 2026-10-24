#!/usr/bin/env python3
"""Adversarial sandbox for Wyrmatron.

Runs the real wyrmatron binary against an emulated Telegram Bot API, FFmpeg
service and SSRF canary (see fakes.py), then attacks it the way bot abusers
do: unauthorised access, forged and replayed buttons, HTML/shell/SQL/log
injection, malformed and oversized updates, floods, resource exhaustion,
Telegram faults, secret leakage, SSRF and HTTP API abuse. Every attack is
followed by a barrier: an allowed user's /help, plus a check of the bot's
database that every earlier update has been handled (chats are processed
concurrently, so the reply alone does not prove that).

    python3 sandbox/run.py --binary target/release/wyrmatron [--report out.md]

Exits non-zero if any check fails. Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes import Canary, FakeFFmpeg, FakeTelegram  # noqa: E402

ADMIN = 100
ALLOWED = 101
BARRIER_USERS = list(range(120, 140))
GROUP = -1001            # allowed group; also the "ops" notification destination
STRANGE_GROUP = -2002    # a group the bot was added to without being allowed
BOT_SENDER = 555
INSIDER = 140           # a second whitelisted user
REVOKED = 150           # whitelisted at first, removed mid-run
ATTACKERS = list(range(666, 690))
ADMIN_USERNAME = "admin_user"
# Bidi overrides/isolates, invisible marks and control characters (Trojan Source).
SPOOF_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\ufeff\x00-\x08\x0b-\x1f\x7f]")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def utf16(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


@dataclass
class Check:
    category: str
    name: str
    passed: bool
    detail: str


class Sandbox:
    def __init__(self, binary: Path, root: Path, verbose: bool) -> None:
        self.binary = binary
        self.root = root
        self.verbose = verbose
        self.results: list[Check] = []
        self.token = f"{secrets.randbelow(10**9)}:SANDBOX-{secrets.token_urlsafe(24)}"
        self.ff_key = "ffkey-" + secrets.token_urlsafe(24)
        self.api_key = "apikey-" + secrets.token_urlsafe(24)
        self.api_key2 = "apikey2-" + secrets.token_urlsafe(24)
        self.message_id = 1
        self.callback_id = 1
        self.barrier_index = 0
        self.attacker_index = 0
        self.expected_blocked: set[int] = set()
        self.proc: subprocess.Popen | None = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self.tg = FakeTelegram(self.token)
        self.ff = FakeFFmpeg(self.ff_key)
        self.canary = Canary()
        self.api_port = free_port()
        self.api = f"http://127.0.0.1:{self.api_port}"
        cfg, data, work, sec = (self.root / d for d in ("config", "data", "work", "secrets"))
        for d in (cfg, data, work, sec):
            d.mkdir(parents=True, exist_ok=True)
        (sec / "telegram_token").write_text(self.token)
        (sec / "ffmpeg_key").write_text(self.ff_key)
        h1 = hashlib.sha256(self.api_key.encode()).hexdigest()
        h2 = hashlib.sha256(self.api_key2.encode()).hexdigest()
        (cfg / "config.toml").write_text(f"""
[server]
listen = "127.0.0.1:{self.api_port}"
header_read_timeout_secs = 3
max_connections = 64
[storage]
data_dir = "{data}"
work_dir = "{work}"
[telegram]
api_base = "{self.tg.base}"
token_file = "{sec / 'telegram_token'}"
poll_timeout_secs = 1
allowed_chats = [{GROUP}]
admins = [{ADMIN}]
max_download_bytes = 1000000
max_upload_bytes = 5000000
[ffmpeg]
base_url = "{self.ff.base}"
key_file = "{sec / 'ffmpeg_key'}"
queue_allowance_secs = 20
process_timeout_secs = 10
[media]
max_source_bytes = 2000000
download_workers = 1
max_active_jobs_per_owner = 3
[fetch]
fxtwitter_api = "https://fxtwitter.invalid"
fxbsky_api = "https://fxbsky.invalid"
plc_directory = "https://plc.invalid"
[destinations.ops]
chat_id = {GROUP}
[[consumers]]
id = "sandbox"
key_sha256 = ["{h1}"]
scopes = ["notify", "media"]
destinations = ["ops"]
[[consumers]]
id = "other"
key_sha256 = ["{h2}"]
scopes = ["notify", "media"]
destinations = []
[uptime_kuma.main]
destination = "ops"
""")
        (cfg / "whitelist.cfg").write_text(
            "# sandbox whitelist\n" + "\n".join(str(u) for u in [ALLOWED, *BARRIER_USERS, INSIDER, REVOKED]) + "\n")
        self.log_path = self.root / "wyrmatron.log"
        self.db_path = data / "wyrmatron.sqlite3"
        env = {k: v for k, v in os.environ.items() if not k.startswith("WYRMATRON_")}
        env.update({"WYRMATRON_CONFIG": str(cfg / "config.toml"), "RUST_LOG": "info"})
        self.log_file = open(self.log_path, "wb")
        self.proc = subprocess.Popen([str(self.binary), "serve"], env=env,
                                     stdout=self.log_file, stderr=subprocess.STDOUT)
        ready = self.tg.wait(lambda: bool(self.tg.calls_to("getUpdates")) and self._healthy(), 30)
        if not ready:
            raise SystemExit(f"wyrmatron did not start; see {self.log_path}:\n{self.log_path.read_text()[-3000:]}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                code = self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                code = None
            log = self.log_path.read_text(errors="replace")
            self.check("Final state", "Graceful shutdown on SIGTERM", code == 0 and '"stopped"' in log,
                       f"exit code {code}")
        self.log_file.close()

    def _healthy(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.api}/health/ready", timeout=2) as r:
                return r.status == 200
        except OSError:
            return False

    # --- helpers ---------------------------------------------------------------

    def check(self, category: str, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append(Check(category, name, bool(passed), detail))
        if self.verbose or not passed:
            print(f"  {'PASS' if passed else 'FAIL'}  {category}: {name}" + (f" — {detail}" if detail and not passed else ""))
        return bool(passed)

    def attacker(self) -> int:
        uid = ATTACKERS[self.attacker_index]
        self.attacker_index += 1
        return uid

    @staticmethod
    def user(uid: int, username: str | None = None, is_bot: bool = False) -> dict:
        return {"id": uid, "is_bot": is_bot, "first_name": f"user{uid}", "username": username or f"user{uid}"}

    def message(self, chat: int, sender: dict | None, text: str | None = None, *, caption: str | None = None,
                entities: list | None = None, **extra: Any) -> dict:
        self.message_id += 1
        kind = "private" if chat > 0 else "supergroup"
        m: dict[str, Any] = {"message_id": self.message_id, "date": int(time.time()), "chat": {"id": chat, "type": kind}}
        if sender is not None:
            m["from"] = sender
        body = text if text is not None else caption
        auto: list = []
        if body is not None:
            if body.startswith("/"):
                auto.append({"type": "bot_command", "offset": 0, "length": utf16(body.split()[0]) if body.split() else 1})
            for mt in re.finditer(r"https?://\S+", body):
                auto.append({"type": "url", "offset": utf16(body[:mt.start()]), "length": utf16(mt.group())})
        if text is not None:
            m["text"] = text
            m["entities"] = entities if entities is not None else auto
        if caption is not None:
            m["caption"] = caption
            m["caption_entities"] = entities if entities is not None else auto
        m.update(extra)
        return m

    def send(self, chat: int, sender: int | dict | None, text: str | None = None, **kw: Any) -> int:
        who = self.user(sender) if isinstance(sender, int) else sender
        return self.tg.push({"message": self.message(chat, who, text, **kw)})

    def press(self, user: int | dict, chat: int, message_id: int, data: str) -> str:
        self.callback_id += 1
        cid = f"cb{self.callback_id}"
        who = self.user(user) if isinstance(user, int) else user
        kind = "private" if chat > 0 else "supergroup"
        self.tg.push({"callback_query": {"id": cid, "from": who, "data": data, "chat_instance": "x",
                                         "message": {"message_id": message_id, "date": 1,
                                                     "chat": {"id": chat, "type": kind}}}})
        return cid

    def answers(self, callback_id: str) -> list[dict]:
        return [c["params"] for c in self.tg.calls_to("answerCallbackQuery")
                if c["params"].get("callback_query_id") == callback_id]

    def chat_calls(self, chat: int) -> list[dict]:
        def chat_of(c: dict) -> Any:
            v = c["params"].get("chat_id")
            try:
                return int(v)
            except (TypeError, ValueError):
                return v
        with self.tg.lock:
            return [c for c in self.tg.calls if chat_of(c) == chat]

    def ok_replies(self, chat: int) -> list[dict]:
        return [c for c in self.chat_calls(chat) if c["method"] == "sendMessage" and c["status"] == 200]

    def settled(self) -> bool:
        """Every update handed to the bot so far has been fully handled: the
        offset is past the newest one and the inbox is empty (rows leave it
        only once handled)."""
        try:
            con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
            try:
                pending = con.execute("SELECT count(*) FROM telegram_inbox").fetchone()[0]
                row = con.execute("SELECT value FROM kv WHERE key = 'telegram_offset'").fetchone()
            finally:
                con.close()
        except sqlite3.Error:
            return False
        return pending == 0 and row is not None and int(row[0]) >= self.tg.next_update_id

    def barrier(self, timeout: float = 30, uid: int | None = None) -> bool:
        """An allowed user's /help; returns once it is answered and every
        update before it has been handled. Chats are processed concurrently,
        so the reply alone does not prove that."""
        if uid is None:
            uid = BARRIER_USERS[self.barrier_index % len(BARRIER_USERS)]
            self.barrier_index += 1
        deadline = time.monotonic() + timeout
        before = len(self.ok_replies(uid))
        self.send(uid, uid, "/help")
        answered = self.tg.wait(lambda: len(self.ok_replies(uid)) > before, timeout)
        return answered and self.tg.wait(self.settled, max(1.0, deadline - time.monotonic()))

    def _status_kb(self, field: str) -> int:
        for line in Path(f"/proc/{self.proc.pid}/status").read_text().splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1])
        return 0

    def reset_peak(self) -> bool:
        """Resets the bot's peak resident memory (Linux); False if unsupported."""
        try:
            Path(f"/proc/{self.proc.pid}/clear_refs").write_text("5")
            return True
        except OSError:
            return False

    def rss_mb(self) -> float:
        return self._status_kb("VmRSS") / 1024

    def peak_mb(self) -> float:
        return self._status_kb("VmHWM") / 1024

    def mark(self) -> int:
        """A point in the call log, for since()."""
        with self.tg.lock:
            return len(self.tg.calls)

    def since(self, chat: int, mark: int, methods: tuple[str, ...] = ("sendMessage", "editMessageText")) -> list[str]:
        """Texts sent to a chat after a mark, in the order they were sent."""
        with self.tg.lock:
            calls = self.tg.calls[mark:]
        return [c["params"].get("text", "") for c in calls
                if c["method"] in methods and str(c["params"].get("chat_id")) == str(chat)]

    def texts(self, chat: int) -> list[str]:
        return self.tg.sent_texts(chat)

    def wait_text(self, chat: int, needle: str, timeout: float = 40, count: int = 1) -> bool:
        return self.tg.wait(lambda: sum(needle in t for t in self.texts(chat)) >= count, timeout)

    def blocklist(self) -> list[str]:
        p = self.root / "config" / "blocklist.cfg"
        return p.read_text().splitlines() if p.exists() else []

    def blocked_count(self, uid: int) -> int:
        return sum(1 for line in self.blocklist() if re.match(rf"^{uid}\s", line))

    def http(self, method: str, path: str, body: Any = None, key: str | None = None,
             headers: dict[str, str] | None = None, raw: bytes | None = None) -> tuple[int, Any]:
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(f"{self.api}{path}", data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if key:
            req.add_header("Authorization", f"Bearer {key}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                payload = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            payload, status = e.read(), e.code
        except OSError as e:
            return 0, str(e)
        try:
            return status, json.loads(payload)
        except ValueError:
            return status, payload

    def video(self, file_id: str, size: int) -> dict:
        return {"file_id": file_id, "file_unique_id": "u" + file_id, "width": 640, "height": 360,
                "duration": 5, "mime_type": "video/mp4", "file_size": size}


# --- Scenarios -----------------------------------------------------------------


def access_control(sb: Sandbox) -> None:
    c = "Access control"
    sb.check(c, "Whitelisted admin is served (control)", sb.barrier() and bool(sb.ok_replies(BARRIER_USERS[0])))

    a = sb.attacker()
    for text in ["/start", "/help", "/gif https://x.com/a/status/1", "hello", "/status 1"]:
        sb.send(a, a, text)
    sb.barrier()
    sb.expected_blocked.add(a)
    sb.check(c, "Unknown account in a private chat gets no reply", not sb.chat_calls(a))
    sb.check(c, "Unknown account is blocklisted exactly once", sb.blocked_count(a) == 1,
             f"{sb.blocked_count(a)} entries")

    for i in range(40):
        sb.send(a, a, f"/help {i}")
    sb.barrier()
    sb.check(c, "A blocked account stays ignored under a 40-message flood",
             not sb.chat_calls(a) and sb.blocked_count(a) == 1)

    a2 = sb.attacker()
    before = len(sb.chat_calls(GROUP))
    sb.send(GROUP, a2, f"/help@{FakeTelegram.BOT_USERNAME}")
    sb.send(GROUP, a2, "/gif https://x.com/a/status/1")
    sb.barrier()
    sb.expected_blocked.add(a2)
    sb.check(c, "Unknown account's commands in an allowed group get no reply",
             len(sb.chat_calls(GROUP)) == before and sb.blocked_count(a2) == 1)

    a3 = sb.attacker()
    sb.send(GROUP, a3, "just chatting, not talking to the bot")
    sb.barrier()
    sb.check(c, "Ordinary group chatter is not blocklisted", sb.blocked_count(a3) == 0)

    sb.send(STRANGE_GROUP, ALLOWED, "/help")
    sb.barrier()
    sb.check(c, "Whitelisted user in a chat that is not allowed gets no reply", not sb.chat_calls(STRANGE_GROUP))

    sb.tg.push({"message": sb.message(GROUP, None, "/help", sender_chat={"id": -100999, "type": "channel"})})
    sb.barrier()
    sb.check(c, "Messages without a sender (channel/anonymous) are ignored",
             len(sb.chat_calls(GROUP)) == before)

    sb.send(BOT_SENDER, sb.user(BOT_SENDER, "evilbot", is_bot=True), "/help")
    sb.barrier()
    sb.check(c, "Messages from other bots are ignored", not sb.chat_calls(BOT_SENDER) and sb.blocked_count(BOT_SENDER) == 0)

    a4 = sb.attacker()
    sb.send(GROUP, a4, "/help@OtherBot")
    sb.barrier()
    sb.check(c, "Commands addressed to another bot are ignored", sb.blocked_count(a4) == 0)

    a5 = sb.attacker()
    sb.send(a5, sb.user(a5, ADMIN_USERNAME), "/help")
    sb.barrier()
    sb.expected_blocked.add(a5)
    sb.check(c, "Copying an admin's username grants nothing (numeric IDs only)",
             not sb.chat_calls(a5) and sb.blocked_count(a5) == 1)


def callbacks(sb: Sandbox) -> None:
    c = "Button abuse"
    sb.tg.add_file("vid-buttons", b"\x00\x00\x00\x18ftypmp42" + b"V" * 2000)
    sb.send(ALLOWED, ALLOWED, video=sb.video("vid-buttons", 2016))
    ok = sb.tg.wait(lambda: any(c_["params"].get("reply_markup") for c_ in sb.chat_calls(ALLOWED)), 15)
    if not sb.check(c, "Private video gets action buttons (control)", ok):
        return
    prompt = [c_ for c_ in sb.chat_calls(ALLOWED) if c_["params"].get("reply_markup")][-1]
    buttons = prompt["params"]["reply_markup"]["inline_keyboard"][0]
    tokens = [b["callback_data"] for b in buttons]
    mid = prompt["message_id"]
    sb.check(c, "Button data fits Telegram's 64-byte limit and carries no user data",
             all(len(t.encode()) <= 64 and "vid-buttons" not in t for t in tokens))

    a = sb.attacker()
    cid = sb.press(a, ALLOWED, mid, tokens[0])
    sb.barrier()
    sb.expected_blocked.add(a)
    sb.check(c, "Another account pressing the button is ignored and blocklisted",
             not sb.answers(cid) and sb.blocked_count(a) == 1
             and not any("Selected" in t for t in sb.texts(ALLOWED)))

    forged = ["' OR '1'='1' --", "A" * 300, "../../../etc/passwd", "\u202e\u0000", "null", ""]
    cids = [sb.press(ALLOWED, ALLOWED, mid, d) for d in forged]
    sb.barrier()
    sb.check(c, "Forged or oversized button data is rejected",
             all(sb.answers(x) and "expired" in (sb.answers(x)[0].get("text") or "") for x in cids))

    cid = sb.press(ALLOWED, GROUP, mid, tokens[1])
    sb.barrier()
    sb.check(c, "A valid button replayed in another chat is rejected",
             sb.answers(cid) and "expired" in (sb.answers(cid)[0].get("text") or ""))

    first = sb.press(ALLOWED, ALLOWED, mid, tokens[0])
    second = sb.press(ALLOWED, ALLOWED, mid, tokens[0])
    third = sb.press(ALLOWED, ALLOWED, mid, tokens[1])
    sb.barrier()
    selected = sum("Selected" in t for t in sb.texts(ALLOWED))
    sb.check(c, "Each prompt's buttons work exactly once (replay protection)",
             selected == 1 and sb.answers(first) and "expired" in (sb.answers(second)[0].get("text") or "")
             and "expired" in (sb.answers(third)[0].get("text") or ""), f"{selected} selections")
    sb.check(c, "The accepted press runs the job", sb.wait_text(ALLOWED, "Done"))


def injection(sb: Sandbox) -> None:
    c = "Injection"
    errors_before = len(sb.tg.html_errors)
    for text in ['/gif <b>INJECT</b>=1', '/gif start=<i>INJECT</i>', '/compress preset=<a href="tg://user?id=1">INJECT</a>',
                 '/status <b>INJECT</b>', '/gif &lt;INJECT&amp;=1 & < >']:
        sb.send(ALLOWED, ALLOWED, text)
    sb.barrier()
    texts = sb.texts(ALLOWED)
    sb.check(c, "User text in replies is HTML-escaped (no markup injection)",
             not any(re.search(r"<(b|i|a)[ >]INJECT|<b>INJECT", t) for t in texts)
             and any("&lt;b&gt;INJECT" in t for t in texts))
    sb.check(c, "Every reply was valid Telegram HTML", len(sb.tg.html_errors) == errors_before,
             "; ".join(e for _, e in sb.tg.html_errors[errors_before:]))

    marker = sb.root / "PWNED"
    replies_before = len(sb.ok_replies(ALLOWED))
    payloads = [f"/fetch https://x.com/a/status/1;touch${{IFS}}{marker}", f"/gif start=$(touch {marker})",
                f"/mp4 `touch {marker}`", "/fetch https://x.com/a/status/1|id", f"/compress ;touch {marker}"]
    for p in payloads:
        sb.send(ALLOWED, ALLOWED, p)
    sb.barrier()
    sb.check(c, "Shell metacharacters are never executed", not marker.exists())
    sb.check(c, "…and each payload got a normal refusal", len(sb.ok_replies(ALLOWED)) >= replies_before + len(payloads))

    for p in ["/status ' OR '1'='1", "/cancel 1;DROP TABLE jobs;--", "/status %' --", "/status 0 UNION SELECT token FROM kv"]:
        sb.send(ALLOWED, ALLOWED, p)
    sb.barrier()
    sb.check(c, "SQL injection in job IDs is refused", sum("No such job" in t for t in sb.texts(ALLOWED)) >= 4)

    a = sb.attacker()
    text = "/gif\n101\r\n100 # injected"
    sb.send(a, sb.user(a, "evil\n101"), text, entities=[{"type": "bot_command", "offset": 0, "length": utf16(text)}])
    sb.barrier()
    sb.expected_blocked.add(a)
    lines = [l for l in sb.blocklist() if l and not l.startswith("#")]
    sb.check(c, "Crafted names/commands cannot inject blocklist lines",
             sb.blocked_count(a) == 1 and all(re.match(r"^\d+\t# ", l) for l in lines)
             and sb.blocked_count(ALLOWED) == 0 and sb.blocked_count(ADMIN) == 0, repr(lines[-3:]))

    before = sum("Queued" in t for t in sb.texts(ALLOWED))
    sb.send(ALLOWED, ALLOWED, "/gіf https://x.com/a/status/1")  # Cyrillic i
    sb.send(ALLOWED, ALLOWED, "/gi\u200bf https://x.com/a/status/1")  # zero-width space
    sb.barrier()
    sb.check(c, "Lookalike and zero-width commands are not executed",
             sum("Queued" in t for t in sb.texts(ALLOWED)) == before)


def malformed(sb: Sandbox) -> None:
    c = "Malformed input"
    sb.tg.push_raw({"update_id": sb.tg.next_update_id, "message": {"message_id": "x", "chat": "y", "from": 5}})
    sb.tg.push_raw({"update_id": sb.tg.next_update_id, "callback_query": {"id": 7, "from": None}})
    sb.check(c, "Updates with wrong field types are skipped", sb.barrier())

    deep: dict = {"message_id": 1, "date": 1, "chat": {"id": ALLOWED, "type": "private"}, "text": "x"}
    for _ in range(90):
        deep = {"message_id": 1, "date": 1, "chat": {"id": ALLOWED, "type": "private"}, "reply_to_message": deep}
    sb.send(ALLOWED, ALLOWED, "/help", reply_to_message=deep)
    sb.check(c, "Deeply nested replies are handled", sb.barrier())

    bomb: dict = {"x": 1}
    for _ in range(300):
        bomb = {"reply_to_message": bomb}
    sb.tg.push_raw({"update_id": sb.tg.next_update_id, "message": bomb})
    sb.check(c, "A getUpdates response too deep to parse cannot stall the bot", sb.barrier(timeout=60))

    sb.send(ALLOWED, ALLOWED, "/help", entities=[{"type": "bot_command", "offset": 0, "length": 999999},
                                                 {"type": "url", "offset": 10**12, "length": 10**12},
                                                 {"type": "text_link", "offset": 0, "length": 1, "url": "javascript:alert(1)"}])
    sb.send(ALLOWED, ALLOWED, "/help", entities=[{"type": "bot_command", "offset": -5, "length": 3}])
    sb.check(c, "Out-of-range and negative entity offsets are handled", sb.barrier())

    big = "/help " + " ".join(f"https://x.com/a/status/{i}" for i in range(3000)) + " " + "A" * 60000
    t0 = time.monotonic()
    sb.send(ALLOWED, ALLOWED, big)
    sb.check(c, "A 150 KB message with 3000 links is processed quickly", sb.barrier() and time.monotonic() - t0 < 15,
             f"{time.monotonic() - t0:.1f}s")

    replies = len(sb.ok_replies(ALLOWED))
    weird = "/help\u0000\u202e\u200b\ufeff \U0001F409" + "\U0001F600" * 500
    sb.send(ALLOWED, ALLOWED, weird, entities=[{"type": "bot_command", "offset": 0, "length": 5}])
    sb.check(c, "Control characters, RTL overrides and emoji are handled",
             sb.barrier() and len(sb.ok_replies(ALLOWED)) > replies)

    uid = BARRIER_USERS[-1]
    before = len(sb.ok_replies(uid))
    dup = {"update_id": sb.tg.next_update_id, "message": sb.message(uid, sb.user(uid), "/help")}
    sb.tg.push_raw(dup)
    sb.tg.push_raw(json.loads(json.dumps(dup)))
    sb.barrier()
    sb.barrier()
    sb.check(c, "A duplicated update is processed once", len(sb.ok_replies(uid)) == before + 1,
             f"{len(sb.ok_replies(uid)) - before} replies")

    a = sb.attacker()
    sb.tg.push({"edited_message": sb.message(a, sb.user(a), "/help")})
    sb.tg.push({"my_chat_member": {"chat": {"id": STRANGE_GROUP, "type": "group"}, "from": sb.user(a)}})
    sb.tg.push({"chat_join_request": {"chat": {"id": GROUP, "type": "supergroup"}, "from": sb.user(a)}})
    sb.check(c, "Unsubscribed update types are ignored", sb.barrier() and not sb.chat_calls(a) and sb.blocked_count(a) == 0)


def resources(sb: Sandbox) -> None:
    c = "Denial of service"
    sb.tg.add_file("vid-ok", b"\x00\x00\x00\x18ftypmp42" + b"V" * 5000)
    sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-ok", 5016))
    done = sb.wait_text(ALLOWED, "Done", count=2)
    sends = sb.tg.calls_to("sendVideo", ALLOWED)
    sb.check(c, "Normal media job completes end to end (control)",
             done and bool(sends) and {"video", "thumb"} <= set(sends[-1]["files"]))

    sb.ff.hold.set()
    for _ in range(6):
        sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-ok", 5016))
    sb.barrier()
    sb.tg.wait(lambda: sum(("· job" in t or "already have" in t) for t in sb.texts(ALLOWED)) >= 6 + 2, 20)
    limited = sum("already have 3 jobs" in t for t in sb.texts(ALLOWED))
    sb.check(c, "A job flood from one account is capped at 3 unfinished jobs", limited == 3, f"{limited} refused")
    sb.ff.hold.clear()
    sb.check(c, "…and the capped jobs still finish", sb.wait_text(ALLOWED, "Done", timeout=90, count=5))

    sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-huge", 50_000_000))
    sb.barrier()
    sb.check(c, "Files over the download limit are refused before downloading",
             any("MB bot download limit" in t for t in sb.texts(ALLOWED))
             and not any(x["params"].get("file_id") == "vid-huge" for x in sb.tg.calls_to("getFile")))

    sb.tg.add_file("vid-endless", size=1000, endless=True)
    sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-endless", 1000))
    failed = sb.wait_text(ALLOWED, "over Telegram's bot download limit", 60)
    work_size = sum(f.stat().st_size for f in (sb.root / "work").rglob("*") if f.is_file())
    sb.check(c, "An endless download (lying file size) is cut off at the limit",
             failed and work_size < 3_000_000, f"work dir {work_size} bytes")

    passwd = Path("/etc/passwd").read_bytes() if Path("/etc/passwd").exists() else b"root:"
    sb.tg.add_file("vid-trav", b"x", path="../../../../etc/passwd")
    uploads_before = len(sb.ff.requests)
    refused = sum("could not provide that file" in t for t in sb.texts(ALLOWED))
    sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-trav", 1))
    failed = sb.wait_text(ALLOWED, "could not provide that file", 30, count=refused + 1)
    outside = [p for p in (sb.root / "work").rglob("*") if p.is_file() and "jobs" not in p.parts]
    sb.check(c, "A traversal file_path from getFile reads no local file",
             failed and len(sb.ff.requests) == uploads_before and not outside and passwd[:20] not in b"".join(
                 b for r in sb.tg.calls if r["method"] in ("sendVideo", "sendDocument") for b in r["file_bytes"].values()))

    sb.send(ALLOWED, ALLOWED, document={"file_id": "doc-evil", "file_name": "../../../../tmp/evil.sh",
                                        "mime_type": "video/mp4", "file_size": 10}, caption="/mp4")
    failed = sb.wait_text(ALLOWED, "could not provide that file", 30, count=refused + 2)
    sb.check(c, "Document file names cannot write outside the work directory",
             not Path("/tmp/evil.sh").exists() and not (sb.root / "evil.sh").exists())
    sb.check(c, "Jobs for files Telegram refuses fail at once instead of retrying forever", failed)

    uid = BARRIER_USERS[3]
    sb.tg.fail("sendMessage", 429, {"ok": False, "error_code": 429, "description": "Too Many Requests: retry after 1",
                                    "parameters": {"retry_after": 1}}, times=2)
    t0 = time.monotonic()
    before = len(sb.ok_replies(uid))
    sb.send(uid, uid, "/help")
    delivered = sb.tg.wait(lambda: len(sb.ok_replies(uid)) > before, 20)
    sb.check(c, "Telegram flood control (429) is honoured and the reply still arrives",
             delivered and time.monotonic() - t0 >= 2, f"{time.monotonic() - t0:.1f}s")

    sb.tg.fail("getUpdates", 502, {"ok": False, "error_code": 502, "description": "Bad Gateway"}, times=2)
    sb.tg.raw_updates_responses.append(b"{not json")
    sb.check(c, "Bot recovers from Telegram outages and garbage responses", sb.barrier(timeout=60))

    sb.check(c, "Bot stays healthy after all of the above", sb._healthy() and sb.proc.poll() is None)


def secrets_check(sb: Sandbox) -> None:
    c = "Secrets"
    log = sb.log_path.read_text(errors="replace")
    secret_part = sb.token.split(":", 1)[1]
    sb.check(c, "Bot token never appears in logs", secret_part not in log)
    sb.check(c, "FFmpeg and API keys never appear in logs", sb.ff_key not in log and sb.api_key not in log)
    sent = "\n".join(sb.tg.sent_texts())
    sb.check(c, "No secret is ever sent to a chat",
             secret_part not in sent and sb.ff_key not in sent and sb.api_key not in sent)
    sb.check(c, "Every Telegram request used the right token", sb.tg.unauthorized_requests == 0)


def http_api(sb: Sandbox) -> None:
    c = "HTTP API"
    routes = [("GET", "/v1/capabilities"), ("POST", "/v1/notifications"), ("POST", "/v1/media/jobs"),
              ("GET", "/v1/jobs/0123456789abcdef0123456789abcdef"), ("DELETE", "/v1/jobs/0123456789abcdef0123456789abcdef")]
    codes = [sb.http(m, p, {} if m == "POST" else None)[0] for m, p in routes]
    codes += [sb.http(m, p, {} if m == "POST" else None, key="wrong-key")[0] for m, p in routes]
    sb.check(c, "Every route rejects missing or wrong keys", all(x == 401 for x in codes), str(codes))

    bad_ids = ["..%2F..%2F..%2Fetc%2Fpasswd", "%27%20OR%201%3D1", "../../data/wyrmatron.sqlite3", "%00", "A" * 500]
    results = [sb.http("GET", f"/v1/jobs/{i}/download", key=sb.api_key) for i in bad_ids]
    sb.check(c, "Path traversal and injection in job IDs return nothing",
             all(s in (400, 404) and b"root:" not in (b if isinstance(b, bytes) else json.dumps(b).encode())
                 for s, b in results), str([s for s, _ in results]))

    status, _ = sb.http("POST", "/v1/notifications", raw=b'{"destination":"ops","text":"' + b"A" * 1_000_000 + b'"}',
                        key=sb.api_key)
    nested = b"[" * 20000 + b"]" * 20000
    s2, _ = sb.http("POST", "/v1/notifications", raw=nested, key=sb.api_key)
    s3, _ = sb.http("POST", "/v1/notifications", raw=b"\xff\xfe\x00garbage", key=sb.api_key)
    sb.check(c, "Oversized, deeply nested and invalid bodies are rejected safely",
             status == 413 and 400 <= s2 < 500 and 400 <= s3 < 500 and sb._healthy(), f"{status} {s2} {s3}")

    errors_before = len(sb.tg.html_errors)
    before = len(sb.chat_calls(GROUP))
    sb.http("POST", "/v1/notifications", {"destination": "ops", "title": "<i>t</i>",
                                          "text": "</b><a href=\"tg://user?id=1\">pwn</a><script>x</script> & <",
                                          "event_id": "sandbox-html-1"}, key=sb.api_key)
    kuma = {"heartbeat": {"monitorID": 1, "status": 0, "time": "t", "msg": "<b>evil</b></pre>&"},
            "monitor": {"id": 1, "name": "<a href='x'>NAS</a>", "url": "javascript:alert(1)"}, "msg": "x"}
    sb.http("POST", "/v1/hooks/uptime-kuma/main", kuma, key=sb.api_key)
    sb.tg.wait(lambda: len(sb.chat_calls(GROUP)) >= before + 2, 20)
    new = [x["params"].get("text", "") for x in sb.chat_calls(GROUP)[before:]]
    sb.check(c, "Notification and Kuma text cannot inject markup",
             len(new) >= 2 and len(sb.tg.html_errors) == errors_before
             and all("<script" not in t and "<a href" not in t and "javascript:" not in t for t in new)
             and any("&lt;script&gt;" in t for t in new), repr(new)[:300])

    s, body = sb.http("POST", "/v1/media/jobs", {"source": {"url": f"http://127.0.0.1:{sb.canary.port}/x"},
                                                 "action": "fetch"}, key=sb.api_key,
                      headers={"Idempotency-Key": "ssrf-http-scheme"})
    sb.check(c, "Plain-HTTP source URLs are refused at the API", s == 422)
    cp = sb.canary.port
    urls = [f"https://127.0.0.1:{cp}/x.mp4", f"https://localhost:{cp}/x.mp4", f"https://2130706433:{cp}/x.mp4",
            f"https://0x7f000001:{cp}/x.mp4", f"https://127.1:{cp}/x.mp4", f"https://[::ffff:127.0.0.1]:{cp}/x.mp4",
            f"https://user:pass@127.0.0.1:{cp}/x.mp4", "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x.mp4", "https://localhost/x.mp4", "https://10.0.0.1/x.mp4", "https://192.168.0.1/x.mp4"]
    outcomes = []
    for i, u in enumerate(urls):
        s, body = sb.http("POST", "/v1/media/jobs", {"source": {"url": u}, "action": "fetch"}, key=sb.api_key,
                          headers={"Idempotency-Key": f"ssrf-probe-{i:04d}"})
        if s != 202:
            outcomes.append((u, f"refused {s}"))
            continue
        jid = body["job_id"]
        state = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            _, view = sb.http("GET", f"/v1/jobs/{jid}", key=sb.api_key)
            state = view.get("state") if isinstance(view, dict) else None
            if state in ("failed", "completed", "cancelled"):
                break
            time.sleep(0.2)
        outcomes.append((u, f"{state} {(view.get('error') or {}).get('code') if isinstance(view, dict) else ''}"))
    sb.check(c, "SSRF: internal, loopback, metadata and encoded-IP URLs are never fetched",
             all(not o.startswith("completed") for _, o in outcomes) and not sb.canary.hits,
             f"canary hits {sb.canary.hits}; " + "; ".join(f"{u} -> {o}" for u, o in outcomes if o.startswith("completed")))
    if not sb.verbose:
        print("    SSRF outcomes: " + ", ".join(sorted({o.split()[-1] for _, o in outcomes})))

    _, view = sb.http("POST", "/v1/media/jobs", {"source": {"url": "https://x.com/a/status/1"}, "action": "fetch"},
                      key=sb.api_key, headers={"Idempotency-Key": "isolation-check-1"})
    jid = view.get("job_id", "") if isinstance(view, dict) else ""
    s_other, _ = sb.http("GET", f"/v1/jobs/{jid}", key=sb.api_key2)
    s_del, _ = sb.http("DELETE", f"/v1/jobs/{jid}", key=sb.api_key2)
    sb.check(c, "Another consumer cannot see or cancel a job", bool(jid) and s_other == 404 and s_del == 404)
    s_dest, _ = sb.http("POST", "/v1/notifications", {"destination": "ops", "text": "x"}, key=sb.api_key2)
    sb.check(c, "A consumer cannot send to a destination it is not granted", s_dest == 403)

    guesses = [sb.http("POST", f"/v1/hooks/uptime-kuma/{g}", kuma)[0]
               for g in ["main", "admin", "../main", "legacy", "%2e%2e", secrets.token_hex(16)]]
    sb.check(c, "Kuma routes require the key; guessing paths gets nothing", all(x in (401, 404) for x in guesses), str(guesses))


def final_state(sb: Sandbox) -> None:
    c = "Final state"
    hit = [x for x in sb.tg.calls if x["method"] != "getUpdates"
           and str(x["params"].get("chat_id")) in {str(a) for a in [*ATTACKERS, STRANGE_GROUP, BOT_SENDER]}]
    sb.check(c, "The bot never sent anything to an attacker or unapproved chat", not hit,
             f"{len(hit)} calls, e.g. {hit[:1]}")
    sb.check(c, "Every message the bot sent was valid Telegram HTML", not sb.tg.html_errors,
             "; ".join(e for _, e in sb.tg.html_errors[:3]))
    spoofed = [t for t in sb.tg.sent_texts() if SPOOF_RE.search(t.replace("\n", "").replace("\t", ""))]
    sb.check(c, "No message carried bidi overrides or invisible control characters", not spoofed, repr(spoofed[:2]))
    sb.check(c, "No connection ever reached the SSRF canary", not sb.canary.hits, str(sb.canary.hits[:3]))
    sb.check(c, "The FFmpeg service only ever saw well-formed, authenticated requests", not sb.ff.violations,
             "; ".join(sb.ff.violations[:3]))
    lines = [l for l in sb.blocklist() if l and not l.startswith("#")]
    ids = {int(l.split()[0]) for l in lines}
    sb.check(c, "Blocklist is well-formed and holds exactly the attackers",
             all(re.fullmatch(r"\d+\t# @[A-Za-z0-9_-]+ blocked \S+ \([ -~]*\)", l) for l in lines)
             and ids == sb.expected_blocked and len(lines) == len(ids),
             f"blocked {sorted(ids)}, expected {sorted(sb.expected_blocked)}")
    log_lines = sb.log_path.read_text(errors="replace").splitlines()
    bad = [l for l in log_lines if l.strip() and not _is_json(l)]
    sb.check(c, "Logs stay structured (no injected log lines)", not bad, repr(bad[:2]))
    sb.check(c, "No panics in the logs", not any("panicked" in l for l in log_lines))
    outside = [p for p in (sb.root / "work").rglob("*") if p.is_file() and "jobs" not in p.relative_to(sb.root / "work").parts]
    sb.check(c, "Nothing is written outside the work directory's jobs folder", not outside, str(outside[:3]))


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except ValueError:
        return False


# --- Atypical attacks ----------------------------------------------------------
#
# Less common attacks aimed at this bot's particular design: its concurrency,
# its host-editable access files, its HTTP server and parsers, and the gaps
# between what a human sees and what the bot processes.

A = "Atypical attacks"


def _prompt(sb: Sandbox, chat: int, file_id: str) -> tuple[int, list[str]] | None:
    """Sends a video and returns the action prompt's message ID and buttons."""
    prompts = lambda: [x for x in sb.chat_calls(chat) if x["params"].get("reply_markup")]  # noqa: E731
    before = len(prompts())
    sb.tg.add_file(file_id, b"\x00\x00\x00\x18ftypmp42" + b"V" * 3000)
    sb.send(chat, chat, video=sb.video(file_id, 3012))
    if not sb.tg.wait(lambda: len(prompts()) > before, 15):
        return None
    p = prompts()[-1]
    return p["message_id"], [b["callback_data"] for b in p["params"]["reply_markup"]["inline_keyboard"][0]]


def x01_trojan_source(sb: Sandbox) -> None:
    spoof = "\u202e\u2066\u200f\u061c\ufeff\u0007"
    m = sb.mark()
    sb.send(ALLOWED, ALLOWED, f"/gif gpj{spoof}exe=1")
    sb.barrier()
    echoed = [t for t in sb.since(ALLOWED, m) if "gpj" in t]
    sb.check(A, "X1 Trojan Source: bidi overrides and invisible controls are stripped from echoed text",
             bool(echoed) and not any(SPOOF_RE.search(t) for t in echoed), repr(echoed)[:200])
    gb = len(sb.chat_calls(GROUP))
    sb.http("POST", "/v1/notifications", {"destination": "ops", "title": f"Backup{spoof}",
                                          "text": "invoice\u202efdp.exe", "event_id": "spoof-0001"}, key=sb.api_key)
    sb.tg.wait(lambda: len(sb.chat_calls(GROUP)) > gb, 20)
    new = [x["params"].get("text", "") for x in sb.chat_calls(GROUP)[gb:]]
    sb.check(A, "…and from notifications sent through the HTTP API",
             any("invoice" in t for t in new) and not any(SPOOF_RE.search(t) for t in new), repr(new)[:200])


def x02_head_of_line(sb: Sandbox) -> None:
    slow_before = len(sb.ok_replies(INSIDER))
    sb.tg.stall[INSIDER] = 10
    try:
        sb.send(INSIDER, INSIDER, "/help")
        time.sleep(0.5)
        uid = BARRIER_USERS[7]
        before = len(sb.ok_replies(uid))
        t0 = time.monotonic()
        sb.send(uid, uid, "/help")
        fast = sb.tg.wait(lambda: len(sb.ok_replies(uid)) > before, 8)
        elapsed = time.monotonic() - t0
        still_stuck = len(sb.ok_replies(INSIDER)) == slow_before
    finally:
        sb.tg.stall.pop(INSIDER, None)
    sb.check(A, "X2 Head-of-line blocking: a chat stuck on a slow Telegram answer does not delay other chats",
             fast and still_stuck and elapsed < 5, f"other chat answered after {elapsed:.1f}s")
    sb.check(A, "…and the stuck chat's reply still arrives",
             sb.tg.wait(lambda: len(sb.ok_replies(INSIDER)) > slow_before, 20))
    sb.tg.stall[ALLOWED] = 0.3
    try:
        m = sb.mark()
        for i in range(6):
            sb.send(ALLOWED, ALLOWED, f"/gif order{i}=1")
        sb.barrier()
    finally:
        sb.tg.stall.pop(ALLOWED, None)
    seen = [int(n) for t in sb.since(ALLOWED, m) for n in re.findall(r"order(\d)", t)]
    sb.check(A, "…while updates within one chat stay in order", seen == list(range(6)), str(seen))


def x03_double_spend(sb: Sandbox) -> None:
    got = _prompt(sb, ALLOWED, "vid-race")
    if not sb.check(A, "X3 setup: a prompt with buttons", got is not None):
        return
    mid, tokens = got
    selected = lambda: sum("Selected" in t for t in sb.texts(ALLOWED))  # noqa: E731
    before = selected()
    insider = sb.press(INSIDER, ALLOWED, mid, tokens[0])
    sb.callback_id += 1
    detached = f"cb{sb.callback_id}"
    sb.tg.push({"callback_query": {"id": detached, "from": sb.user(ALLOWED), "data": tokens[0],
                                   "chat_instance": "x", "inline_message_id": "AAAA"}})
    burst = [sb.press(ALLOWED, ALLOWED, mid, tokens[i % len(tokens)]) for i in range(12)]
    sb.barrier()
    accepted = [x for x in burst if sb.answers(x) and not sb.answers(x)[0].get("text")]
    sb.check(A, "X3 Double spend: a burst of 12 presses across a prompt's buttons runs exactly one action",
             selected() - before == 1 and len(accepted) == 1 and accepted[0] == burst[0],
             f"{selected() - before} selections, {len(accepted)} accepted")
    sb.check(A, "…another whitelisted user cannot press it, and a press without its message consumes nothing",
             "not yours" in ((sb.answers(insider) or [{}])[0].get("text") or ""))


def x04_revocation(sb: Sandbox) -> None:
    got = _prompt(sb, REVOKED, "vid-revoke")
    if not sb.check(A, "X4 setup: a prompt for a user about to be removed", got is not None):
        return
    mid, tokens = got
    wl = sb.root / "config" / "whitelist.cfg"
    wl.write_text("".join(l + "\n" for l in wl.read_text().splitlines() if l.strip() != str(REVOKED)))
    calls = len(sb.chat_calls(REVOKED))
    cid = sb.press(REVOKED, REVOKED, mid, tokens[0])
    sb.send(REVOKED, REVOKED, "/help")
    sb.barrier()
    sb.expected_blocked.add(REVOKED)
    sb.check(A, "X4 Revocation race: buttons issued before removal from the whitelist are dead after it",
             not sb.answers(cid) and len(sb.chat_calls(REVOKED)) == calls and sb.blocked_count(REVOKED) == 1)


def x05_whitelist_tamper(sb: Sandbox) -> None:
    wl = sb.root / "config" / "whitelist.cfg"
    saved = wl.read_bytes()
    blocklist = sb.blocklist()
    replies = len(sb.ok_replies(ALLOWED))
    a = sb.attacker()
    wl.unlink()
    try:
        sb.send(ALLOWED, ALLOWED, "/help")
        sb.send(a, a, "/help")
        admin_ok = sb.barrier(uid=ADMIN)
        silent = len(sb.ok_replies(ALLOWED)) == replies and not sb.chat_calls(a)
        unchanged = sb.blocklist() == blocklist
    finally:
        wl.write_bytes(saved)
    sb.check(A, "X5 Whitelist deleted at runtime: fails closed to admins only and blocklists nobody",
             admin_ok and silent and unchanged, f"admin {admin_ok}, silent {silent}, blocklist unchanged {unchanged}")
    sb.send(ALLOWED, ALLOWED, "/help")
    sb.check(A, "…and service resumes the moment it is restored",
             sb.barrier() and len(sb.ok_replies(ALLOWED)) > replies)
    replies = len(sb.ok_replies(ALLOWED))
    wl.write_bytes(b"\xff\xfe\x00garbage\x80\x81\n" * 64)
    try:
        sb.send(ALLOWED, ALLOWED, "/help")
        ok = sb.barrier(uid=ADMIN) and len(sb.ok_replies(ALLOWED)) > replies
    finally:
        wl.write_bytes(saved)
    sb.check(A, "…and a corrupted (non-UTF-8) whitelist keeps the last good list",
             ok and sb.blocked_count(ALLOWED) == 0)


def x06_redirect(sb: Sandbox) -> None:
    refused = sum("could not provide that file" in t for t in sb.texts(ALLOWED))
    sb.tg.add_file("vid-redirect", size=100, redirect=f"http://127.0.0.1:{sb.canary.port}/steal")
    sb.send(ALLOWED, ALLOWED, caption="/mp4", video=sb.video("vid-redirect", 100))
    failed = sb.wait_text(ALLOWED, "could not provide that file", 30, count=refused + 1)
    sb.check(A, "X6 A file download redirected to an internal host is not followed",
             failed and not sb.canary.hits, str(sb.canary.hits[:2]))


def x07_update_bomb(sb: Sandbox) -> None:
    measured = sb.reset_peak()
    base = sb.rss_mb()
    head = (b'{"ok":true,"result":[{"update_id":%d,"message":{"message_id":1,"date":1,'
            b'"chat":{"id":%d,"type":"private"},"from":{"id":%d,"is_bot":false,"first_name":"x"},"text":"'
            % (sb.tg.next_update_id, ALLOWED, ALLOWED))
    sb.tg.raw_updates_responses.append(head + b"A" * 48_000_000 + b'"}}]}')
    ok = sb.barrier(timeout=60)
    growth = sb.peak_mb() - base
    sb.check(A, "X7 Memory bomb: a 48 MB getUpdates response is refused without buffering it",
             ok and (not measured or growth < 40), f"peak memory grew {growth:.0f} MB")


def x08_upload_part_bomb(sb: Sandbox) -> None:
    measured = sb.reset_peak()
    base = sb.rss_mb()
    boundary = "sandbox-bomb"
    size = 64 * 1024 * 1024
    part = (f'--{boundary}\r\nContent-Disposition: form-data; name="request"\r\n'
            "Content-Type: application/json\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    head = (f"POST /v1/media/uploads HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {sb.api_key}\r\n"
            f"Idempotency-Key: upload-bomb-0001\r\nContent-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(part) + size + len(tail)}\r\n\r\n").encode()
    sent = 0
    resp = b""
    with socket.create_connection(("127.0.0.1", sb.api_port), timeout=15) as s:
        try:
            s.sendall(head + part)
            chunk = b"{" * 1_048_576
            while sent < size:
                s.sendall(chunk)
                sent += len(chunk)
            s.sendall(tail)
        except OSError:
            pass
        try:
            resp = s.recv(4096)
        except OSError:
            pass
    growth = sb.peak_mb() - base
    sb.check(A, "X8 Field bomb: a 64 MB multipart request part is cut off, not buffered",
             resp.startswith(b"HTTP/1.1 413") and (not measured or growth < 32) and sb._healthy(),
             f"{resp[:40]!r} after {sent >> 20} MB; peak memory grew {growth:.0f} MB")


def _raw(sb: Sandbox, data: bytes, wait: float = 3.0) -> bytes:
    out = b""
    with socket.create_connection(("127.0.0.1", sb.api_port), timeout=wait) as s:
        s.sendall(data)
        try:
            while chunk := s.recv(65536):
                out += chunk
        except OSError:
            pass
    return out


def x09_smuggling(sb: Sandbox) -> None:
    post = b"POST /v1/notifications HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
    ambiguous = [
        post + b"Content-Length: 2\r\nContent-Length: 40\r\n\r\n{}",
        post + b"Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
        post + b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
        post + b"Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
        post + b"Transfer-Encoding:\x0bchunked\r\n\r\n0\r\n\r\n",
        post + b"Content-Length: -1\r\n\r\n",
        post + b"Content-Length: +2\r\n\r\n{}",
        b"GET /health/live HTTP/1.1\r\nHost: x\r\nX-A: a\r\n folded\r\n\r\n",
        b"GET /health/live HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n",
        b"GET /health/live HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n",
        b"GET /health/live\r\n\r\n",
    ]
    outs = [_raw(sb, d) for d in ambiguous]
    sb.check(A, "X9 Request smuggling: conflicting lengths, obfuscated Transfer-Encoding and malformed headers are refused",
             all(o.startswith(b"HTTP/1.1 400") and o.count(b"HTTP/1.1 ") == 1 for o in outs),
             str([o[:12] for o in outs]))
    clte = _raw(sb, post + b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                b"GET /health/live HTTP/1.1\r\nHost: x\r\n\r\n")
    sb.check(A, "…a CL.TE request's smuggled second request is never answered",
             clte.count(b"HTTP/1.1 ") == 1 and b'{"ok":true}' not in clte, repr(clte[:60]))
    big = [_raw(sb, b"GET /health/live HTTP/1.1\r\nHost: x\r\nX-Big: " + b"A" * 1_000_000 + b"\r\n\r\n"),
           _raw(sb, b"GET /health/live HTTP/1.1\r\nHost: x\r\n" + b"".join(b"X-%d: a\r\n" % i for i in range(500)) + b"\r\n")]
    ext = _raw(sb, post + f"Authorization: Bearer {sb.api_key}\r\n".encode() + b"Transfer-Encoding: chunked\r\n\r\n1;"
               + b"e" * 1_000_000 + b"\r\nx\r\n0\r\n\r\n")
    absolute = _raw(sb, f"GET http://127.0.0.1:{sb.canary.port}/steal HTTP/1.1\r\nHost: 127.0.0.1:{sb.canary.port}\r\n"
                        "Connection: close\r\n\r\n".encode())
    sb.check(A, "…header and chunk-extension bombs are bounded, and absolute-form URIs are not proxied",
             all(o.startswith(b"HTTP/1.1 431") for o in big) and ext.startswith(b"HTTP/1.1 413")
             and absolute.startswith(b"HTTP/1.1 404") and not sb.canary.hits,
             f"{[o[:12] for o in big]} {ext[:12]!r} {absolute[:12]!r}")


def x10_slowloris(sb: Sandbox) -> None:
    socks = []
    for _ in range(300):
        try:
            s = socket.create_connection(("127.0.0.1", sb.api_port), timeout=5)
            s.sendall(b"GET /health/live HTTP/1.1\r\nHost: x\r\n")
            s.setblocking(False)
            socks.append(s)
        except OSError:
            pass
    t0 = time.monotonic()
    tg_ok = sb.barrier()
    alive = set(range(len(socks)))
    while alive and time.monotonic() - t0 < 15:
        for i in list(alive):
            try:
                socks[i].recv(4096)  # data (408) or b"" (closed): the server ended it
                alive.discard(i)
            except BlockingIOError:
                try:
                    socks[i].send(b"X-Trickle: 1\r\n")
                except OSError:
                    alive.discard(i)
            except OSError:
                alive.discard(i)
        time.sleep(0.5)
    elapsed = time.monotonic() - t0
    for s in socks:
        s.close()
    sb.check(A, "X10 Slowloris: 300 connections trickling headers are all cut off by the header timeout",
             len(socks) > 0 and not alive and elapsed < 10, f"{len(alive)} of {len(socks)} still open after {elapsed:.1f}s")
    sb.check(A, "…the API is immediately usable again and Telegram was served throughout",
             sb._healthy() and tg_ok)


def x11_existence_oracle(sb: Sandbox) -> None:
    _, mine = sb.http("POST", "/v1/media/jobs", {"source": {"url": "https://x.com/a/status/20"}, "action": "fetch"},
                      key=sb.api_key, headers={"Idempotency-Key": "oracle-check-0001"})
    jid = mine.get("job_id", "") if isinstance(mine, dict) else ""
    fake = secrets.token_hex(16)
    pairs = [(sb.http(m, f"/v1/jobs/{jid}{s}", key=sb.api_key2), sb.http(m, f"/v1/jobs/{fake}{s}", key=sb.api_key2))
             for m, s in [("GET", ""), ("GET", "/download"), ("DELETE", "")]]
    sb.check(A, "X11 Existence oracle: another consumer's job answers exactly like a job that does not exist",
             bool(jid) and all(a == b for a, b in pairs), str(pairs)[:300])
    sb.http("DELETE", f"/v1/jobs/{jid}", key=sb.api_key)
    ids = re.findall(r"job <code>([0-9a-f]{32})</code>", "\n".join(sb.texts(ALLOWED)))
    if not sb.check(A, "X11 setup: a Telegram job ID to probe", bool(ids)):
        return
    m = sb.mark()
    for cmd in ("status", "cancel"):
        sb.send(INSIDER, INSIDER, f"/{cmd} {ids[-1]}")
        sb.send(INSIDER, INSIDER, f"/{cmd} {secrets.token_hex(16)}")
    sb.barrier()
    got = sb.since(INSIDER, m)
    sb.check(A, "…and so does another Telegram user's job, for /status and /cancel",
             len(got) == 4 and got[0] == got[1] and got[2] == got[3], repr(got))


def x12_idempotency(sb: Sandbox) -> None:
    body = {"source": {"url": "https://x.com/a/status/30"}, "action": "fetch"}
    key = {"Idempotency-Key": "shared-key-0001"}
    s1, a = sb.http("POST", "/v1/media/jobs", body, key=sb.api_key, headers=key)
    s2, again = sb.http("POST", "/v1/media/jobs", body, key=sb.api_key, headers=key)
    s3, conflict = sb.http("POST", "/v1/media/jobs", {**body, "action": "compress"}, key=sb.api_key, headers=key)
    s4, b = sb.http("POST", "/v1/media/jobs", body, key=sb.api_key2, headers=key)
    ja = a.get("job_id") if isinstance(a, dict) else None
    jb = b.get("job_id") if isinstance(b, dict) else None
    s5, _ = sb.http("GET", f"/v1/jobs/{ja}", key=sb.api_key2)
    sb.check(A, "X12 Idempotency keys: reusing another consumer's key yields a separate job, never theirs",
             s1 == s4 == 202 and ja and jb and ja != jb and s5 == 404, f"{s1} {s4} {ja} {jb} {s5}")
    sb.check(A, "…and reusing a key for a different request is a conflict, not a replay",
             isinstance(again, dict) and again.get("job_id") == ja and s3 == 409 and ja not in json.dumps(conflict),
             f"{s2} {s3} {conflict}")
    for j, k in ((ja, sb.api_key), (jb, sb.api_key2)):
        sb.http("DELETE", f"/v1/jobs/{j}", key=k)


def x13_duplicate_keys(sb: Sandbox) -> None:
    cp = sb.canary.port
    gb = len(sb.texts(GROUP))
    probes = [
        ("/v1/notifications", b'{"destination":"nowhere","text":"dup-key-probe","destination":"ops"}'),
        ("/v1/media/jobs", b'{"source":{"url":"https://x.com/a/status/1","url":"https://127.0.0.1:%d/x.mp4"},"action":"fetch"}' % cp),
        ("/v1/media/jobs", b'{"source":{"url":"https://x.com/a/status/40"},"action":"fetch","action":"compress"}'),
    ]
    codes = [sb.http("POST", p, raw=r, key=sb.api_key, headers={"Idempotency-Key": f"dup-key-{i:04d}"})[0]
             for i, (p, r) in enumerate(probes)]
    time.sleep(2)
    sb.check(A, "X13 Parser differentials: JSON with duplicate keys is rejected outright",
             all(400 <= x < 500 for x in codes) and not any("dup-key-probe" in t for t in sb.texts(GROUP)[gb:])
             and not sb.canary.hits, str(codes))


def x14_numeric_edges(sb: Sandbox) -> None:
    src = {"url": "https://x.com/a/status/50"}
    bodies = [json.dumps({"source": src, "action": "fetch", "options": o}).encode() for o in
              ({"media_index": 0}, {"media_index": 4294967296}, {"media_index": -1},
               {"start_seconds": -0.0, "duration_seconds": -0.0}, {"duration_seconds": 1e308})]
    bodies.append(b'{"source":{"url":"https://x.com/a/status/50"},"action":"gif","options":{"start_seconds":1e400}}')
    codes = [sb.http("POST", "/v1/media/jobs", raw=r, key=sb.api_key, headers={"Idempotency-Key": f"numeric-{i:04d}"})[0]
             for i, r in enumerate(bodies)]
    sb.check(A, "X14 Numeric edge cases (index 0, u32 overflow, negative zero, 1e308, 1e400) are refused",
             all(400 <= x < 500 for x in codes) and sb._healthy(), str(codes))
    m = sb.mark()
    args = ("video=0", "video=4294967296", "video=-1", "start=99999999999999999999", "duration=1e308", "start=NaN",
            "duration=inf")
    for arg in args:
        sb.send(ALLOWED, ALLOWED, f"/gif https://x.com/a/status/50 {arg}")
    sb.barrier()
    got = sb.since(ALLOWED, m, ("sendMessage",))
    sb.check(A, "…and the same values (plus NaN and inf) in Telegram commands",
             len(got) >= len(args) and not any("Queued" in t for t in got), repr(got))


def x15_homoglyph_hosts(sb: Sandbox) -> None:
    cp = sb.canary.port
    links = ["https://х.com/a/status/1", "https://x.com.evil.example/a/status/1",
             "https://evil.example/x.com/a/status/1", f"https://x.com@127.0.0.1:{cp}/a/status/1",
             f"https://bsky.app.127.0.0.1.nip.io:{cp}/profile/a/post/b", "https://twitter.com․evil.example/a/status/1"]
    m = sb.mark()
    for link in links:
        sb.send(ALLOWED, ALLOWED, f"/fetch {link}")
    sb.barrier()
    got = sb.since(ALLOWED, m)
    refused = sum("Only X/Twitter and Bluesky" in t or t.startswith("Usage:") for t in got)
    sb.check(A, "X15 Lookalike hosts (Cyrillic look-alike, suffix and userinfo tricks) are not treated as X or Bluesky",
             refused == len(links) and not any("Queued" in t for t in got) and not sb.canary.hits, repr(got))


def x16_impersonation(sb: Sandbox) -> None:
    a = sb.attacker()
    admin = sb.user(ADMIN, ADMIN_USERNAME)
    group_calls = len(sb.chat_calls(GROUP))
    sb.send(a, a, "/help", forward_origin={"type": "user", "date": 1, "sender_user": admin},
            forward_from=admin, forward_date=1)
    sb.send(a, a, "/help", reply_to_message=sb.message(a, admin, "/help"))
    sb.send(GROUP, a, "/help", via_bot=sb.user(FakeTelegram.BOT_ID, FakeTelegram.BOT_USERNAME, is_bot=True))
    sb.send(GROUP, sb.user(1087968824, "GroupAnonymousBot", is_bot=True), "/help",
            sender_chat={"id": GROUP, "type": "supergroup"})
    sb.barrier()
    sb.expected_blocked.add(a)
    sb.check(A, "X16 Impersonation: forwarding or replying to an admin's message, via_bot and anonymous-admin posts grant nothing",
             not sb.chat_calls(a) and len(sb.chat_calls(GROUP)) == group_calls
             and sb.blocked_count(a) == 1 and sb.blocked_count(ADMIN) == 0)


def atypical(sb: Sandbox) -> None:
    for attack in (x01_trojan_source, x02_head_of_line, x03_double_spend, x04_revocation, x05_whitelist_tamper,
                   x06_redirect, x07_update_bomb, x08_upload_part_bomb, x09_smuggling, x10_slowloris,
                   x11_existence_oracle, x12_idempotency, x13_duplicate_keys, x14_numeric_edges,
                   x15_homoglyph_hosts, x16_impersonation):
        try:
            attack(sb)
        except Exception as e:  # one crashed attack must not skip the rest
            sb.check(A, f"{attack.__name__} raised {type(e).__name__}", False, str(e))


SCENARIOS: list[tuple[str, Callable[[Sandbox], None]]] = [
    ("Access control", access_control),
    ("Button abuse", callbacks),
    ("Injection", injection),
    ("Malformed input", malformed),
    ("Denial of service", resources),
    ("HTTP API", http_api),
    ("Atypical attacks", atypical),
    ("Secrets", secrets_check),
]


def report(sb: Sandbox, path: Path | None) -> int:
    failed = [r for r in sb.results if not r.passed]
    lines = ["# Wyrmatron adversarial sandbox report", "",
             f"{len(sb.results) - len(failed)} of {len(sb.results)} checks passed.", ""]
    for cat in dict.fromkeys(r.category for r in sb.results):
        lines.append(f"## {cat}")
        lines.append("")
        for r in (x for x in sb.results if x.category == cat):
            lines.append(f"- {'✅' if r.passed else '❌'} {r.name}" + (f" — {r.detail}" if not r.passed and r.detail else ""))
        lines.append("")
    text = "\n".join(lines)
    if path:
        path.write_text(text)
    print()
    print(f"{len(sb.results) - len(failed)}/{len(sb.results)} checks passed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", type=Path, default=Path("target/release/wyrmatron"))
    ap.add_argument("--report", type=Path)
    ap.add_argument("--keep", action="store_true", help="keep the sandbox directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if not args.binary.exists():
        print(f"binary {args.binary} not found; build it with `cargo build --release`", file=sys.stderr)
        return 2
    root = Path(tempfile.mkdtemp(prefix="wyrmatron-sandbox-"))
    sb = Sandbox(args.binary.resolve(), root, args.verbose)
    sb.start()
    try:
        for title, scenario in SCENARIOS:
            print(f"[{title}]")
            try:
                scenario(sb)
            except Exception as e:  # a scenario crash is a failure, not a harness abort
                sb.check(title, f"scenario raised {type(e).__name__}", False, str(e))
        final_state(sb)
    finally:
        sb.stop()
        if args.keep:
            print(f"sandbox kept at {root}")
        else:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
    return report(sb, args.report)


if __name__ == "__main__":
    sys.exit(main())
