"""Emulated services for the adversarial sandbox (standard library only).

FakeTelegram implements the Bot API methods Wyrmatron uses, including long
polling, file downloads and Telegram's HTML parse-mode rules, and records
every call. FakeFFmpeg implements the FFmpeg service API v1. Canary records
any request at all: the bot must never be tricked into contacting it.
"""

from __future__ import annotations

import email.parser
import email.policy
import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

# --- Telegram's HTML parse mode -------------------------------------------

ALLOWED_TAGS = {
    "b", "strong", "i", "em", "u", "ins", "s", "strike", "del", "span",
    "tg-spoiler", "a", "code", "pre", "blockquote", "tg-emoji",
}
TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9-]*)((?:\s[^<>]*)?)>")
ENTITY_RE = re.compile(r"&(lt|gt|amp|quot|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});")


class HtmlError(ValueError):
    pass


def parse_html(text: str) -> tuple[str, list[str]]:
    """Validates Telegram HTML like the Bot API does and returns the visible
    text and the tags used. Raises HtmlError where Telegram would answer
    "Bad Request: can't parse entities"."""
    visible: list[str] = []
    stack: list[str] = []
    tags: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "<":
            m = TAG_RE.match(text, i)
            if not m:
                raise HtmlError(f"unescaped '<' at {i}")
            closing, name, _attrs = m.group(1), m.group(2).lower(), m.group(3)
            if name not in ALLOWED_TAGS:
                raise HtmlError(f"unsupported tag <{name}>")
            if closing:
                if not stack or stack[-1] != name:
                    raise HtmlError(f"unmatched </{name}>")
                stack.pop()
            else:
                stack.append(name)
                tags.append(name)
            i = m.end()
        elif c == "&":
            m = ENTITY_RE.match(text, i)
            if not m:
                raise HtmlError(f"unsupported entity at {i}")
            visible.append("&")
            i = m.end()
        elif c == ">":
            raise HtmlError(f"unescaped '>' at {i}")
        else:
            visible.append(c)
            i += 1
    if stack:
        raise HtmlError(f"unclosed <{stack[-1]}>")
    return "".join(visible), tags


def utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


# --- Shared HTTP plumbing ---------------------------------------------------


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _serve(handler_cls: type, owner: Any) -> _Server:
    server = _Server(("127.0.0.1", 0), handler_cls)
    server.owner = owner  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # quiet
        pass

    @property
    def owner(self) -> Any:
        return self.server.owner  # type: ignore[attr-defined]

    def body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def send_json(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(self, status: int, data: bytes, ctype: str = "application/octet-stream") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def parse_form(content_type: str, body: bytes) -> tuple[dict[str, str], dict[str, bytes]]:
    """Splits multipart/form-data into text fields and file parts."""
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    )
    fields: dict[str, str] = {}
    files: dict[str, bytes] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if part.get_filename() is not None:
            files[name] = payload
        else:
            fields[name] = payload.decode()
    return fields, files


# --- Telegram Bot API -----------------------------------------------------


class FakeTelegram:
    """Bot API emulation with a scriptable update queue and fault injection."""

    BOT_ID = 900000001
    BOT_USERNAME = "SandboxBot"

    def __init__(self, token: str) -> None:
        self.token = token
        self.lock = threading.Condition()
        self.updates: list[dict] = []
        self.next_update_id = 1
        self.calls: list[dict] = []
        self.html_errors: list[tuple[str, str]] = []
        self.unauthorized_requests = 0
        self.files: dict[str, dict] = {}
        self.next_message_id = 1000
        # method -> list of (status, json body) answered before normal handling
        self.faults: dict[str, list[tuple[int, Any]]] = {}
        # getUpdates answered with raw bytes (malformed responses)
        self.raw_updates_responses: list[bytes] = []
        self.server = _serve(_TelegramHandler, self)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    # Scripting -----------------------------------------------------------

    def push(self, update: dict) -> int:
        with self.lock:
            uid = update.get("update_id", self.next_update_id)
            update = {"update_id": uid, **{k: v for k, v in update.items() if k != "update_id"}}
            self.next_update_id = max(self.next_update_id, uid + 1)
            self.updates.append(update)
            self.lock.notify_all()
            return uid

    def push_raw(self, update: dict) -> None:
        """Queues an update exactly as given (it may be malformed)."""
        with self.lock:
            self.updates.append(update)
            if isinstance(update.get("update_id"), int):
                self.next_update_id = max(self.next_update_id, update["update_id"] + 1)
            self.lock.notify_all()

    def add_file(self, file_id: str, data: bytes | None = None, *, size: int | None = None,
                 path: str | None = None, endless: bool = False) -> None:
        self.files[file_id] = {
            "data": data or b"",
            "size": size if size is not None else len(data or b""),
            "path": path or f"videos/{file_id}.mp4",
            "endless": endless,
        }

    def fail(self, method: str, status: int, body: Any, times: int = 1) -> None:
        with self.lock:
            self.faults.setdefault(method, []).extend([(status, body)] * times)

    def calls_to(self, method: str, chat_id: int | None = None) -> list[dict]:
        # Multipart requests carry chat_id as a string.
        with self.lock:
            return [c for c in self.calls
                    if c["method"] == method and (chat_id is None or str(c["params"].get("chat_id")) == str(chat_id))]

    def sent_texts(self, chat_id: int | None = None) -> list[str]:
        out = []
        for m in ("sendMessage", "editMessageText"):
            out += [c["params"].get("text", "") for c in self.calls_to(m, chat_id)]
        for m in ("sendAnimation", "sendVideo", "sendDocument"):
            out += [c["params"].get("caption", "") for c in self.calls_to(m, chat_id)]
        return out

    def wait(self, predicate: Callable[[], bool], timeout: float = 15.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return predicate()

    # Handling ------------------------------------------------------------

    def _message(self, chat_id: Any, text: str | None = None) -> dict:
        with self.lock:
            self.next_message_id += 1
            mid = self.next_message_id
        kind = "private" if isinstance(chat_id, int) and chat_id > 0 else "supergroup"
        msg = {"message_id": mid, "date": int(time.time()), "chat": {"id": chat_id, "type": kind}}
        if text is not None:
            msg["text"] = text
        return msg

    def _check_text(self, method: str, text: str) -> str | None:
        try:
            visible, _ = parse_html(text)
        except HtmlError as e:
            self.html_errors.append((method, f"{e}: {text[:200]!r}"))
            return "Bad Request: can't parse entities: " + str(e)
        if not visible.strip():
            return "Bad Request: message text is empty"
        if utf16_len(visible) > 4096:
            return "Bad Request: message is too long"
        return None

    def handle(self, method: str, params: dict, files: dict[str, bytes]) -> tuple[int, Any, dict]:
        call = {"method": method, "params": params, "files": {k: len(v) for k, v in files.items()},
                "file_bytes": files, "time": time.monotonic(), "status": 200}
        with self.lock:
            self.calls.append(call)
            queued = self.faults.get(method)
            if queued:
                status, body = queued.pop(0)
                call["status"] = status
                return status, body, {}
        ok = lambda result: (200, {"ok": True, "result": result}, {})  # noqa: E731
        bad = lambda desc, code=400: (code, {"ok": False, "error_code": code, "description": desc}, {})  # noqa: E731
        if method == "getMe":
            return ok({"id": self.BOT_ID, "is_bot": True, "first_name": "Sandbox", "username": self.BOT_USERNAME})
        if method == "deleteWebhook":
            return ok(True)
        if method == "getUpdates":
            offset = int(params.get("offset") or 0)
            timeout = min(float(params.get("timeout") or 0), 1.0)
            deadline = time.monotonic() + timeout
            with self.lock:
                if offset < 0:
                    # A negative offset keeps only the newest updates and
                    # confirms everything before them.
                    self.updates = self.updates[offset:]
                else:
                    # Telegram forgets updates below the offset (confirmation).
                    self.updates = [u for u in self.updates
                                    if not isinstance(u.get("update_id"), int) or u["update_id"] >= offset]
                while not self.updates and time.monotonic() < deadline:
                    self.lock.wait(deadline - time.monotonic())
                batch = self.updates[:100]
                if self.raw_updates_responses:
                    return 200, self.raw_updates_responses.pop(0), {}
            return ok(batch)
        if method in ("sendMessage", "editMessageText"):
            if not isinstance(params.get("chat_id"), int):
                return bad("Bad Request: chat_id is invalid")
            err = self._check_text(method, params.get("text", ""))
            if err:
                call["status"] = 400
                return bad(err)
            msg = self._message(params["chat_id"], params.get("text"))
            call["message_id"] = msg["message_id"]
            return ok(msg)
        if method == "answerCallbackQuery":
            if len(params.get("text") or "") > 200:
                return bad("Bad Request: text is too long")
            return ok(True)
        if method == "getFile":
            f = self.files.get(params.get("file_id", ""))
            if not f:
                return bad("Bad Request: invalid file_id")
            return ok({"file_id": params["file_id"], "file_unique_id": "u" + params["file_id"],
                       "file_size": f["size"], "file_path": f["path"]})
        if method in ("sendAnimation", "sendVideo", "sendDocument"):
            try:
                chat_id = int(params.get("chat_id", ""))
            except ValueError:
                return bad("Bad Request: chat_id is invalid")
            caption = params.get("caption")
            if caption:
                err = self._check_text(method, caption)
                if err:
                    call["status"] = 400
                    return bad(err)
            if not files:
                return bad("Bad Request: there is no file in the request")
            return ok(self._message(chat_id))
        return bad(f"Not Found: method {method} not emulated", 404)


class _TelegramHandler(_Handler):
    def do_POST(self) -> None:
        tg: FakeTelegram = self.owner
        m = re.fullmatch(r"/bot([^/]+)/([A-Za-z]+)", self.path)
        body = self.body()
        if not m:
            return self.send_json(404, {"ok": False, "error_code": 404, "description": "Not Found"})
        if m.group(1) != tg.token:
            with tg.lock:
                tg.unauthorized_requests += 1
            return self.send_json(401, {"ok": False, "error_code": 401, "description": "Unauthorized"})
        ctype = self.headers.get("Content-Type", "")
        files: dict[str, bytes] = {}
        if ctype.startswith("multipart/form-data"):
            params, files = parse_form(ctype, body)
        elif body:
            params = json.loads(body)
        else:
            params = {}
        status, payload, headers = tg.handle(m.group(2), params, files)
        if isinstance(payload, bytes):
            return self.send_bytes(status, payload, "application/json")
        self.send_json(status, payload, headers)

    def do_GET(self) -> None:
        tg: FakeTelegram = self.owner
        prefix = f"/file/bot{tg.token}/"
        if not self.path.startswith(prefix):
            with tg.lock:
                tg.unauthorized_requests += 1 if self.path.startswith("/file/bot") else 0
            return self.send_bytes(404, b"not found")
        path = self.path[len(prefix):]
        with tg.lock:
            tg.calls.append({"method": "downloadFile", "params": {"path": path}, "files": {}, "time": time.monotonic()})
        f = next((f for f in tg.files.values() if f["path"] == path), None)
        if not f:
            return self.send_bytes(404, b"not found")
        if f["endless"]:
            # No Content-Length: the bot must enforce its own limit.
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"\0" * 65536
            try:
                for _ in range(2000):  # up to ~128 MiB
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.send_bytes(200, f["data"], "video/mp4")


# --- FFmpeg service API v1 --------------------------------------------------

METADATA = {
    "format": "mov,mp4,m4a,3gp,3g2,mj2", "duration_seconds": 5.0, "width": 640, "height": 360,
    "video_codec": "h264", "audio_codec": "aac", "channels": 2, "frame_rate": 30.0, "still_image": False,
}
VIDEO_PARAMS = ["width", "height", "fit", "quality", "audio_bitrate_kbps", "audio_mode",
                "max_dimension", "max_fps", "max_bitrate_kbps"]
PARAMETERS = {
    "metadata": [], "transcode": VIDEO_PARAMS, "remux": ["audio_mode"],
    "trim": ["start_seconds", "duration_seconds", *VIDEO_PARAMS],
    "thumbnail": ["timestamp_seconds", "width", "height", "fit", "jpeg_quality"],
}


class FakeFFmpeg:
    def __init__(self, key: str) -> None:
        self.key = key
        self.lock = threading.Lock()
        self.requests: list[dict] = []
        self.violations: list[str] = []
        self.jobs: dict[str, dict] = {}
        self.hold = threading.Event()  # while set, jobs stay "processing"
        self.server = _serve(_FFmpegHandler, self)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def result_for(self, op: str) -> tuple[bytes, str]:
        if op == "metadata":
            return json.dumps(METADATA).encode(), "application/json"
        if op == "thumbnail":
            return b"\xff\xd8JPEG-THUMB", "image/jpeg"
        return b"ENCODED-VIDEO-BYTES", "video/mp4"


class _FFmpegHandler(_Handler):
    def _authorized(self) -> bool:
        ff: FakeFFmpeg = self.owner
        if self.headers.get("Authorization") != f"Bearer {ff.key}":
            with ff.lock:
                ff.violations.append(f"{self.command} {self.path} without the consumer key")
            self.send_json(401, {"error": {"code": "invalid_authentication", "retryable": False}})
            return False
        return True

    def _job(self, jid: str) -> dict:
        ff: FakeFFmpeg = self.owner
        j = ff.jobs[jid]
        status = "processing" if ff.hold.is_set() else "completed"
        data, ctype = ff.result_for(j["op"])
        return {"api_version": "1", "instance_id": "sandbox", "job_id": jid, "status": status,
                "status_url": f"/v1/jobs/{jid}",
                "result": None if status != "completed" else
                {"content_type": ctype, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
                "error": None}

    def do_GET(self) -> None:
        ff: FakeFFmpeg = self.owner
        if not self._authorized():
            return
        if self.path == "/v1/capabilities":
            return self.send_json(200, {
                "api_version": "1", "instance_id": "sandbox",
                "operations": {"metadata": ["json"], "transcode": ["mp4", "webm"], "remux": ["mp4", "webm"],
                               "trim": ["mp4", "webm"], "thumbnail": ["jpg", "png"]},
                "parameters": PARAMETERS,
                "limits": {"max_upload_bytes": 50_000_000, "max_jobs_per_consumer": 2,
                           "max_duration_seconds": 600, "process_timeout_seconds": 10}})
        m = re.fullmatch(r"/v1/jobs/([0-9a-f]{32})(/download)?", self.path)
        if not m or m.group(1) not in ff.jobs:
            return self.send_json(404, {"error": {"code": "job_not_found", "retryable": False}})
        if m.group(2):
            data, ctype = ff.result_for(ff.jobs[m.group(1)]["op"])
            return self.send_bytes(200, data, ctype)
        self.send_json(200, self._job(m.group(1)))

    def do_POST(self) -> None:
        ff: FakeFFmpeg = self.owner
        body = self.body()
        if not self._authorized() or self.path != "/v1/jobs":
            return
        fields, files = parse_form(self.headers.get("Content-Type", ""), body)
        spec = json.loads(fields.get("request", "{}"))
        op = spec.get("operation", "")
        params = spec.get("parameters", {})
        with ff.lock:
            ff.requests.append(spec)
            unknown = set(params) - set(PARAMETERS.get(op, []))
            if unknown or op not in PARAMETERS:
                ff.violations.append(f"unexpected request {spec}")
            data = files.get("file", b"")
            decl = spec.get("input", {})
            if decl.get("size_bytes") != len(data) or decl.get("sha256") != hashlib.sha256(data).hexdigest():
                ff.violations.append("declared size/hash does not match the upload")
            jid = hashlib.md5(f"{len(ff.jobs)}{time.time()}".encode()).hexdigest()
            ff.jobs[jid] = {"op": op}
        self.send_json(202, self._job(jid), {"Location": f"/v1/jobs/{jid}"})

    def do_DELETE(self) -> None:
        if not self._authorized():
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


# --- SSRF canary -------------------------------------------------------------


class _CanaryServer(_Server):
    def verify_request(self, request: Any, client_address: Any) -> bool:
        # Count every TCP connection, including TLS handshakes that never
        # become a parseable HTTP request.
        self.owner.hits.append(f"connection from {client_address[0]}")  # type: ignore[attr-defined]
        return True


class Canary:
    """Any connection reaching this server means the bot was tricked into
    contacting an internal address."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        self.server = _CanaryServer(("127.0.0.1", 0), _CanaryHandler)
        self.server.owner = self  # type: ignore[attr-defined]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]


class _CanaryHandler(_Handler):
    def _hit(self) -> None:
        self.owner.hits.append(f"{self.command} {self.path}")
        self.send_bytes(200, b"internal secret")

    do_GET = do_POST = do_PUT = do_HEAD = _hit  # type: ignore[assignment]
