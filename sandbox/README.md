# Adversarial sandbox

The sandbox runs the **real `wyrmatron` binary** against emulated services and attacks it the way people attack Telegram bots. Every input arrives over the wire, exactly as it would in production; nothing calls the bot's internals.

```sh
cargo build --release
python3 sandbox/run.py --binary target/release/wyrmatron --report sandbox-report.md
```

It needs Python 3.10+ and nothing else (standard library only). A full run takes about three minutes and exits non-zero if any check fails. `--keep` keeps the temporary directory (config, database, logs, blocklist) for inspection; `-v` prints every check. CI runs it on amd64 and arm64 against the binary copied out of the Docker image, and uploads the report.

## What runs

| Component | Emulates | Purpose |
|---|---|---|
| `FakeTelegram` (`fakes.py`) | Bot API: `getUpdates` long polling (including negative offsets), `sendMessage`, `editMessageText`, `answerCallbackQuery`, `getFile`, file downloads, `send{Animation,Video,Document}` | Scriptable update queue and fault injection (429 flood control, 5xx, garbage JSON). Validates every message with Telegram's HTML parse-mode rules, so escaping bugs show up as rejected messages |
| `FakeFFmpeg` | FFmpeg service API v1 | Flags any request with unknown parameters, a size/hash mismatch or a missing key; can hold jobs in `processing` to build up a queue |
| `Canary` | Nothing | Counts every TCP connection it receives. The bot must never be tricked into contacting it |

The bot runs with its own config, whitelist and secrets, plus several identities:
- **Admin:** 100.
- **Whitelisted user:** 101.
- **Barrier users:** 120–139.
- **Attackers:** 666 and up.
- **Chats:** an allowed group (−1001) and a group the bot was added to without permission (−2002).

Each negative test is followed by a **barrier**: a whitelisted user's `/help`, plus a read-only look at the bot's SQLite database confirming that the update offset has passed every pushed update and that the inbox is empty (an update leaves the inbox only once handled). Chats are processed concurrently, so the reply alone would not prove that earlier updates in other chats are finished.

## Attack coverage

| Area | Attacks |
|---|---|
| Access control | Unknown accounts in private chats and groups, a 40-message flood from a blocked account, chats the bot was added to without permission, senderless and bot-sent messages, commands for other bots, copying the admin's username |
| Button abuse | Pressing another user's button, forged, SQL-like and oversized `callback_data`, replay of a button in another chat, double presses |
| Injection | HTML/markup injection through command arguments and option names, shell metacharacters (`;`, `$( )`, backticks, `\|`), SQL injection in job IDs, newline injection into the blocklist and logs through usernames and crafted command entities, lookalike (Cyrillic) and zero-width commands |
| Malformed input | Wrong field types, deeply nested replies, a `getUpdates` response too deep to parse, out-of-range and negative entity offsets, a 150 KB message with 3000 links, control characters, RTL overrides and emoji, duplicated updates, unsubscribed update types |
| Denial of service | Job floods from one account, files over the download limit, an endless download behind a lying `file_size`, a `getFile` path traversal (`../../../../etc/passwd`), traversal in document file names, files Telegram refuses, Telegram 429 flood control, Telegram outages and garbage responses |
| HTTP API | Missing or wrong keys on every route, path traversal and injection in job IDs, a 1 MB body, a 20 000-level JSON nesting bomb, invalid UTF-8, markup injection through notifications and Uptime Kuma payloads, plain-HTTP sources, **SSRF** (loopback, `localhost`, decimal/hex/short IPv4 forms, IPv4-mapped IPv6, credentials in URLs, cloud metadata, private ranges), cross-consumer access, unauthorised destinations, guessing Kuma route paths |
| Secrets | Bot token, FFmpeg key and API key never in logs or chat messages; Telegram never called with a wrong token |
| Atypical attacks | See below |
| Final state | No call of any kind to an attacker or unapproved chat; every message valid Telegram HTML; no bidi overrides or invisible control characters in any message; zero connections to the canary; the FFmpeg service saw only well-formed, authenticated requests; the blocklist is well-formed and holds exactly the attackers; logs are valid JSON lines with no panics; nothing written outside the work directory; clean SIGTERM shutdown |

### Atypical attacks

Less common attacks aimed at this bot's particular design:

| # | Attack | Expected outcome |
|---|---|---|
| X1 | **Trojan Source:** RLO/LRI/RLM/ALM/BOM and control characters in text the bot echoes, and in API notifications (`invoice<U+202E>fdp.exe` displays as `invoiceexe.pdf`) | Stripped before sending |
| X2 | **Head-of-line blocking:** one chat's `sendMessage` stalls for 10 s | Other chats are answered at once; the stalled chat still gets its reply; order within a chat is kept |
| X3 | **Double spend:** 12 presses across one prompt's buttons in a single batch, another whitelisted user's press, a press without its message | Exactly one action runs |
| X4 | **Revocation race:** a button issued before its owner is removed from `whitelist.cfg`, pressed after | Ignored; the account is blocklisted |
| X5 | **Whitelist tampering:** `whitelist.cfg` deleted at runtime, then replaced with non-UTF-8 garbage | Deleted: admins only and nobody blocklisted, recovering on restore. Garbage: the last good list stays in force |
| X6 | **Redirected download:** Telegram's file endpoint answers 302 to an internal host | Not followed; the job fails |
| X7 | **Memory bomb:** a 48 MB `getUpdates` response | Refused at 16 MiB; peak memory checked through `/proc` |
| X8 | **Field bomb:** a 64 MB multipart `request` part on the upload route (which has no body limit) | 413 at 16 KiB, without buffering |
| X9 | **Request smuggling:** conflicting `Content-Length`, obfuscated `Transfer-Encoding`, CL.TE with a smuggled request, folded/NUL/bare-CR headers, HTTP/0.9, 1 MB headers, 500 headers, a 1 MB chunk extension, absolute-form URIs | 400/431/413; the smuggled request is never answered; nothing is proxied |
| X10 | **Slowloris:** 300 connections trickling header lines | Over-cap connections closed at accept, the rest cut off by the header timeout; Telegram is served throughout |
| X11 | **Existence oracle:** another consumer's or user's job ID through GET, download, DELETE, `/status` and `/cancel` | Byte-identical to a job that doesn't exist |
| X12 | **Idempotency-key confusion:** another consumer's key, and a reused key with a different body | A separate job; 409 conflict |
| X13 | **Parser differentials:** JSON with duplicate keys (`destination`, `source.url` pointing at the canary, `action`) | Rejected |
| X14 | **Numeric edges:** `media_index` 0, 2³², −1, negative zero, 1e308, 1e400, NaN and inf, through the API and Telegram | Refused |
| X15 | **Look-alike hosts:** Cyrillic `х.com`, `x.com.evil.example`, `x.com@127.0.0.1`, `bsky.app.<ip>.nip.io`, a one-dot-leader `twitter.com․evil.example` | Not treated as X or Bluesky; nothing queued |
| X16 | **Impersonation:** an attacker forwarding or replying to the admin's message, `via_bot`, an anonymous-admin post | Nothing granted; the attacker is blocklisted |

The checks themselves were tested by reintroducing vulnerabilities: removing HTML escaping from error replies fails the injection check, and bypassing the whitelist fails seven checks.

## Fixed because of this suite

- **Poison update:** one malformed update in a `getUpdates` batch stalled the bot permanently (the whole batch failed to decode, so the offset never advanced). Updates are now decoded one at a time; a response that cannot be parsed at all is skipped after three attempts.
- **Command name injection:** command names weren't validated, so a crafted entity could carry newlines into logs and `blocklist.cfg`. Only Telegram's command syntax is accepted now, and the blocklist sanitizes what it writes.
- **No per-account job limit:** one account could queue unlimited jobs. Now capped at 3 unfinished jobs per Telegram user or API consumer.
- **Lost replies under flood control:** replies were lost when Telegram answered with 429. Waits of up to 30 s are now honoured and retried.
- **Endless retries:** a `file_id` Telegram refuses (or a 404 file path) retried every 30 s forever. Telegram 4xx answers now fail the job, and every temporary failure gives up after 6 attempts.

### Fixed because of the atypical attacks

Run against the previous release, the suite passed 83 of 98 checks. That release was vulnerable to X1, X2, X5, X6, X7, X10, X14 and X15; X9 and X13 failed there only because X6 had already reached the canary. Highlights: a 48 MB `getUpdates` response raised peak memory by 283 MB, all 300 slowloris connections were still open after 15 s, a redirected download reached the canary, and deleting the whitelist blocklisted a whitelisted user.

- **Slowloris:** `axum::serve` builds connections without a timer, so Hyper's header-read timeout never fired and one client could hold any number of connections open indefinitely. The server now uses its own accept loop with a 10 s header timeout (`header_read_timeout_secs`), a 256-connection cap (`max_connections`) and a graceful drain.
- **Head-of-line blocking:** updates were handled one at a time, so one slow chat (flood control, a slow Telegram answer) delayed every other chat. Each chat now has its own ordered lane, with 32 handlers running at once.
- **Missing whitelist:** a deleted whitelist, or one caught mid-rewrite, read as empty, and every whitelisted user who wrote in that window was blocklisted. A missing whitelist now serves admins only and records nothing.
- **`media_index` 0:** the API accepted it, and selecting item 0 underflowed. It's now refused at validation, and selection can no longer underflow.
- **Trojan Source:** bidi overrides, isolates, invisible marks and control characters are stripped from everything the bot sends.
- **Unbounded reads:** a Bot API response is capped at 16 MiB, and the upload `request` part at 16 KiB.
- **Redirects:** the Telegram client followed redirects, so a redirecting file endpoint could make the bot fetch internal URLs. It no longer follows them.
- **Atomic buttons:** a button is checked and consumed in one transaction (defence in depth: a chat's presses already run in order).
- **Unsupported links:** these are refused up front instead of first showing a "Queued" message.

## Not covered here

These need a real environment or are guarded elsewhere:

- **Real Telegram:** the emulation follows the Bot API documentation. Behaviour of the live service, such as exact flood-control thresholds, isn't reproduced.
- **DNS rebinding and redirects from a public host to an internal one:** these can't be staged on loopback. The fetch client's DNS filtering and per-hop redirect checks have unit tests in `src/fetch.rs`.
- **Distributed connection floods against the HTTP API:** one source is handled (X10), but many hosts can still fill the connection cap. Keep the API on the private Docker network or behind a reverse proxy, as the deployment docs require.
- **Malicious media against FFmpeg decoders:** that is the FFmpeg service's sandbox (Landlock, seccomp, resource limits), not this bot.
- **A compromised whitelisted account** can still use its own quota: 3 jobs at a time and normal Telegram rate limits. Remove it from `whitelist.cfg` to cut it off; that takes effect immediately.
- **Blocklist growth:** each new account that contacts the bot adds one line to `blocklist.cfg`. A mass campaign with many Telegram accounts grows the file, but costs the attacker one account per line.

## Adding a scenario

Write a function `def my_attack(sb: Sandbox) -> None` in `run.py` and add it to `SCENARIOS`. Use these helpers:

- **Sending input:** `sb.send(chat, user, text, ...)` and `sb.press(user, chat, message_id, data)` push updates.
- **Waiting:** `sb.barrier()` waits until everything before it has been processed.
- **Inspecting:** `sb.chat_calls(chat)`, `sb.texts(chat)`, `sb.blocklist()`, `sb.http(...)` and `sb.canary.hits` show what happened.
- **Recording results:** `sb.check(category, name, condition, detail)`.
