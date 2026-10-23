# Adversarial sandbox

The sandbox runs the **real `wyrmatron` binary** against emulated services and attacks it the way people attack Telegram bots. Every input arrives over the wire, exactly as it would in production; nothing calls the bot's internals.

```sh
cargo build --release
python3 sandbox/run.py --binary target/release/wyrmatron --report sandbox-report.md
```

It needs Python 3.10+ and nothing else (standard library only). A full run takes about two minutes and exits non-zero if any check fails. `--keep` keeps the temporary directory (config, database, logs, blocklist) for inspection; `-v` prints every check. CI runs it on amd64 and arm64 against the binary copied out of the Docker image, and uploads the report.

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

Each negative test is followed by a **barrier**: a whitelisted user's `/help`. The bot processes updates in order, so once the barrier is answered, the attack has been fully handled and its absence of effects can be asserted.

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
| Final state | No call of any kind to an attacker or unapproved chat; every message valid Telegram HTML; zero connections to the canary; the FFmpeg service saw only well-formed, authenticated requests; the blocklist is well-formed and holds exactly the attackers; logs are valid JSON lines with no panics; nothing written outside the work directory; clean SIGTERM shutdown |

The checks themselves were tested by reintroducing vulnerabilities: removing HTML escaping from error replies fails the injection check, and bypassing the whitelist fails seven checks.

## Fixed because of this suite

- **Poison update:** one malformed update in a `getUpdates` batch stalled the bot permanently (the whole batch failed to decode, so the offset never advanced). Updates are now decoded one at a time; a response that cannot be parsed at all is skipped after three attempts.
- **Command name injection:** command names weren't validated, so a crafted entity could carry newlines into logs and `blocklist.cfg`. Only Telegram's command syntax is accepted now, and the blocklist sanitizes what it writes.
- **No per-account job limit:** one account could queue unlimited jobs. Now capped at 3 unfinished jobs per Telegram user or API consumer.
- **Lost replies under flood control:** replies were lost when Telegram answered with 429. Waits of up to 30 s are now honoured and retried.
- **Endless retries:** a `file_id` Telegram refuses (or a 404 file path) retried every 30 s forever. Telegram 4xx answers now fail the job, and every temporary failure gives up after 6 attempts.

## Not covered here

These need a real environment or are guarded elsewhere:

- **Real Telegram:** the emulation follows the Bot API documentation. Behaviour of the live service, such as exact flood-control thresholds, isn't reproduced.
- **DNS rebinding and redirects from a public host to an internal one:** these can't be staged on loopback. The fetch client's DNS filtering and per-hop redirect checks have unit tests in `src/fetch.rs`.
- **Slow-request (slowloris) and connection floods against the HTTP API:** keep the API on the private Docker network or behind a reverse proxy, as the deployment docs require.
- **Malicious media against FFmpeg decoders:** that is the FFmpeg service's sandbox (Landlock, seccomp, resource limits), not this bot.
- **A compromised whitelisted account** can still use its own quota: 3 jobs at a time and normal Telegram rate limits. Remove it from `whitelist.cfg` to cut it off; that takes effect immediately.
- **Blocklist growth:** each new account that contacts the bot adds one line to `blocklist.cfg`. A mass campaign with many Telegram accounts grows the file, but costs the attacker one account per line.

## Adding a scenario

Write a function `def my_attack(sb: Sandbox) -> None` in `run.py` and add it to `SCENARIOS`. Use these helpers:

- **Sending input:** `sb.send(chat, user, text, ...)` and `sb.press(user, chat, message_id, data)` push updates.
- **Waiting:** `sb.barrier()` waits until everything before it has been processed.
- **Inspecting:** `sb.chat_calls(chat)`, `sb.texts(chat)`, `sb.blocklist()`, `sb.http(...)` and `sb.canary.hits` show what happened.
- **Recording results:** `sb.check(category, name, condition, detail)`.
