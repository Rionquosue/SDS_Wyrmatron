# Wyrmatron

A small containerised Telegram bot and notification relay, built to the SDS-Wyrmatron design document.

- **Notifications:** an authenticated HTTP API and an Uptime Kuma webhook adapter deliver messages to Telegram chats through a restart-safe outbox.
- **Media:** Telegram users and API clients can turn videos (uploads, Telegram files, or X/Twitter and Bluesky post links) into silent Telegram GIFs, muted copies, compressed files or H.264/AAC MP4s, or just fetch the post's video. All encoding runs in the separate, sandboxed [FFmpeg service](https://github.com/Rionquosue/FFMPEG_container) over its private API; this container never runs FFmpeg.

Version 0.1.0. See [Verification status](#verification-status) for what has and has not been exercised.

## Architecture

| Area | Implementation |
|---|---|
| Runtime | Rust 1.97, Tokio (2 worker threads, 8 blocking threads), static musl binary, mimalloc |
| HTTP API | Axum; per-route body limits; notification routes have their own concurrency limit |
| Storage | Embedded SQLite (bundled) on a dedicated thread; WAL, `synchronous=FULL`, `BEGIN IMMEDIATE` writes, STRICT tables |
| Telegram | Thin Bot API client; long polling into a persisted inbox; per-chat rate limiting |
| FFmpeg | Client for API v1: capability detection, streamed uploads, ETag polling, resumable verified downloads, cleanup |
| Fetching | Public URLs only through a client that filters DNS answers, checks every redirect and enforces per-source host allowlists |

Source map: `src/api` (HTTP API), `src/telegram` (Bot API client, polling, commands), `src/notify.rs` (outbox), `src/ffmpeg` (FFmpeg client), `src/media` (planner, pipeline, job store), `src/extract.rs` (FxTwitter/FxBluesky), `src/fetch.rs` (restricted fetch client), `src/app.rs` (process wiring).

## Requirements

- Docker Engine with Compose.
- The FFmpeg service, version 0.2.0 or newer for `/gif`, `/mute` and clipping (0.1.0 supports `/fetch`, `/mp4` and `/compress`). Features are detected from its `/v1/capabilities`, so unsupported actions are reported as unavailable rather than failing.
- A Telegram bot token from @BotFather.

## Setup

Everything below runs as your own user: no `sudo`, and everything the bot writes on the host belongs to you. (See [User and permissions](#user-and-permissions) for other choices.)

1. **Choose the user.** Copy the environment file and set `BOT_UID`/`BOT_GID` to your own IDs:
   ```sh
   cp .env.example .env
   sed -i "s/^BOT_UID=.*/BOT_UID=$(id -u)/; s/^BOT_GID=.*/BOT_GID=$(id -g)/" .env
   ```
2. **Directories.** Create them yourself; otherwise Docker would create them owned by root:
   ```sh
   mkdir -p config data work secrets
   ```
3. **Network shared with the FFmpeg service** (once, if it does not exist):
   ```sh
   docker network create --internal media_processing
   ```
4. **FFmpeg consumer key.** Generate a key and add a `wyrmatron` consumer to the FFmpeg service's `api_keys.json`, then restart that service (it reads keys at startup):
   ```sh
   docker compose build
   docker run --rm wyrmatron:0.1.0 gen-key
   ```
   ```json
   { "consumers": [ { "id": "wyrmatron", "keys": ["<key>"] } ] }
   ```
   Put the same key in `secrets/ffmpeg_key`.
5. **Telegram token** in `secrets/telegram_token`. Keep both secrets private to you:
   ```sh
   chmod 0400 secrets/*
   ```
6. **Configuration.** `./config` is mounted at `/etc/wyrmatron`. It holds `config.toml` (mounted read-only), `whitelist.cfg` and `blocklist.cfg`, which the bot writes:
   ```sh
   cp config.example.toml config/config.toml
   cp whitelist.example.cfg config/whitelist.cfg
   ```
   In `config.toml`, set at least:
   - `telegram.admins`: numeric IDs; admins are always allowed.
   - `destinations`.
   - API `consumers`: store only `key_sha256` from `wyrmatron gen-key`.

   Put every other account allowed to use the bot in `whitelist.cfg` (see [Account access](#account-access)).
7. **Start:**
   ```sh
   docker compose up -d --build
   docker compose logs -f wyrmatron
   ```
   The first log line shows the user it runs as, for example `"user":"uid 1000 gid 1000"`.

The container has a read-only root filesystem, no capabilities, `no-new-privileges`, a PID limit, 256 MiB of memory and 0.5 CPU. It writes only to `/data` (SQLite), `/work` (media spool), `/etc/wyrmatron` (the blocklist) and a small `/tmp`. Keep `data` on local storage, never NFS/SMB, because of SQLite's WAL. Back it up with `sqlite3 data/wyrmatron.sqlite3 "VACUUM INTO 'data/backup.sqlite3'"`, or stop the container before copying.

## User and permissions

The bot runs as whatever numeric UID/GID you give it. No account has to exist in the image, and it never needs root. `BOT_UID` and `BOT_GID` in `.env` set both the runtime user and the owner of the image's directories, so new named volumes match too. If they're unset, the image's default is 10001:10001.

| How you run Docker | `BOT_UID` / `BOT_GID` | Result |
|---|---|---|
| Regular Docker, your user in the `docker` group | your `id -u` / `id -g` | The bot runs as you; `config`, `data` and `work` stay yours |
| Rootless Docker | `0` / `0` | Container root *is* your unprivileged host user, so files on the host are yours. Capabilities are still dropped |
| Rootless Podman | your `id -u` / `id -g`, plus `userns_mode: keep-id` under the service | Your IDs inside the container map to yours outside |
| Dedicated service account | that account's IDs | `chown` the directories to it once |

- **Startup check:** the bot checks that `data` and `work` are writable before it starts. If they aren't, it exits with the exact fix, for example `Data directory /data is not writable by uid 1000 gid 1000 … (chown -R 1000:1000 on the host)`.
- **Config directory:** if it isn't writable, the bot still starts, but blocked accounts can't be saved to `blocklist.cfg` and are kept in memory only.
- **Real root:** running as UID 0 in the host's user namespace (real root, not rootless) logs a warning.
- **Rootless resource limits:** `mem_limit`, `cpus` and `pids_limit` need cgroup v2 with controller delegation. The rootless Docker and Podman documentation covers enabling it; without it, remove those lines from `compose.yaml`.

## Telegram

| Command | Effect |
|---|---|
| `/gif [URL] [start=S] [duration=S]` | Silent H.264 MP4 sent as an animation; at most 30 s, sized to fit 8 MiB using a three-step ladder |
| `/mute [URL]` | Remove the audio track; the video stream is copied when possible |
| `/compress [URL] [light\|balanced\|small]` | Re-encode with a named preset; also `preset=small` |
| `/mp4 [URL]` | H.264/AAC MP4; compatible files are only re-wrapped |
| `/fetch URL` | Download the video from an X/Twitter or Bluesky post |
| `/status JOB_ID`, `/cancel JOB_ID` | Your own jobs (admins: any job) |
| `/help` | Commands, limits and anything currently unavailable |

- **Sources:** reply to a video with a command, or put a link after it. Use `video=N` to choose one video from a post that has several.
- **Private chats:** a bare video or supported link gets action buttons. Buttons are bound to you, the chat and the message, expire after 15 minutes, and work once.
- **Groups:** with privacy mode on (the default), use commands, including `/gif@YourBot`. The bot does not react to plain links.
- **Authorization:** by account whitelist (below) and, for groups, `allowed_chats`. Numeric IDs only.
- **Telegram limits:** the hosted Bot API downloads files up to 20 MB and uploads up to 50 MB. For larger files, run a Local Bot API server and set `telegram.api_base` and the size limits.

## Account access

Every Telegram account is screened against the whitelist **before the bot replies or does anything**.

- **Whitelist:** `config/whitelist.cfg` (in the container, `/etc/wyrmatron/whitelist.cfg`) has one numeric user ID per line. Text after `#` is a comment. Admins from `config.toml` are always allowed. If the file is missing, the bot creates an empty one with instructions.
- **Blocking:** any other account that sends the bot a private message, sends it a command in a group, or presses one of its buttons is appended to `config/blocklist.cfg` and ignored from then on:
  ```
  987654321	# @someone blocked 2026-10-23T07:00:00Z (private chat)
  ```
  The bot sends no reply and doesn't even acknowledge the button press. Telegram has no Bot API method for a bot to block a user, so a block means the bot never responds; it does not remove anyone from groups.
- **Group chatter:** ordinary messages in a group that aren't addressed to the bot are not screened, so members of an allowed group are not blocklisted just for talking.
- **Edits apply without a restart.** Both files are re-read when they change on the host:
  - Delete a line from `blocklist.cfg` to unblock an account.
  - Add an ID to `whitelist.cfg` to allow it. The whitelist wins over an older blocklist entry.
  - Remove an ID from the whitelist to block that account on its next contact.
- **Finding someone's ID:** have them message the bot. They are blocklisted with their username, and you can move that line into the whitelist.
- **Other locations:** set `telegram.whitelist_file` and `telegram.blocklist_file` to keep the files elsewhere.

If the whitelist is empty and no admins are configured, every account is blocked, and the bot logs a warning at startup.

## Uptime Kuma

Configure a **Webhook** notification in Kuma:

- **URL:** `http://wyrmatron:8080/v1/hooks/uptime-kuma/main` (attach Kuma to the `bot_services` network).
- **Body:** *Preset — application/json* (the native payload). Form-data is also accepted.
- **Additional Headers:** `{"Authorization": "Bearer <key of a consumer with the notify scope>"}`.

Down, up, pending, maintenance, test and certificate notifications are formatted and deduplicated. Recoveries stay distinct from outages, and pending/maintenance alerts can be suppressed per route. If your Kuma version cannot send custom headers, use a `route_secret` route instead (see `config.example.toml`); the URL path then acts as the credential.

## HTTP API

Every `/v1` route requires `Authorization: Bearer <key>`. Errors use `{"error": {"code", "message", "field", "retryable"}}`.

| Endpoint | Purpose |
|---|---|
| `GET /health/live`, `GET /health/ready` | Liveness; readiness also checks the database |
| `GET /v1/capabilities` | Available actions (with reasons), adapters, limits, FFmpeg instance |
| `POST /v1/notifications` | `{"destination", "text", "title"?, "severity"?, "source"?, "event_id"?}` |
| `POST /v1/hooks/uptime-kuma/{route}` | Kuma's native payload |
| `POST /v1/media/jobs` | JSON URL job; requires `Idempotency-Key` |
| `POST /v1/media/uploads` | Multipart: `request` JSON (with `size_bytes`) first, then `file`; requires `Idempotency-Key` |
| `GET /v1/jobs/{id}` | Your job's state, result and errors |
| `GET /v1/jobs/{id}/download` | The result (supports Range), kept for 1 hour |
| `DELETE /v1/jobs/{id}` | Cancel a running job or delete a result |

```sh
curl -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"destination":"ops","text":"Storage server is down","severity":"critical","event_id":"storage-down-1"}' \
  http://wyrmatron:8080/v1/notifications

curl -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -H "Idempotency-Key: gif-$(uuidgen)" \
  -d '{"source":{"url":"https://fixupx.com/example/status/123456789"},"action":"gif","destination":"personal","options":{"start_seconds":3,"duration_seconds":8}}' \
  http://wyrmatron:8080/v1/media/jobs
```

Status codes:

- **202** accepted; the response includes a `Location` header. Acceptance is not delivery.
- **200** an idempotent replay.
- **409** a key reused with a different body.
- **413** too large.
- **422** invalid options, or an action unavailable on the connected FFmpeg service.
- **429/503** retry later, with `Retry-After`.

Another consumer's jobs return 404.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                     # unit, API and end-to-end pipeline tests (mocked services)
cargo audit
docker build -t wyrmatron:test . && sh scripts/container-smoke.sh wyrmatron:test
```

The image cross-compiles on the build platform with `cargo-zigbuild` (no emulation) for `linux/amd64` and `linux/arm64`, and the build fails if the binary is not static. The Rust toolchain is pinned in `rust-toolchain.toml` and base images by digest.

## Security testing

[`sandbox/`](sandbox/README.md) runs the real binary against an emulated Telegram Bot API, FFmpeg service and SSRF canary, and attacks it with 98 checks. They cover:

- unauthorised access, and forged or replayed buttons;
- HTML, shell, SQL and log injection;
- malformed and oversized updates, floods and resource exhaustion;
- Telegram faults, secret leakage, SSRF and HTTP API abuse;
- 16 less common attacks aimed at this bot's design: Trojan Source text, head-of-line blocking, button double-spend races, whitelist revocation and tampering, redirected downloads, memory bombs, request smuggling, slowloris, existence oracles, idempotency-key confusion, duplicate JSON keys, numeric edge cases, look-alike hosts and admin impersonation.

CI runs it on every push against the binary in the image:

```sh
python3 sandbox/run.py --binary target/release/wyrmatron --report sandbox-report.md
```

See its README for what it covers, what it found and fixed, and the remaining risks it can't test.

## Verification status

Verified in the development environment (Rust 1.97.0):

- 98 tests pass, covering:
  - configuration, the migrations and SQLite pragmas;
  - consumer authentication, notifications and the Kuma adapter (JSON, form-data, dedup, suppression, secret routes);
  - the outbox (split messages, resumption, permanent failures, lease recovery);
  - the Telegram client (token never in errors, 429 mapping, download limits, rate limiting);
  - command parsing, the account whitelist and blocklist (no replies to unknown accounts, persistence, host edits without restart, admin override, group chatter), button binding and expiry, and group privacy behaviour;
  - the FFmpeg client against a mock service (submission format, polling, async and sync errors, lost jobs, 503 back-off, integrity failures, Range resume, restart cleanup);
  - the planner for every preset on service 0.1.0 and 0.2.0 capabilities;
  - the restricted fetch client (address classes, URL checks, redirect limits, size limits);
  - the extractors against **recorded live FxTwitter and FxBluesky responses**;
  - end-to-end pipeline runs: upload → metadata → encode → thumbnail → Telegram animation, remux with metadata caching, and the API upload/status/download/ownership flows.
- `cargo clippy -D warnings`, `cargo fmt --check` and `cargo audit` are clean.
- Static release binaries build for x86_64 and aarch64 musl (`ldd`: not a dynamic executable). The x86_64 binary was started with Telegram and FFmpeg disabled:
  - health, the healthcheck subcommand and the notification API worked;
  - it used about 18 MB RSS at idle;
  - it exited cleanly on SIGTERM.

- In GitHub Actions on amd64 and arm64 runners, the image builds (17.5–18 MB). `scripts/container-smoke.sh` passes against it: read-only root, non-root user, no capabilities, health, auth, notifications, the Kuma hook, graceful stop, and the outbox surviving container replacement. The Trivy scan reports no fixable high or critical findings.

- The adversarial sandbox passes all 98 checks against the release binary.

Not verified yet:

- **Telegram:** no bot token was available, so there were no live Bot API calls.
- **FFmpeg service:** not run against the real service; the client is tested against a mock built from its API contract.
- **Media downloads:** not run against real X/Twitter or Bluesky media hosts. Those hosts were blocked in the development environment; the metadata APIs were reachable.


## Known limitations

- Polling only; the optional webhook mode is not implemented.
- HLS-only videos are reported as unsupported. Bluesky videos are fetched as the original upload from the author's PDS, falling back to FxBluesky's cache.
- Posts with several videos ask for `video=N` instead of showing a chooser.
- No machine-readable OpenAPI document for this API yet.
- The opt-in `/library` collection is not implemented.
