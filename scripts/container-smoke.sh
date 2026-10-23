#!/bin/sh
# Starts the image with Telegram and FFmpeg disabled and checks the API,
# health, persistence across container replacement and container hardening.
#
# The main run uses the caller's own UID/GID with plain host directories, as
# a user-space deployment would; a second run checks the image's default
# user with named volumes; a third checks the error for an unwritable
# data directory.
set -eu
image="${1:-wyrmatron:test}"
suffix="$$"
name="wyrmatron-smoke-$suffix"
volume="wyrmatron-smoke-data-$suffix"
work="wyrmatron-smoke-work-$suffix"
scratch="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" "$work" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

uid="$(id -u)"
gid="$(id -g)"
key="smoke-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
hash="$(printf %s "$key" | docker run --rm -i --entrypoint /usr/local/bin/wyrmatron "$image" hash-key)"
mkdir -p "$scratch/config" "$scratch/data" "$scratch/work"
cat > "$scratch/config/config.toml" <<CONF
[telegram]
enabled = false
[ffmpeg]
enabled = false
[destinations.ops]
chat_id = -100123
[[consumers]]
id = "smoke"
key_sha256 = ["$hash"]
scopes = ["notify", "media"]
destinations = ["ops"]
[uptime_kuma.main]
destination = "ops"
CONF
# Owned by the caller only: nothing is made world-writable.
chmod 0700 "$scratch/config" "$scratch/data" "$scratch/work"
chmod 0600 "$scratch/config/config.toml"

# start <user> <tmpfs uid:gid> <data> <work>
start() {
  docker run -d --name "$name" --user "$1" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 64 --memory 256m --cpus 0.5 \
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=${2%:*},gid=${2#*:},mode=0700" \
    -v "$3:/data" -v "$4:/work" -v "$scratch/config:/etc/wyrmatron" \
    -v "$scratch/config/config.toml:/etc/wyrmatron/config.toml:ro" \
    -p 127.0.0.1::8080 "$image" >/dev/null
}

wait_healthy() {
  for _ in $(seq 1 30); do
    if docker exec "$name" /usr/local/bin/wyrmatron healthcheck 2>/dev/null; then return 0; fi
    sleep 1
  done
  docker logs "$name"
  echo "container did not become healthy" >&2
  exit 1
}

api_url() {
  echo "http://127.0.0.1:$(docker port "$name" 8080/tcp | head -n1 | sed 's/.*://')"
}

# --- 1. The caller's own UID/GID with host directories -----------------------
start "$uid:$gid" "$uid:$gid" "$scratch/data" "$scratch/work"
wait_healthy
api="$(api_url)"
curl -fsS "$api/health/live" | grep -q '"ok":true'
test "$(curl -s -o /dev/null -w '%{http_code}' "$api/v1/capabilities")" = 401
curl -fsS -H "Authorization: Bearer $key" "$api/v1/capabilities" | grep -q '"api_version":"1"'
body='{"destination":"ops","text":"container smoke test","event_id":"smoke-1"}'
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$body" "$api/v1/notifications")" = 202
kuma='{"heartbeat":{"monitorID":1,"status":0,"time":"2026-10-22 14:00:00.000","msg":"down"},"monitor":{"id":1,"name":"NAS"},"msg":"[NAS] down"}'
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$kuma" "$api/v1/hooks/uptime-kuma/main")" = 202

# Runs as the requested user, with no capabilities and a read-only root.
docker exec "$name" sh -c "test \"\$(id -u):\$(id -g)\" = '$uid:$gid'"
docker exec "$name" sh -c 'grep -q "^CapEff:[[:space:]]*0*$" /proc/1/status'
if docker exec "$name" sh -c 'touch /usr/local/bin/x' 2>/dev/null; then echo "root filesystem is writable" >&2; exit 1; fi
docker logs "$name" 2>&1 | grep -q "\"user\":\"uid $uid gid $gid\"" || { docker logs "$name"; echo "identity not logged" >&2; exit 1; }
# Files written on the host belong to the caller.
test "$(stat -c %u:%g "$scratch/data/wyrmatron.sqlite3")" = "$uid:$gid"

# Graceful stop, then a new container on the same directories keeps the
# outbox: the duplicate event is recognised.
docker stop -t 30 "$name" >/dev/null
docker logs "$name" 2>&1 | grep -q '"stopped"' || { docker logs "$name"; echo "no clean shutdown" >&2; exit 1; }
docker rm "$name" >/dev/null
start "$uid:$gid" "$uid:$gid" "$scratch/data" "$scratch/work"
wait_healthy
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$body" "$(api_url)/v1/notifications")" = 200
docker rm -f "$name" >/dev/null
echo "user-space run passed as $uid:$gid"

# --- 2. The image's default user with named volumes --------------------------
default_user="$(docker image inspect "$image" --format '{{.Config.User}}')"
chmod 0755 "$scratch/config"
chmod 0644 "$scratch/config/config.toml"
start "$default_user" "$default_user" "$volume" "$work"
wait_healthy
docker exec "$name" sh -c "test \"\$(id -u):\$(id -g)\" = '$default_user'"
docker rm -f "$name" >/dev/null
echo "default-user run passed as $default_user"

# --- 3. An unwritable data directory fails with a usable message -------------
mkdir -p "$scratch/locked"
chmod 0500 "$scratch/locked"
start "$uid:$gid" "$uid:$gid" "$scratch/locked" "$scratch/work"
for _ in $(seq 1 15); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$name")" = false ]; then break; fi
  sleep 1
done
docker logs "$name" 2>&1 | grep -q "not writable by uid $uid gid $gid" || { docker logs "$name"; echo "missing permission error" >&2; exit 1; }
chmod 0700 "$scratch/locked"
echo "permission error check passed"

echo "container smoke checks passed"
